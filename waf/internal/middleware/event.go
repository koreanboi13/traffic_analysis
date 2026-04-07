package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/koreanboi13/traffic_analysis/waf/internal/events"
	ch "github.com/koreanboi13/traffic_analysis/waf/internal/events/clickhouse"
	"go.uber.org/zap"
)

// responseWriter обёртка над http.ResponseWriter для перехвата HTTP статус кода
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

// newResponseWriter создаёт новую обёртку responseWriter
func newResponseWriter(w http.ResponseWriter) *responseWriter {
	return &responseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // По умолчанию 200
		written:        false,
	}
}

// WriteHeader перехватывает запись статус кода
func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

// Write перехватывает запись тела ответа
func (rw *responseWriter) Write(data []byte) (int, error) {
	// Если WriteHeader не был вызван явно, статус будет 200
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(data)
}

// StatusCode возвращает перехваченный статус код
func (rw *responseWriter) StatusCode() int {
	return rw.statusCode
}

// RecordEvent middleware для записи событий в ClickHouse
type RecordEvent struct {
	writer *events.Writer
	logger *zap.Logger
}

// NewRecordEvent создаёт новый middleware для записи событий
func NewRecordEvent(writer *events.Writer, logger *zap.Logger) *RecordEvent {
	return &RecordEvent{
		writer: writer,
		logger: logger,
	}
}

// Handler возвращает http.HandlerFunc middleware
func (m *RecordEvent) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		rw := newResponseWriter(w)

		// Pass request to next handler (proxy / detect middleware).
		next.ServeHTTP(rw, r)

		// Read ParsedRequest AFTER next — so Phase 4 detect can update verdict/score.
		parsedReq := GetParsedRequest(r.Context())
		if parsedReq == nil {
			m.logger.Warn("parsed request not found in context, skipping event recording",
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
			)
			return
		}

		latencyMs := float32(time.Since(startTime).Nanoseconds()) / 1_000_000.0
		event := m.buildEvent(parsedReq, rw.StatusCode(), latencyMs)
		m.writer.Send(event)

		m.logger.Debug("event recorded",
			zap.String("event_id", event.EventID.String()),
			zap.String("request_id", event.RequestID),
			zap.String("method", event.Method),
			zap.String("path", event.Path),
			zap.Int("status_code", int(event.StatusCode)),
			zap.Float32("latency_ms", latencyMs),
		)
	})
}

// buildEvent создаёт Event из ParsedRequest
func (m *RecordEvent) buildEvent(parsedReq *ParsedRequest, statusCode int, latencyMs float32) ch.Event {
	// Сериализуем map-поля в JSON строки
	queryParamsJSON := serializeToJSON(parsedReq.QueryParams, m.logger)
	bodyParamsJSON := serializeToJSON(parsedReq.BodyParams, m.logger)
	headersJSON := serializeToJSON(parsedReq.Headers, m.logger)
	cookiesJSON := serializeToJSON(parsedReq.Cookies, m.logger)

	// Конвертируем bool в uint8 (0 или 1)
	bodyTruncated := uint8(0)
	if parsedReq.BodyTruncated {
		bodyTruncated = 1
	}

	// Создаём событие
	event := ch.Event{}

	// Заполняем базовые поля
	event.RequestID = parsedReq.RequestID
	event.ClientIP = parsedReq.ClientIP
	event.Host = parsedReq.Host
	event.Method = parsedReq.Method
	event.Path = parsedReq.Path
	event.NormalizedPath = parsedReq.NormalizedPath
	event.Verdict = parsedReq.Verdict
	if event.Verdict == "" {
		event.Verdict = "allow"
	}
	event.StatusCode = uint16(statusCode)
	event.LatencyMs = latencyMs

	// Заполняем расширенные поля
	event.RawQuery = parsedReq.RawQuery
	event.NormalizedQuery = parsedReq.NormalizedQuery
	event.RawBody = string(parsedReq.RawBody)
	event.NormalizedBody = parsedReq.NormalizedBody
	event.QueryParams = queryParamsJSON
	event.BodyParams = bodyParamsJSON
	event.Headers = headersJSON
	event.Cookies = cookiesJSON
	event.UserAgent = parsedReq.UserAgent
	event.ContentType = parsedReq.ContentType
	event.Referer = parsedReq.Referer
	event.BodyTruncated = bodyTruncated
	if parsedReq.BodySize > 0 {
		event.BodySize = uint32(parsedReq.BodySize)
	}

	// Detection results from Detect middleware
	event.RuleIDs = parsedReq.RuleIDs
	if event.RuleIDs == nil {
		event.RuleIDs = []string{}
	}
	event.Score = parsedReq.Score

	return event
}

// serializeToJSON сериализует объект в JSON строку
func serializeToJSON(data interface{}, logger *zap.Logger) string {
	if data == nil {
		return "{}"
	}

	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			return "{}"
		}
	case map[string]string:
		if len(v) == 0 {
			return "{}"
		}
	case []BodyParam:
		if len(v) == 0 {
			return "[]"
		}
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		logger.Warn("failed to serialize to JSON",
			zap.Error(err),
			zap.String("type", fmt.Sprintf("%T", data)),
		)
		return "{}"
	}

	return string(jsonBytes)
}
