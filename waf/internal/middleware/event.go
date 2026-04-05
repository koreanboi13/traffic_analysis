package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"waf/internal/events"
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

// ParsedRequest содержит все данные, собранные из запроса после парсинга и нормализации
type ParsedRequest struct {
	RequestID        string
	ClientIP         string
	Host             string
	Method           string
	Path             string
	RawQuery         string
	NormalizedQuery  string
	RawBody          string
	NormalizedBody   string
	QueryParams      map[string]interface{}
	BodyParams       map[string]interface{}
	Headers          map[string]string
	Cookies          map[string]string
	UserAgent        string
	ContentType      string
	Referer          string
	BodyTruncated    bool
	BodySize         uint32
}

// contextKey тип для ключей контекста
type contextKey string

const (
	// ParsedRequestKey ключ для хранения ParsedRequest в контексте
	ParsedRequestKey contextKey = "parsed_request"
)

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
		// Засекаем время начала обработки запроса
		startTime := time.Now()

		// Создаём обёртку для response writer
		rw := newResponseWriter(w)

		// Получаем ParsedRequest из контекста
		parsedReq := getParsedRequestFromContext(r.Context())
		if parsedReq == nil {
			m.logger.Warn("parsed request not found in context, skipping event recording",
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
			)
			// Пропускаем запрос дальше, даже если нет данных для логирования
			next.ServeHTTP(rw, r)
			return
		}

		// Пропускаем запрос к следующему обработчику (proxy)
		next.ServeHTTP(rw, r)

		// Вычисляем задержку в миллисекундах
		latencyMs := float32(time.Since(startTime).Nanoseconds()) / 1_000_000.0

		// Собираем событие
		event := m.buildEvent(parsedReq, rw.StatusCode(), latencyMs)

		// Отправляем событие через writer
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
func (m *RecordEvent) buildEvent(parsedReq *ParsedRequest, statusCode int, latencyMs float32) events.Event {
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
	event := events.NewEvent()
	
	// Заполняем базовые поля
	event.RequestID = parsedReq.RequestID
	event.ClientIP = parsedReq.ClientIP
	event.Host = parsedReq.Host
	event.Method = parsedReq.Method
	event.Path = parsedReq.Path
	event.Verdict = "allow" // Пока всегда allow, позже будет меняться detect middleware
	event.StatusCode = uint16(statusCode)
	event.LatencyMs = latencyMs

	// Заполняем расширенные поля
	event.RawQuery = parsedReq.RawQuery
	event.NormalizedQuery = parsedReq.NormalizedQuery
	event.RawBody = parsedReq.RawBody
	event.NormalizedBody = parsedReq.NormalizedBody
	event.QueryParams = queryParamsJSON
	event.BodyParams = bodyParamsJSON
	event.Headers = headersJSON
	event.Cookies = cookiesJSON
	event.UserAgent = parsedReq.UserAgent
	event.ContentType = parsedReq.ContentType
	event.Referer = parsedReq.Referer
	event.BodyTruncated = bodyTruncated
	event.BodySize = parsedReq.BodySize

	// Заполняем плейсхолдеры для Phase 4
	event.TriggeredRulesIDs = []string{} // Пустой массив строк
	event.RiskScore = 0.0

	return event
}

// serializeToJSON сериализует объект в JSON строку
func serializeToJSON(data interface{}, logger *zap.Logger) string {
	if data == nil {
		return "{}"
	}
	
	// Проверяем пустые map'ы
	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			return "{}"
		}
	case map[string]string:
		if len(v) == 0 {
			return "{}"
		}
	}
	
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		logger.Warn("failed to serialize to JSON",
			zap.Error(err),
			zap.String("type", getType(data)),
		)
		return "{}"
	}
	
	return string(jsonBytes)
}

// getType возвращает строковое представление типа для логирования
func getType(v interface{}) string {
	if v == nil {
		return "nil"
	}
	return string(v.(type).(string))
}

// getParsedRequestFromContext извлекает ParsedRequest из контекста
func getParsedRequestFromContext(ctx context.Context) *ParsedRequest {
	if val := ctx.Value(ParsedRequestKey); val != nil {
		if req, ok := val.(*ParsedRequest); ok {
			return req
		}
	}
	return nil
}

// SetParsedRequestToContext сохраняет ParsedRequest в контекст
func SetParsedRequestToContext(ctx context.Context, req *ParsedRequest) context.Context {
	return context.WithValue(ctx, ParsedRequestKey, req)
}