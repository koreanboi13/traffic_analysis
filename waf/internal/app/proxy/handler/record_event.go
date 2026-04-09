package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/wafcontext"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// EventSender is a local interface for sending WAF events asynchronously.
type EventSender interface {
	Send(event domain.Event)
}

// recordResponseWriter wraps http.ResponseWriter to capture the status code.
type recordResponseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func newRecordResponseWriter(w http.ResponseWriter) *recordResponseWriter {
	return &recordResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
		written:        false,
	}
}

func (rw *recordResponseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.statusCode = statusCode
		rw.written = true
		rw.ResponseWriter.WriteHeader(statusCode)
	}
}

func (rw *recordResponseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(data)
}

// RecordEvent middleware records WAF events via EventSender after each request.
type RecordEvent struct {
	sender EventSender
	logger *zap.Logger
}

// NewRecordEvent creates a new RecordEvent middleware.
func NewRecordEvent(sender EventSender, logger *zap.Logger) *RecordEvent {
	return &RecordEvent{
		sender: sender,
		logger: logger,
	}
}

// Handler returns the http.Handler middleware.
func (m *RecordEvent) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		rw := newRecordResponseWriter(w)

		next.ServeHTTP(rw, r)

		parsedReq := wafcontext.GetParsedRequest(r.Context())
		if parsedReq == nil {
			m.logger.Warn("parsed request not found in context, skipping event recording",
				zap.String("path", r.URL.Path),
				zap.String("method", r.Method),
			)
			return
		}

		latencyMs := float32(time.Since(startTime).Nanoseconds()) / 1_000_000.0
		event := m.buildEvent(parsedReq, rw.statusCode, latencyMs)
		m.sender.Send(event)

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

func (m *RecordEvent) buildEvent(parsedReq *domain.ParsedRequest, statusCode int, latencyMs float32) domain.Event {
	queryParamsJSON := serializeToJSON(parsedReq.QueryParams, m.logger)
	bodyParamsJSON := serializeToJSON(parsedReq.BodyParams, m.logger)
	headersJSON := serializeToJSON(parsedReq.Headers, m.logger)
	cookiesJSON := serializeToJSON(parsedReq.Cookies, m.logger)

	bodyTruncated := uint8(0)
	if parsedReq.BodyTruncated {
		bodyTruncated = 1
	}

	event := domain.Event{}
	event.EventID = uuid.New()
	event.Timestamp = time.Now().UnixMilli()

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

	event.RuleIDs = parsedReq.RuleIDs
	if event.RuleIDs == nil {
		event.RuleIDs = []string{}
	}
	event.Score = parsedReq.Score

	return event
}

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
	case []domain.BodyParam:
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
