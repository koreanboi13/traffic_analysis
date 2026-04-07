package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/pipeline"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// Parse middleware
// ---------------------------------------------------------------------------

// Parse extracts request data into domain.ParsedRequest and stores it in context.
func Parse(maxBodySize int) func(http.Handler) http.Handler {
	if maxBodySize <= 0 {
		maxBodySize = 1 << 20
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := chimw.GetReqID(r.Context())
			if requestID == "" {
				requestID = uuid.New().String()
			}

			pr := &domain.ParsedRequest{
				RequestID:   requestID,
				Method:      r.Method,
				Path:        r.URL.Path,
				RawQuery:    r.URL.RawQuery,
				QueryParams: pipeline.ExtractQueryParams(r.URL.Query()),
				Headers:     pipeline.ExtractHeaders(r.Header),
				Cookies:     pipeline.ExtractCookies(r.Cookies()),
				UserAgent:   r.UserAgent(),
				Referer:     r.Referer(),
				ContentType: r.Header.Get("Content-Type"),
				Host:        r.Host,
				ClientIP:    pipeline.ExtractClientIP(r),
			}

			rawBody, truncated := pipeline.ReadBodyLimited(r.Body, maxBodySize)
			pr.RawBody = rawBody
			pr.BodyTruncated = truncated
			pr.BodySize = len(rawBody)
			pr.BodyParams = pipeline.ExtractBodyParams(rawBody, pr.ContentType)

			// Reassemble body: buffered prefix + remaining original stream.
			// If body was truncated, r.Body still has the unread tail.
			if truncated {
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(rawBody), r.Body))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(rawBody))
			}

			next.ServeHTTP(w, r.WithContext(WithParsedRequest(r.Context(), pr)))
		})
	}
}

// ---------------------------------------------------------------------------
// Normalize middleware
// ---------------------------------------------------------------------------

// Normalize fills ParsedRequest normalized fields for downstream detection.
func Normalize(maxPasses int) func(http.Handler) http.Handler {
	if maxPasses <= 0 {
		maxPasses = 3
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := GetParsedRequest(r.Context())
			if pr == nil {
				next.ServeHTTP(w, r)
				return
			}

			pr.NormalizedParams = pipeline.NormalizeQueryParams(pr.QueryParams, maxPasses)
			pr.NormalizedQuery = pipeline.NormalizeString(pr.RawQuery, maxPasses)
			pr.NormalizedPath = pipeline.NormalizePath(pr.Path, maxPasses)
			pr.NormalizedBody = pipeline.NormalizeString(string(pr.RawBody), maxPasses)
			pr.NormalizedBodyParams = pipeline.NormalizeBodyParams(pr.BodyParams, maxPasses)

			next.ServeHTTP(w, r)
		})
	}
}

// ---------------------------------------------------------------------------
// Detect middleware
// ---------------------------------------------------------------------------

type blockResponse struct {
	RequestID    string   `json:"request_id"`
	Message      string   `json:"message"`
	MatchedRules []string `json:"matched_rules"`
	Score        float32  `json:"risk_score"`
}

// RequestBypasser determines if a request should bypass WAF detection.
type RequestBypasser interface {
	ShouldBypass(req *domain.ParsedRequest) bool
}

// Detector evaluates rules against zone data from a parsed request.
type Detector interface {
	Evaluate(zoneData map[string][]string) domain.EvaluationResult
}

// Detect middleware evaluates requests against detection rules.
type Detect struct {
	detector  Detector
	allowlist RequestBypasser
	enabled   bool
	logger    *zap.Logger
}

// NewDetect creates a new Detect middleware.
func NewDetect(detector Detector, allowlist RequestBypasser, enabled bool, logger *zap.Logger) *Detect {
	return &Detect{
		detector:  detector,
		allowlist: allowlist,
		enabled:   enabled,
		logger:    logger,
	}
}

// Handler returns the middleware handler function.
func (d *Detect) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr := GetParsedRequest(r.Context())

		if pr == nil || !d.enabled {
			if pr != nil {
				pr.Verdict = "allow"
			}
			next.ServeHTTP(w, r)
			return
		}

		if d.allowlist.ShouldBypass(pr) {
			pr.Verdict = "allow"
			d.logger.Debug("request allowlisted",
				zap.String("request_id", pr.RequestID),
				zap.String("client_ip", pr.ClientIP),
			)
			next.ServeHTTP(w, r)
			return
		}

		result := d.detector.Evaluate(extractZoneData(pr))

		// Set detection results on ParsedRequest BEFORE writing response,
		// so RecordEvent (which wraps this middleware) can read them.
		pr.Verdict = result.Verdict
		pr.RuleIDs = result.MatchedRuleIDs
		pr.Score = result.Score

		d.logger.Debug("detection result",
			zap.String("request_id", pr.RequestID),
			zap.String("verdict", result.Verdict),
			zap.Float32("score", result.Score),
			zap.Int("matched_rules", len(result.Matches)),
		)

		if result.Verdict == "block" {
			w.Header().Set("X-WAF-Verdict", "block")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(blockResponse{
				RequestID:    pr.RequestID,
				Message:      "Request blocked by WAF",
				MatchedRules: result.MatchedRuleIDs,
				Score:        result.Score,
			})
			return
		}

		w.Header().Set("X-WAF-Verdict", result.Verdict)
		next.ServeHTTP(w, r)
	})
}

// extractZoneData maps domain.ParsedRequest fields to zone name -> values for the rule engine.
func extractZoneData(pr *domain.ParsedRequest) map[string][]string {
	zd := make(map[string][]string, 5)

	// query zone
	queryVals := make([]string, 0, len(pr.NormalizedParams)+1)
	for _, v := range pr.NormalizedParams {
		queryVals = append(queryVals, v)
	}
	if pr.NormalizedQuery != "" {
		queryVals = append(queryVals, pr.NormalizedQuery)
	}
	zd["query"] = queryVals

	// path zone
	zd["path"] = []string{pr.NormalizedPath}

	// headers zone
	headerVals := make([]string, 0, len(pr.Headers))
	for _, v := range pr.Headers {
		headerVals = append(headerVals, v)
	}
	zd["headers"] = headerVals

	// cookies zone
	cookieVals := make([]string, 0, len(pr.Cookies))
	for _, v := range pr.Cookies {
		cookieVals = append(cookieVals, v)
	}
	zd["cookies"] = cookieVals

	// body zone
	var bodyVals []string
	if pr.NormalizedBody != "" {
		bodyVals = append(bodyVals, pr.NormalizedBody)
	}
	for _, bp := range pr.NormalizedBodyParams {
		bodyVals = append(bodyVals, bp.Value)
	}
	zd["body"] = bodyVals

	return zd
}

// ---------------------------------------------------------------------------
// RecordEvent middleware
// ---------------------------------------------------------------------------

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

		// Pass request to next handler (proxy / detect middleware).
		next.ServeHTTP(rw, r)

		// Read ParsedRequest AFTER next — so Detect middleware can update verdict/score.
		parsedReq := GetParsedRequest(r.Context())
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

// buildEvent creates a domain.Event from a domain.ParsedRequest.
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

	// Base fields
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

	// Extended fields
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

// serializeToJSON serializes a value to a JSON string.
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
