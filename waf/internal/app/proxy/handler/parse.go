package handler

import (
	"bytes"
	"io"
	"net/http"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/wafcontext"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/pipeline"
)

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

			if truncated {
				r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(rawBody), r.Body))
			} else {
				r.Body = io.NopCloser(bytes.NewReader(rawBody))
			}

			next.ServeHTTP(w, r.WithContext(wafcontext.WithParsedRequest(r.Context(), pr)))
		})
	}
}
