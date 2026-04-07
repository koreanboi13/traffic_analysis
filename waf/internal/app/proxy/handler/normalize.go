package handler

import (
	"net/http"

	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/wafcontext"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/pipeline"
)

// Normalize fills ParsedRequest normalized fields for downstream detection.
func Normalize(maxPasses int) func(http.Handler) http.Handler {
	if maxPasses <= 0 {
		maxPasses = 3
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := wafcontext.GetParsedRequest(r.Context())
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
