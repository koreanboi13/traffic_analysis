package middleware

import (
	"html"
	"net/http"
	"net/url"
	"path"
	"strings"

	"go.uber.org/zap"
)

const defaultMaxDecodePasses = 3

// Normalize fills ParsedRequest normalized fields for downstream detection.
func Normalize(maxPasses int, logger *zap.Logger) func(http.Handler) http.Handler {
	if maxPasses <= 0 {
		maxPasses = defaultMaxDecodePasses
	}
	if logger == nil {
		logger = zap.NewNop()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := GetParsedRequest(r.Context())
			if pr == nil {
				logger.Debug("normalize middleware: parsed request is missing, skipping",
					zap.String("method", r.Method),
					zap.String("path", r.URL.Path),
				)
				next.ServeHTTP(w, r)
				return
			}

			logger.Debug("normalize middleware: start",
				zap.String("request_id", pr.RequestID),
				zap.Int("query_params_count", len(pr.QueryParams)),
				zap.Int("body_params_count", len(pr.BodyParams)),
				zap.Int("raw_body_bytes", len(pr.RawBody)),
				zap.Int("max_decode_passes", maxPasses),
			)

			pr.NormalizedParams = normalizeQueryParams(pr.QueryParams, maxPasses, logger)
			pr.NormalizedQuery = normalizeString(pr.RawQuery, maxPasses, logger)
			pr.NormalizedPath = normalizePath(pr.Path, maxPasses, logger)
			pr.NormalizedBody = normalizeString(string(pr.RawBody), maxPasses, logger)
			pr.NormalizedBodyParams = normalizeBodyParams(pr.BodyParams, maxPasses, logger)

			logger.Debug("normalize middleware: done",
				zap.String("request_id", pr.RequestID),
				zap.Bool("query_changed", pr.NormalizedQuery != pr.RawQuery),
				zap.Bool("path_changed", pr.NormalizedPath != pr.Path),
				zap.Bool("body_changed", pr.NormalizedBody != string(pr.RawBody)),
			)

			next.ServeHTTP(w, r)
		})
	}
}

func normalizeQueryParams(params map[string]string, maxPasses int, logger *zap.Logger) map[string]string {
	if len(params) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(params))
	for key, value := range params {
		normalizedValue := normalizeString(value, maxPasses, logger)
		normalized[key] = normalizedValue
		if normalizedValue != value {
			logger.Debug("normalize query param: value changed", zap.String("key", key))
		}
	}

	return normalized
}

func normalizeBodyParams(params []BodyParam, maxPasses int, logger *zap.Logger) []BodyParam {
	if len(params) == 0 {
		return nil
	}

	normalized := make([]BodyParam, len(params))
	for i, param := range params {
		normalizedValue := normalizeString(param.Value, maxPasses, logger)
		normalized[i] = BodyParam{
			Key:    param.Key,
			Value:  normalizedValue,
			Source: param.Source,
		}
		if normalizedValue != param.Value {
			logger.Debug("normalize body param: value changed",
				zap.String("key", param.Key),
				zap.String("source", param.Source),
			)
		}
	}

	return normalized
}

func normalizeString(input string, maxPasses int, logger *zap.Logger) string {
	decoded := decodeURLMultiPass(input, maxPasses, logger)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

func normalizePath(input string, maxPasses int, logger *zap.Logger) string {
	decoded := decodeURLMultiPass(input, maxPasses, logger)
	decoded = path.Clean(decoded)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

func decodeURLMultiPass(input string, maxPasses int, logger *zap.Logger) string {
	result := input

	for pass := 0; pass < maxPasses; pass++ {
		decoded, err := url.QueryUnescape(result)
		if err != nil {
			logger.Warn("normalize url decode: stop on decode error",
				zap.Int("pass", pass+1),
				zap.Error(err),
			)
			break
		}
		if decoded == result {
			logger.Debug("normalize url decode: stabilized",
				zap.Int("pass", pass+1),
			)
			break
		}
		logger.Debug("normalize url decode: pass changed input", zap.Int("pass", pass+1))
		result = decoded
	}

	return result
}
