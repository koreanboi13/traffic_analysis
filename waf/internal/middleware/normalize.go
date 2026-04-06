package middleware

import (
	"html"
	"net/http"
	"net/url"
	"path"
	"strings"
)

const defaultMaxDecodePasses = 3

// Normalize fills ParsedRequest normalized fields for downstream detection.
func Normalize(maxPasses int) func(http.Handler) http.Handler {
	if maxPasses <= 0 {
		maxPasses = defaultMaxDecodePasses
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := GetParsedRequest(r.Context())
			if pr != nil {
				pr.NormalizedParams = normalizeQueryParams(pr.QueryParams, maxPasses)
				pr.NormalizedQuery = normalizeString(pr.RawQuery, maxPasses)
				pr.NormalizedPath = normalizePath(pr.Path, maxPasses)
				pr.NormalizedBody = normalizeString(string(pr.RawBody), maxPasses)
				pr.NormalizedBodyParams = normalizeBodyParams(pr.BodyParams, maxPasses)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func normalizeQueryParams(params map[string]string, maxPasses int) map[string]string {
	if len(params) == 0 {
		return nil
	}

	normalized := make(map[string]string, len(params))
	for key, value := range params {
		normalized[key] = normalizeString(value, maxPasses)
	}

	return normalized
}

func normalizeBodyParams(params []BodyParam, maxPasses int) []BodyParam {
	if len(params) == 0 {
		return nil
	}

	normalized := make([]BodyParam, len(params))
	for i, param := range params {
		normalized[i] = BodyParam{
			Key:    param.Key,
			Value:  normalizeString(param.Value, maxPasses),
			Source: param.Source,
		}
	}

	return normalized
}

func normalizeString(input string, maxPasses int) string {
	decoded := decodeURLMultiPass(input, maxPasses)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

func normalizePath(input string, maxPasses int) string {
	decoded := decodeURLMultiPass(input, maxPasses)
	decoded = path.Clean(decoded)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

func decodeURLMultiPass(input string, maxPasses int) string {
	result := input

	for range maxPasses {
		decoded, err := url.QueryUnescape(result)
		if err != nil || decoded == result {
			break
		}
		result = decoded
	}

	return result
}
