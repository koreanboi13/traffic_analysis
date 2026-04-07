package pipeline

import (
	"html"
	"net/url"
	"path"
	"strings"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// NormalizeString URL-decodes (multi-pass), HTML-unescapes, lowercases,
// and strips null bytes from input.
func NormalizeString(input string, maxPasses int) string {
	decoded := DecodeURLMultiPass(input, maxPasses)
	decoded = html.UnescapeString(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

// NormalizePath URL-decodes (multi-pass), HTML-unescapes, cleans the path,
// lowercases, and strips null bytes.
func NormalizePath(input string, maxPasses int) string {
	decoded := DecodeURLMultiPass(input, maxPasses)
	decoded = html.UnescapeString(decoded)
	decoded = path.Clean(decoded)
	decoded = strings.ToLower(decoded)
	decoded = strings.ReplaceAll(decoded, "\x00", "")
	return decoded
}

// NormalizeQueryParams normalizes both keys and values in the params map.
func NormalizeQueryParams(params map[string]string, maxPasses int) map[string]string {
	if len(params) == 0 {
		return nil
	}
	normalized := make(map[string]string, len(params))
	for key, value := range params {
		normalizedKey := NormalizeString(key, maxPasses)
		normalizedValue := NormalizeString(value, maxPasses)
		normalized[normalizedKey] = normalizedValue
	}
	return normalized
}

// NormalizeBodyParams normalizes the Value of each BodyParam.
func NormalizeBodyParams(params []domain.BodyParam, maxPasses int) []domain.BodyParam {
	if len(params) == 0 {
		return nil
	}
	normalized := make([]domain.BodyParam, len(params))
	for i, param := range params {
		normalized[i] = domain.BodyParam{
			Key:    param.Key,
			Value:  NormalizeString(param.Value, maxPasses),
			Source: param.Source,
		}
	}
	return normalized
}

// DecodeURLMultiPass repeatedly URL-decodes input until it stabilizes or maxPasses is reached.
func DecodeURLMultiPass(input string, maxPasses int) string {
	result := input
	for pass := 0; pass < maxPasses; pass++ {
		decoded, err := url.QueryUnescape(result)
		if err != nil {
			break
		}
		if decoded == result {
			break
		}
		result = decoded
	}
	return result
}
