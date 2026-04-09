package pipeline

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// ExtractQueryParams converts url.Values to a flat string map, keeping the first value per key.
func ExtractQueryParams(values url.Values) map[string]string {
	if len(values) == 0 {
		return nil
	}
	params := make(map[string]string, len(values))
	for key, vals := range values {
		if len(vals) == 0 {
			params[key] = ""
			continue
		}
		params[key] = vals[0]
	}
	return params
}

// ExtractHeaders converts http.Header to a flat string map with lowercase keys,
// keeping the first value per header.
func ExtractHeaders(header http.Header) map[string]string {
	if len(header) == 0 {
		return nil
	}
	headers := make(map[string]string, len(header))
	for key, vals := range header {
		if len(vals) == 0 {
			headers[strings.ToLower(key)] = ""
			continue
		}
		headers[strings.ToLower(key)] = vals[0]
	}
	return headers
}

// ExtractCookies converts a cookie slice to a name→value map.
func ExtractCookies(cookies []*http.Cookie) map[string]string {
	if len(cookies) == 0 {
		return nil
	}
	result := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}
	return result
}

// ReadBodyLimited reads up to maxBodySize bytes from body.
// Returns the data read and a boolean indicating whether the body was truncated.
// Does NOT close body — caller is responsible for reassembly.
func ReadBodyLimited(body io.ReadCloser, maxBodySize int) ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	limited := io.LimitReader(body, int64(maxBodySize)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, false
	}
	if len(data) > maxBodySize {
		return data[:maxBodySize], true
	}
	return data, false
}

// ExtractBodyParams parses rawBody according to contentType and returns structured params.
// Supports application/x-www-form-urlencoded and application/json.
func ExtractBodyParams(rawBody []byte, contentType string) []domain.BodyParam {
	if len(rawBody) == 0 {
		return nil
	}

	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(rawBody))
		if err != nil {
			return nil
		}
		params := make([]domain.BodyParam, 0, len(vals))
		for key, arr := range vals {
			if len(arr) == 0 {
				params = append(params, domain.BodyParam{Key: key, Value: "", Source: "form"})
				continue
			}
			params = append(params, domain.BodyParam{Key: key, Value: arr[0], Source: "form"})
		}
		return params
	}

	if strings.Contains(contentType, "application/json") {
		var object map[string]interface{}
		if err := json.Unmarshal(rawBody, &object); err != nil {
			return nil
		}
		var params []domain.BodyParam
		FlattenJSON(object, "", &params, 0, 5)
		return params
	}

	return nil
}

// ExtractClientIP returns the client IP using X-Real-IP → X-Forwarded-For (first) → RemoteAddr.
func ExtractClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// FlattenJSON recursively flattens a JSON object into dot-notation BodyParams.
// maxDepth limits recursion to prevent stack overflow on deeply nested input.
func FlattenJSON(data map[string]interface{}, prefix string, params *[]domain.BodyParam, depth, maxDepth int) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			if depth < maxDepth {
				FlattenJSON(v, fullKey, params, depth+1, maxDepth)
			} else {
				encoded, _ := json.Marshal(v)
				*params = append(*params, domain.BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
			}
		case []interface{}:
			encoded, _ := json.Marshal(v)
			*params = append(*params, domain.BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
		case string:
			*params = append(*params, domain.BodyParam{Key: fullKey, Value: v, Source: "json"})
		case nil:
			*params = append(*params, domain.BodyParam{Key: fullKey, Value: "", Source: "json"})
		default:
			encoded, _ := json.Marshal(v)
			*params = append(*params, domain.BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
		}
	}
}
