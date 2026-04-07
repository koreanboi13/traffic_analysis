package middleware

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Parse extracts request data into ParsedRequest and stores it in context.
func Parse(maxBodySize int) func(http.Handler) http.Handler {
	if maxBodySize <= 0 {
		maxBodySize = 1 << 20
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pr := &ParsedRequest{
				RequestID:   chimw.GetReqID(r.Context()),
				Method:      r.Method,
				Path:        r.URL.Path,
				RawQuery:    r.URL.RawQuery,
				QueryParams: extractQueryParams(r.URL.Query()),
				Headers:     extractHeaders(r.Header),
				Cookies:     extractCookies(r.Cookies()),
				UserAgent:   r.UserAgent(),
				Referer:     r.Referer(),
				ContentType: r.Header.Get("Content-Type"),
				Host:        r.Host,
				ClientIP:    extractClientIP(r),
			}

			rawBody, truncated := readBodyLimited(r.Body, maxBodySize)
			pr.RawBody = rawBody
			pr.BodyTruncated = truncated
			pr.BodySize = len(rawBody)
			pr.BodyParams = extractBodyParams(rawBody, pr.ContentType)

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

func extractQueryParams(values url.Values) map[string]string {
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

func extractHeaders(header http.Header) map[string]string {
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

func extractCookies(cookies []*http.Cookie) map[string]string {
	if len(cookies) == 0 {
		return nil
	}

	result := make(map[string]string, len(cookies))
	for _, cookie := range cookies {
		result[cookie.Name] = cookie.Value
	}

	return result
}

// readBodyLimited reads up to maxBodySize bytes from body.
// If body exceeds maxBodySize, returns truncated data and true.
// IMPORTANT: does NOT close body — caller is responsible for reassembly.
func readBodyLimited(body io.ReadCloser, maxBodySize int) ([]byte, bool) {
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

func extractBodyParams(rawBody []byte, contentType string) []BodyParam {
	if len(rawBody) == 0 {
		return nil
	}

	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		vals, err := url.ParseQuery(string(rawBody))
		if err != nil {
			return nil
		}
		params := make([]BodyParam, 0, len(vals))
		for key, arr := range vals {
			if len(arr) == 0 {
				params = append(params, BodyParam{Key: key, Value: "", Source: "form"})
				continue
			}
			params = append(params, BodyParam{Key: key, Value: arr[0], Source: "form"})
		}
		return params
	}

	if strings.Contains(contentType, "application/json") {
		var object map[string]interface{}
		if err := json.Unmarshal(rawBody, &object); err != nil {
			return nil
		}
		var params []BodyParam
		flattenJSON(object, "", &params, 0, 5)
		return params
	}

	return nil
}

// flattenJSON recursively flattens a JSON object into dot-notation BodyParams.
// maxDepth limits recursion to prevent stack overflow on deeply nested input.
func flattenJSON(data map[string]interface{}, prefix string, params *[]BodyParam, depth, maxDepth int) {
	for key, value := range data {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := value.(type) {
		case map[string]interface{}:
			if depth < maxDepth {
				flattenJSON(v, fullKey, params, depth+1, maxDepth)
			} else {
				// Max depth reached — serialize remainder as JSON string
				encoded, _ := json.Marshal(v)
				*params = append(*params, BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
			}
		case []interface{}:
			// Arrays: serialize as JSON string (individual element scanning is Phase 4)
			encoded, _ := json.Marshal(v)
			*params = append(*params, BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
		case string:
			*params = append(*params, BodyParam{Key: fullKey, Value: v, Source: "json"})
		case nil:
			*params = append(*params, BodyParam{Key: fullKey, Value: "", Source: "json"})
		default:
			encoded, _ := json.Marshal(v)
			*params = append(*params, BodyParam{Key: fullKey, Value: string(encoded), Source: "json"})
		}
	}
}

// extractClientIP returns the client IP using X-Real-IP → X-Forwarded-For (first) → RemoteAddr.
func extractClientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For: client, proxy1, proxy2 — take first
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
