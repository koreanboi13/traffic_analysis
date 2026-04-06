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
				ClientIP:    clientIPFromRemoteAddr(r.RemoteAddr),
			}

			rawBody, truncated := readBodyLimited(r.Body, maxBodySize)
			pr.RawBody = rawBody
			pr.BodyTruncated = truncated
			pr.BodySize = len(rawBody)
			pr.BodyParams = extractBodyParams(rawBody, pr.ContentType)

			r.Body = io.NopCloser(bytes.NewReader(rawBody))
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

func readBodyLimited(body io.ReadCloser, maxBodySize int) ([]byte, bool) {
	if body == nil {
		return nil, false
	}
	defer body.Close()

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
		params := make([]BodyParam, 0, len(object))
		for key, value := range object {
			params = append(params, BodyParam{Key: key, Value: stringifyJSONValue(value), Source: "json"})
		}
		return params
	}

	return nil
}

func stringifyJSONValue(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	default:
		encoded, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(encoded)
	}
}

func clientIPFromRemoteAddr(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}
