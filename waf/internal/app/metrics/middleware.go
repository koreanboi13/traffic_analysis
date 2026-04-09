package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// Instrument returns chi middleware that records request metrics.
func Instrument(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.ActiveConns.Inc()
			defer m.ActiveConns.Dec()

			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			next.ServeHTTP(rw, r)

			duration := time.Since(start).Seconds()
			status := strconv.Itoa(rw.statusCode)
			verdict := w.Header().Get("X-WAF-Verdict")
			if verdict == "" {
				verdict = "allow"
			}

			m.RequestsTotal.WithLabelValues(r.Method, r.URL.Path, status, verdict).Inc()
			m.RequestLatency.WithLabelValues(r.Method, r.URL.Path).Observe(duration)

			if verdict == "block" {
				m.BlocksTotal.Inc()
			}
		})
	}
}
