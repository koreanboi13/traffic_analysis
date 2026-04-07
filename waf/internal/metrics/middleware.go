package metrics

import (
	"net/http"
	"strconv"
	"time"
)

// Instrument returns a chi-compatible middleware that records request metrics.
func Instrument(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.ActiveConns.Inc()
			defer m.ActiveConns.Dec()

			start := time.Now()
			ww := &responseWriter{ResponseWriter: w, statusCode: 200}
			next.ServeHTTP(ww, r)
			duration := time.Since(start).Seconds()

			// Get verdict from response header (set by detect middleware).
			verdict := ww.Header().Get("X-WAF-Verdict")
			if verdict == "" {
				verdict = "allow"
			}
			statusStr := strconv.Itoa(ww.statusCode)

			m.RequestsTotal.WithLabelValues(verdict, statusStr).Inc()
			m.VerdictCounter.WithLabelValues(verdict).Inc()
			m.LatencyHistogram.WithLabelValues(verdict).Observe(duration)

			if r.ContentLength > 0 {
				m.BodySizeHist.WithLabelValues(r.Method).Observe(float64(r.ContentLength))
			}
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// Unwrap allows middleware like chi's to access the underlying ResponseWriter.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}
