package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewServer creates an HTTP server that serves Prometheus metrics.
func NewServer(addr string, m *Metrics) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{}))

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}
