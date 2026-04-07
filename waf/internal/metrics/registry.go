package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all WAF Prometheus metrics with a custom registry.
type Metrics struct {
	RequestsTotal    *prometheus.CounterVec
	BlocksByRuleID   *prometheus.CounterVec
	VerdictCounter   *prometheus.CounterVec
	LatencyHistogram *prometheus.HistogramVec
	BodySizeHist     *prometheus.HistogramVec
	ActiveConns      prometheus.Gauge
	Registry         *prometheus.Registry
}

// NewMetrics creates a new Metrics instance with a custom Prometheus registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		RequestsTotal: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total number of requests processed",
		}, []string{"verdict", "status_code"}),
		BlocksByRuleID: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "waf_blocks_by_rule_total",
			Help: "Total blocks by rule_id",
		}, []string{"rule_id"}),
		VerdictCounter: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "waf_verdict_total",
			Help: "Total requests by verdict",
		}, []string{"verdict"}),
		LatencyHistogram: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_duration_seconds",
			Help:    "Request processing latency",
			Buckets: prometheus.DefBuckets,
		}, []string{"verdict"}),
		BodySizeHist: promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_body_bytes",
			Help:    "Request body size in bytes",
			Buckets: prometheus.ExponentialBuckets(64, 4, 8), // 64, 256, 1K, 4K, 16K, 64K, 256K, 1M
		}, []string{"method"}),
		ActiveConns: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "waf_active_connections",
			Help: "Number of active connections",
		}),
	}
	return m
}
