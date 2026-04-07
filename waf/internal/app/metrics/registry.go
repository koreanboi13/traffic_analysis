package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all WAF Prometheus metrics.
type Metrics struct {
	RequestsTotal  *prometheus.CounterVec
	RequestLatency *prometheus.HistogramVec
	BlocksTotal    prometheus.Counter
	BlocksByRuleID *prometheus.CounterVec
	ActiveConns    prometheus.Gauge
	Registry       *prometheus.Registry
}

// NewMetrics creates a new Metrics instance with a dedicated Prometheus registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	f := promauto.With(reg)

	return &Metrics{
		RequestsTotal: f.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total number of requests processed by the WAF proxy.",
		}, []string{"method", "path", "status", "verdict"}),

		RequestLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "waf_request_latency_seconds",
			Help:    "Request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "path"}),

		BlocksTotal: f.NewCounter(prometheus.CounterOpts{
			Name: "waf_blocks_total",
			Help: "Total number of blocked requests.",
		}),

		BlocksByRuleID: f.NewCounterVec(prometheus.CounterOpts{
			Name: "waf_blocks_by_rule_total",
			Help: "Blocked requests broken down by rule ID.",
		}, []string{"rule_id"}),

		ActiveConns: f.NewGauge(prometheus.GaugeOpts{
			Name: "waf_active_connections",
			Help: "Number of requests currently being processed.",
		}),

		Registry: reg,
	}
}
