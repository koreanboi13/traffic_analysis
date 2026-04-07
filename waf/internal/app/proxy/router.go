package proxy

import (
	"net/http/httputil"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/metrics"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/handler"
	"go.uber.org/zap"
)

// RouterConfig holds parameters for building the proxy router.
type RouterConfig struct {
	MaxBodySize      int
	MaxDecodePasses  int
	DetectionEnabled bool
}

// NewRouter creates a chi.Router with the full WAF middleware pipeline.
func NewRouter(
	cfg RouterConfig,
	reverseProxy *httputil.ReverseProxy,
	detector handler.Detector,
	allowlist handler.RequestBypasser,
	eventSender handler.EventSender,
	m *metrics.Metrics,
	logger *zap.Logger,
) chi.Router {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)

	// Health check — before WAF middleware.
	r.Get("/healthz", handler.HealthHandler())

	// WAF pipeline: Metrics -> Parse -> Normalize -> RecordEvent -> Detect -> Proxy
	r.Group(func(r chi.Router) {
		r.Use(metrics.Instrument(m))
		r.Use(handler.Parse(cfg.MaxBodySize))
		r.Use(handler.Normalize(cfg.MaxDecodePasses))

		recordEvent := handler.NewRecordEvent(eventSender, logger)
		r.Use(recordEvent.Handler)

		detect := handler.NewDetect(detector, allowlist, cfg.DetectionEnabled, logger)
		r.Use(detect.Handler)

		r.Handle("/*", reverseProxy)
	})

	return r
}
