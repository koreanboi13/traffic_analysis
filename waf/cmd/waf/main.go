package main

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/engine"
	events "github.com/koreanboi13/traffic_analysis/waf/internal/events/clickhouse"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	// 1. Determine config path.
	configPath := os.Getenv("WAF_CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	// 2. Load configuration.
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 3. Setup logger.
	logger, err := setupLogger(cfg.Logging)
	if err != nil {
		log.Fatalf("failed to setup logger: %v", err)
	}
	defer logger.Sync()

	// 4. Connect to ClickHouse.
	storage, err := events.NewStorage(cfg.ClickHouse.Addr, cfg.ClickHouse.Database, logger)
	if err != nil {
		logger.Fatal("failed to connect to clickhouse", zap.Error(err))
	}
	defer storage.Close()
	_ = storage // will be used by event writer in later plans

	// 5. Create reverse proxy.
	proxy, err := engine.NewProxy(cfg.Proxy.BackendURL, logger)
	if err != nil {
		logger.Fatal("failed to create proxy", zap.Error(err))
	}

	// 6. Setup chi router.
	r := chi.NewRouter()
	r.Use(chimw.RequestID)

	// healthz before WAF middleware — no analysis on healthchecks.
	r.Get("/healthz", engine.HealthHandler())

	// WAF middleware group — Parse, Normalize, RecordEvent will be added here.
	r.Group(func(r chi.Router) {
		// r.Use(wafmw.Parse(cfg.Analysis.MaxBodySize))
		// r.Use(wafmw.Normalize(cfg.Analysis.MaxDecodePasses))
		// r.Use(wafmw.RecordEvent(writer))
		r.Handle("/*", proxy)
	})

	// 7. Start HTTP server.
	logger.Info("waf proxy ready",
		zap.String("listen", cfg.Proxy.ListenAddr),
		zap.String("backend", cfg.Proxy.BackendURL),
	)

	if err := http.ListenAndServe(cfg.Proxy.ListenAddr, r); err != nil {
		logger.Fatal("http server failed", zap.Error(err))
	}
}

// setupLogger creates a zap.Logger based on logging config.
func setupLogger(cfg config.LoggingConfig) (*zap.Logger, error) {
	var zapCfg zap.Config

	switch cfg.Format {
	case "console":
		zapCfg = zap.NewDevelopmentConfig()
	default:
		zapCfg = zap.NewProductionConfig()
	}

	// Parse log level.
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	zapCfg.Level.SetLevel(level)

	return zapCfg.Build()
}
