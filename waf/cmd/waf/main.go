package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/api"
	"github.com/koreanboi13/traffic_analysis/waf/internal/engine"
	"github.com/koreanboi13/traffic_analysis/waf/internal/events"
	eventsch "github.com/koreanboi13/traffic_analysis/waf/internal/events/clickhouse"
	"github.com/koreanboi13/traffic_analysis/waf/internal/metrics"
	wafmw "github.com/koreanboi13/traffic_analysis/waf/internal/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/internal/postgres"
	"github.com/koreanboi13/traffic_analysis/waf/internal/rules"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
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
	storage, err := eventsch.NewStorage(cfg.ClickHouse.Addr, cfg.ClickHouse.Database, logger)
	if err != nil {
		logger.Fatal("failed to connect to clickhouse", zap.Error(err))
	}
	defer storage.Close()

	writer := events.NewWriter(storage, cfg.ClickHouse.BatchSize, cfg.ClickHouse.FlushInterval, logger)
	writer.Start()
	defer writer.Stop()

	// 5. Connect to PostgreSQL.
	pgCtx, pgCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pgCancel()

	pgDB, err := postgres.NewDB(pgCtx, cfg.Postgres.DSN(), logger)
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer pgDB.Close()

	// 6. Seed default admin user if none exists.
	seedCtx := context.Background()
	existingAdmin, _ := pgDB.GetUserByUsername(seedCtx, "admin")
	if existingAdmin == nil {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			logger.Fatal("failed to hash default admin password", zap.Error(err))
		}
		if _, err := pgDB.CreateUser(seedCtx, "admin", string(hash), "admin"); err != nil {
			logger.Error("failed to seed default admin user", zap.Error(err))
		} else {
			logger.Info("default admin user created",
				zap.String("username", "admin"),
				zap.String("note", "change default password immediately"))
		}
	}

	// 7. Seed rules from YAML into PostgreSQL on first startup.
	dbRules, err := pgDB.ListRules(seedCtx)
	if err != nil {
		logger.Fatal("failed to list rules from postgres", zap.Error(err))
	}
	if len(dbRules) == 0 {
		yamlRules, err := rules.LoadFromFile(cfg.Detection.RulesFile)
		if err != nil {
			logger.Fatal("failed to load rules YAML for seeding", zap.Error(err))
		}
		for _, r := range yamlRules {
			if _, err := pgDB.CreateRule(seedCtx, r); err != nil {
				logger.Error("failed to seed rule", zap.String("rule_id", r.ID), zap.Error(err))
			}
		}
		logger.Info("rules seeded from YAML into PostgreSQL", zap.Int("count", len(yamlRules)))

		// Re-read rules from DB after seeding.
		dbRules, err = pgDB.ListRules(seedCtx)
		if err != nil {
			logger.Fatal("failed to list rules after seeding", zap.Error(err))
		}
	}

	// 8. Load allowlist from config.
	allowlistEntries := make([]wafmw.AllowlistEntry, len(cfg.Detection.Allowlist))
	for i, e := range cfg.Detection.Allowlist {
		allowlistEntries[i] = wafmw.AllowlistEntry{
			Comment:    e.Comment,
			IPs:        e.IPs,
			Paths:      e.Paths,
			Headers:    e.Headers,
			UserAgents: e.UserAgents,
			Params:     e.Params,
			RuleIDs:    e.RuleIDs,
		}
	}
	allowlist, err := wafmw.NewAllowlist(allowlistEntries)
	if err != nil {
		logger.Fatal("failed to init allowlist", zap.Error(err))
	}

	// 9. Initialize RuleEngine from PostgreSQL (source-of-truth).
	engineRules := make([]rules.Rule, len(dbRules))
	for i, r := range dbRules {
		engineRules[i] = r.ToRule()
	}

	ruleEngine, err := rules.NewRuleEngine(engineRules, cfg.Detection)
	if err != nil {
		logger.Fatal("failed to init rule engine", zap.Error(err))
	}
	logger.Info("rule engine initialized from PostgreSQL", zap.Int("count", len(engineRules)))

	// 10. Create reverse proxy.
	proxy, err := engine.NewProxy(cfg.Proxy.BackendURL, logger)
	if err != nil {
		logger.Fatal("failed to create proxy", zap.Error(err))
	}

	// 11. Create Prometheus metrics.
	m := metrics.NewMetrics()

	// 12. Setup chi router for proxy.
	r := chi.NewRouter()
	r.Use(chimw.RequestID)

	// healthz before WAF middleware -- no analysis on healthchecks.
	r.Get("/healthz", engine.HealthHandler())

	// WAF middleware group: Metrics -> Parse -> Normalize -> RecordEvent -> Detect -> Proxy
	r.Group(func(r chi.Router) {
		r.Use(metrics.Instrument(m))
		r.Use(wafmw.Parse(cfg.Analysis.MaxBodySize))
		r.Use(wafmw.Normalize(cfg.Analysis.MaxDecodePasses, logger))

		recordEvent := wafmw.NewRecordEvent(writer, logger)
		r.Use(recordEvent.Handler)

		detect := wafmw.NewDetect(ruleEngine, allowlist, cfg.Detection.Enabled, logger)
		r.Use(detect.Handler)

		r.Handle("/*", proxy)
	})

	// 13. Create admin API server.
	adminSrv := api.NewServer(*cfg, pgDB, storage, ruleEngine, logger)

	// 14. Create metrics HTTP server.
	metricsSrv := metrics.NewMetricsServer(cfg.Metrics.ListenAddr, m)

	// 15. Start three servers with graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyServer := &http.Server{Addr: cfg.Proxy.ListenAddr, Handler: r}

	adminServer := &http.Server{Addr: cfg.AdminAPI.ListenAddr, Handler: adminSrv.Router}

	go func() {
		logger.Info("proxy listening", zap.String("addr", cfg.Proxy.ListenAddr))
		if err := proxyServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("proxy server failed", zap.Error(err))
			stop()
		}
	}()

	go func() {
		logger.Info("admin api listening", zap.String("addr", cfg.AdminAPI.ListenAddr))
		if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("admin server failed", zap.Error(err))
			stop()
		}
	}()

	go func() {
		logger.Info("metrics listening", zap.String("addr", cfg.Metrics.ListenAddr))
		if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", zap.Error(err))
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down servers")

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := proxyServer.Shutdown(shutCtx); err != nil {
		logger.Error("proxy shutdown error", zap.Error(err))
	}
	if err := adminServer.Shutdown(shutCtx); err != nil {
		logger.Error("admin shutdown error", zap.Error(err))
	}
	if err := metricsSrv.Shutdown(shutCtx); err != nil {
		logger.Error("metrics shutdown error", zap.Error(err))
	}

	logger.Info("all servers stopped")
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
