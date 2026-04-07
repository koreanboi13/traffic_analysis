package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/clickhouse"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/postgres"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/rulesfile"
	"github.com/koreanboi13/traffic_analysis/waf/internal/eventwriter"
	"github.com/koreanboi13/traffic_analysis/waf/internal/transport/api"
	"github.com/koreanboi13/traffic_analysis/waf/internal/transport/metrics"
	"github.com/koreanboi13/traffic_analysis/waf/internal/transport/proxy"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/admin"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/detection"
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

	// 4. Connect to ClickHouse and create storage adapter.
	chStorage, err := clickhouse.NewStorage(cfg.ClickHouse.Addr, cfg.ClickHouse.Database, logger)
	if err != nil {
		logger.Fatal("failed to connect to clickhouse", zap.Error(err))
	}
	defer chStorage.Close()

	// 5. Create batched event writer backed by the ClickHouse EventWriter interface.
	ew := eventwriter.NewWriter(chStorage, cfg.ClickHouse.BatchSize, cfg.ClickHouse.FlushInterval, logger)
	ew.Start()
	defer ew.Stop()

	// 6. Connect to PostgreSQL.
	pgCtx, pgCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer pgCancel()

	pgDB, err := postgres.NewDB(pgCtx, cfg.Postgres.DSN(), logger)
	if err != nil {
		logger.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer pgDB.Close()

	// Wrap postgres.DB in its domain repository views.
	ruleRepo := postgres.NewRuleRepository(pgDB)
	userRepo := postgres.NewUserRepository(pgDB)

	// 7. Seed default admin user if none exists.
	seedCtx := context.Background()
	existingAdmin, _ := userRepo.GetUserByUsername(seedCtx, "admin")
	if existingAdmin == nil {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			logger.Fatal("failed to hash default admin password", zap.Error(err))
		}
		if _, err := userRepo.CreateUser(seedCtx, "admin", string(hash), "admin"); err != nil {
			logger.Error("failed to seed default admin user", zap.Error(err))
		} else {
			logger.Info("default admin user created",
				zap.String("username", "admin"),
				zap.String("note", "change default password immediately"))
		}
	}

	// 8. Seed rules from YAML into PostgreSQL on first startup.
	dbRules, err := ruleRepo.ListRules(seedCtx)
	if err != nil {
		logger.Fatal("failed to list rules from postgres", zap.Error(err))
	}
	if len(dbRules) == 0 {
		loader := rulesfile.NewLoader()
		yamlRules, err := loader.Load(cfg.Detection.RulesFile)
		if err != nil {
			logger.Fatal("failed to load rules YAML for seeding", zap.Error(err))
		}
		for _, r := range yamlRules {
			if _, err := ruleRepo.CreateRule(seedCtx, r); err != nil {
				logger.Error("failed to seed rule", zap.String("rule_id", r.ID), zap.Error(err))
			}
		}
		logger.Info("rules seeded from YAML into PostgreSQL", zap.Int("count", len(yamlRules)))

		// Re-read rules from DB after seeding.
		dbRules, err = ruleRepo.ListRules(seedCtx)
		if err != nil {
			logger.Fatal("failed to list rules after seeding", zap.Error(err))
		}
	}

	// 9. Load allowlist from config.
	allowlistEntries := make([]detection.AllowlistEntry, len(cfg.Detection.Allowlist))
	for i, e := range cfg.Detection.Allowlist {
		allowlistEntries[i] = detection.AllowlistEntry{
			Comment:    e.Comment,
			IPs:        e.IPs,
			Paths:      e.Paths,
			Headers:    e.Headers,
			UserAgents: e.UserAgents,
			Params:     e.Params,
			RuleIDs:    e.RuleIDs,
		}
	}
	allowlist, err := detection.NewAllowlist(allowlistEntries)
	if err != nil {
		logger.Fatal("failed to init allowlist", zap.Error(err))
	}

	// 10. Initialize RuleEngine from PostgreSQL (source-of-truth).
	ruleEngine, err := detection.NewRuleEngine(dbRules, cfg.Detection.BlockThreshold, cfg.Detection.LogThreshold)
	if err != nil {
		logger.Fatal("failed to init rule engine", zap.Error(err))
	}
	logger.Info("rule engine initialized from PostgreSQL", zap.Int("count", len(dbRules)))

	// 11. Create reverse proxy.
	reverseProxy, err := proxy.NewProxy(cfg.Proxy.BackendURL, logger)
	if err != nil {
		logger.Fatal("failed to create proxy", zap.Error(err))
	}

	// 12. Create Prometheus metrics.
	m := metrics.NewMetrics()

	// 13. Setup chi router for proxy server.
	r := chi.NewRouter()
	r.Use(chimw.RequestID)

	// Healthz: before WAF middleware — no analysis on health checks.
	r.Get("/healthz", proxy.HealthHandler())

	// WAF middleware group: Metrics -> Parse -> Normalize -> RecordEvent -> Detect -> Proxy
	r.Group(func(r chi.Router) {
		r.Use(metrics.Instrument(m))
		r.Use(proxy.Parse(cfg.Analysis.MaxBodySize))
		r.Use(proxy.Normalize(cfg.Analysis.MaxDecodePasses))

		recordEvent := proxy.NewRecordEvent(ew, logger)
		r.Use(recordEvent.Handler)

		detect := proxy.NewDetect(ruleEngine, allowlist, cfg.Detection.Enabled, logger)
		r.Use(detect.Handler)

		r.Handle("/*", reverseProxy)
	})

	// 14. Create admin API server.
	jwtSecret := []byte(cfg.Auth.JWTSecret)
	ruleService := admin.NewRuleService(ruleRepo, ruleEngine)
	authService := admin.NewAuthService(userRepo, jwtSecret, cfg.Auth.TokenTTL)
	eventService := admin.NewEventService(chStorage)

	adminSrv := api.NewServer(ruleService, authService, eventService, jwtSecret, nil, logger)

	// 15. Create metrics HTTP server.
	metricsSrv := metrics.NewMetricsServer(cfg.Metrics.ListenAddr, m)

	// 16. Start three servers with graceful shutdown.
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

	var wg sync.WaitGroup
	for _, srv := range []*http.Server{proxyServer, adminServer, metricsSrv} {
		wg.Add(1)
		go func(s *http.Server) {
			defer wg.Done()
			if err := s.Shutdown(shutCtx); err != nil {
				logger.Error("server shutdown error", zap.String("addr", s.Addr), zap.Error(err))
			}
		}(srv)
	}
	wg.Wait()

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

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, err
	}
	zapCfg.Level.SetLevel(level)

	return zapCfg.Build()
}
