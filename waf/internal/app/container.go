package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/clickhouse"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/postgres"
	"github.com/koreanboi13/traffic_analysis/waf/internal/adapter/rulesfile"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/admin"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/metrics"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy"
	"github.com/koreanboi13/traffic_analysis/waf/internal/eventwriter"
	useadmin "github.com/koreanboi13/traffic_analysis/waf/internal/usecase/admin"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/detection"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/bcrypt"
)

// Container holds all application dependencies as lazy singletons
type Container struct {
	cfg *config.Config

	// Components with their sync.Once and errors
	logger         *zap.Logger
	loggerOnce     sync.Once
	loggerErr      error

	clickHouse     *clickhouse.Storage
	clickHouseOnce sync.Once
	clickHouseErr  error

	eventWriter    *eventwriter.Writer
	eventWriterOnce sync.Once
	eventWriterErr  error

	postgresDB     *postgres.DB
	postgresOnce   sync.Once
	postgresErr    error

	ruleRepo       *postgres.RuleRepository
	ruleRepoOnce   sync.Once
	ruleRepoErr    error

	userRepo       *postgres.UserRepository
	userRepoOnce   sync.Once
	userRepoErr    error

	ruleEngine     *detection.RuleEngine
	ruleEngineOnce sync.Once
	ruleEngineErr  error

	allowlist      *detection.Allowlist
	allowlistOnce  sync.Once
	allowlistErr   error

	reverseProxy   *httputil.ReverseProxy
	reverseProxyOnce sync.Once
	reverseProxyErr  error

	metrics        *metrics.Metrics
	metricsOnce    sync.Once
	metricsErr     error

	ruleService    *useadmin.RuleService
	ruleServiceOnce sync.Once
	ruleServiceErr  error

	authService    *useadmin.AuthService
	authServiceOnce sync.Once
	authServiceErr  error

	eventService   *useadmin.EventService
	eventServiceOnce sync.Once
	eventServiceErr  error

	// Routers (cached after first use)
	proxyRouter    http.Handler
	proxyRouterOnce sync.Once
	proxyRouterErr  error

	adminRouter    http.Handler
	adminRouterOnce sync.Once
	adminRouterErr  error
}

// NewContainer creates a new DI container with configuration
func NewContainer(cfg *config.Config) *Container {
	return &Container{
		cfg: cfg,
	}
}

// Logger returns zap logger (lazy initialization)
func (c *Container) Logger() (*zap.Logger, error) {
	c.loggerOnce.Do(func() {
		c.logger, c.loggerErr = c.setupLogger()
	})
	return c.logger, c.loggerErr
}

func (c *Container) setupLogger() (*zap.Logger, error) {
	var zapCfg zap.Config

	switch c.cfg.Logging.Format {
	case "console":
		zapCfg = zap.NewDevelopmentConfig()
	default:
		zapCfg = zap.NewProductionConfig()
	}

	level, err := zapcore.ParseLevel(c.cfg.Logging.Level)
	if err != nil {
		return nil, err
	}
	zapCfg.Level.SetLevel(level)

	return zapCfg.Build()
}

// ClickHouseStorage returns ClickHouse storage adapter
func (c *Container) ClickHouseStorage() (*clickhouse.Storage, error) {
	c.clickHouseOnce.Do(func() {
		logger, err := c.Logger()
		if err != nil {
			c.clickHouseErr = fmt.Errorf("failed to get logger for ClickHouse: %w", err)
			return
		}

		c.clickHouse, c.clickHouseErr = clickhouse.NewStorage(
			c.cfg.ClickHouse.Addr,
			c.cfg.ClickHouse.Database,
			logger,
		)
	})
	return c.clickHouse, c.clickHouseErr
}

// EventWriter returns batched event writer
func (c *Container) EventWriter() (*eventwriter.Writer, error) {
	c.eventWriterOnce.Do(func() {
		chStorage, err := c.ClickHouseStorage()
		if err != nil {
			c.eventWriterErr = fmt.Errorf("failed to get ClickHouse storage: %w", err)
			return
		}

		logger, err := c.Logger()
		if err != nil {
			c.eventWriterErr = fmt.Errorf("failed to get logger: %w", err)
			return
		}

		c.eventWriter = eventwriter.NewWriter(
			chStorage,
			c.cfg.ClickHouse.BatchSize,
			c.cfg.ClickHouse.FlushInterval,
			logger,
		)
		c.eventWriter.Start()
	})
	return c.eventWriter, c.eventWriterErr
}

// PostgresDB returns PostgreSQL connection
func (c *Container) PostgresDB() (*postgres.DB, error) {
	c.postgresOnce.Do(func() {
		logger, err := c.Logger()
		if err != nil {
			c.postgresErr = fmt.Errorf("failed to get logger for PostgreSQL: %w", err)
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c.postgresDB, c.postgresErr = postgres.NewDB(ctx, c.cfg.Postgres.DSN(), logger)
	})
	return c.postgresDB, c.postgresErr
}

// RuleRepository returns rule repository
func (c *Container) RuleRepository() (*postgres.RuleRepository, error) {
	c.ruleRepoOnce.Do(func() {
		db, err := c.PostgresDB()
		if err != nil {
			c.ruleRepoErr = fmt.Errorf("failed to get PostgreSQL DB: %w", err)
			return
		}
		c.ruleRepo = postgres.NewRuleRepository(db)
	})
	return c.ruleRepo, c.ruleRepoErr
}

// UserRepository returns user repository
func (c *Container) UserRepository() (*postgres.UserRepository, error) {
	c.userRepoOnce.Do(func() {
		db, err := c.PostgresDB()
		if err != nil {
			c.userRepoErr = fmt.Errorf("failed to get PostgreSQL DB: %w", err)
			return
		}
		c.userRepo = postgres.NewUserRepository(db)
	})
	return c.userRepo, c.userRepoErr
}

// RuleEngine returns detection rule engine
func (c *Container) RuleEngine() (*detection.RuleEngine, error) {
	c.ruleEngineOnce.Do(func() {
		ruleRepo, err := c.RuleRepository()
		if err != nil {
			c.ruleEngineErr = fmt.Errorf("failed to get rule repository: %w", err)
			return
		}

		ctx := context.Background()
		rules, err := ruleRepo.ListRules(ctx)
		if err != nil {
			c.ruleEngineErr = fmt.Errorf("failed to list rules: %w", err)
			return
		}

		c.ruleEngine, c.ruleEngineErr = detection.NewRuleEngine(
			rules,
			c.cfg.Detection.BlockThreshold,
			c.cfg.Detection.LogThreshold,
		)
	})
	return c.ruleEngine, c.ruleEngineErr
}

// Allowlist returns allowlist from config
func (c *Container) Allowlist() (*detection.Allowlist, error) {
	c.allowlistOnce.Do(func() {
		entries := make([]detection.AllowlistEntry, len(c.cfg.Detection.Allowlist))
		for i, e := range c.cfg.Detection.Allowlist {
			entries[i] = detection.AllowlistEntry{
				Comment:    e.Comment,
				IPs:        e.IPs,
				Paths:      e.Paths,
				Headers:    e.Headers,
				UserAgents: e.UserAgents,
				Params:     e.Params,
				RuleIDs:    e.RuleIDs,
			}
		}

		c.allowlist, c.allowlistErr = detection.NewAllowlist(entries)
	})
	return c.allowlist, c.allowlistErr
}

// ReverseProxy returns reverse proxy
func (c *Container) ReverseProxy() (*httputil.ReverseProxy, error) {
	c.reverseProxyOnce.Do(func() {
		logger, err := c.Logger()
		if err != nil {
			c.reverseProxyErr = fmt.Errorf("failed to get logger: %w", err)
			return
		}

		c.reverseProxy, c.reverseProxyErr = proxy.NewProxy(c.cfg.Proxy.BackendURL, logger)
	})
	return c.reverseProxy, c.reverseProxyErr
}

// Metrics returns Prometheus metrics
func (c *Container) Metrics() (*metrics.Metrics, error) {
	c.metricsOnce.Do(func() {
		c.metrics = metrics.NewMetrics()
	})
	return c.metrics, c.metricsErr
}

// RuleService returns admin rule service
func (c *Container) RuleService() (*useadmin.RuleService, error) {
	c.ruleServiceOnce.Do(func() {
		ruleRepo, err := c.RuleRepository()
		if err != nil {
			c.ruleServiceErr = fmt.Errorf("failed to get rule repository: %w", err)
			return
		}

		ruleEngine, err := c.RuleEngine()
		if err != nil {
			c.ruleServiceErr = fmt.Errorf("failed to get rule engine: %w", err)
			return
		}

		c.ruleService = useadmin.NewRuleService(ruleRepo, ruleEngine)
	})
	return c.ruleService, c.ruleServiceErr
}

// AuthService returns admin auth service
func (c *Container) AuthService() (*useadmin.AuthService, error) {
	c.authServiceOnce.Do(func() {
		userRepo, err := c.UserRepository()
		if err != nil {
			c.authServiceErr = fmt.Errorf("failed to get user repository: %w", err)
			return
		}

		c.authService = useadmin.NewAuthService(
			userRepo,
			[]byte(c.cfg.Auth.JWTSecret),
			c.cfg.Auth.TokenTTL,
		)
	})
	return c.authService, c.authServiceErr
}

// EventService returns admin event service
func (c *Container) EventService() (*useadmin.EventService, error) {
	c.eventServiceOnce.Do(func() {
		chStorage, err := c.ClickHouseStorage()
		if err != nil {
			c.eventServiceErr = fmt.Errorf("failed to get ClickHouse storage: %w", err)
			return
		}
		c.eventService = useadmin.NewEventService(chStorage)
	})
	return c.eventService, c.eventServiceErr
}

// ProxyRouter returns configured proxy router
func (c *Container) ProxyRouter() (http.Handler, error) {
	c.proxyRouterOnce.Do(func() {
		reverseProxy, err := c.ReverseProxy()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get reverse proxy: %w", err)
			return
		}

		ruleEngine, err := c.RuleEngine()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get rule engine: %w", err)
			return
		}

		allowlist, err := c.Allowlist()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get allowlist: %w", err)
			return
		}

		eventWriter, err := c.EventWriter()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get event writer: %w", err)
			return
		}

		metrics, err := c.Metrics()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get metrics: %w", err)
			return
		}

		logger, err := c.Logger()
		if err != nil {
			c.proxyRouterErr = fmt.Errorf("failed to get logger: %w", err)
			return
		}

		c.proxyRouter = proxy.NewRouter(proxy.RouterConfig{
			MaxBodySize:      c.cfg.Analysis.MaxBodySize,
			MaxDecodePasses:  c.cfg.Analysis.MaxDecodePasses,
			DetectionEnabled: c.cfg.Detection.Enabled,
		}, reverseProxy, ruleEngine, allowlist, eventWriter, metrics, logger)
	})
	return c.proxyRouter, c.proxyRouterErr
}

// AdminRouter returns configured admin router
func (c *Container) AdminRouter() (http.Handler, error) {
	c.adminRouterOnce.Do(func() {
		ruleService, err := c.RuleService()
		if err != nil {
			c.adminRouterErr = fmt.Errorf("failed to get rule service: %w", err)
			return
		}

		authService, err := c.AuthService()
		if err != nil {
			c.adminRouterErr = fmt.Errorf("failed to get auth service: %w", err)
			return
		}

		eventService, err := c.EventService()
		if err != nil {
			c.adminRouterErr = fmt.Errorf("failed to get event service: %w", err)
			return
		}

		logger, err := c.Logger()
		if err != nil {
			c.adminRouterErr = fmt.Errorf("failed to get logger: %w", err)
			return
		}

		c.adminRouter = admin.NewRouter(
			ruleService,
			authService,
			eventService,
			[]byte(c.cfg.Auth.JWTSecret),
			nil,
			logger,
		)
	})
	return c.adminRouter, c.adminRouterErr
}

// SeedDefaults seeds default admin user and rules if needed
func (c *Container) SeedDefaults(ctx context.Context) error {
	// Seed admin user
	userRepo, err := c.UserRepository()
	if err != nil {
		return fmt.Errorf("failed to get user repository: %w", err)
	}

	existingAdmin, _ := userRepo.GetUserByUsername(ctx, "admin")
	if existingAdmin == nil {
		hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to hash default admin password: %w", err)
		}
		if _, err := userRepo.CreateUser(ctx, "admin", string(hash), "admin"); err != nil {
			return fmt.Errorf("failed to seed admin user: %w", err)
		}
		logger, _ := c.Logger()
		logger.Info("default admin user created",
			zap.String("username", "admin"),
			zap.String("note", "change default password immediately"))
	}

	// Seed rules from YAML if empty
	ruleRepo, err := c.RuleRepository()
	if err != nil {
		return fmt.Errorf("failed to get rule repository: %w", err)
	}

	rules, err := ruleRepo.ListRules(ctx)
	if err != nil {
		return fmt.Errorf("failed to list rules: %w", err)
	}

	if len(rules) == 0 {
		loader := rulesfile.NewLoader()
		yamlRules, err := loader.Load(c.cfg.Detection.RulesFile)
		if err != nil {
			return fmt.Errorf("failed to load rules YAML: %w", err)
		}

		for _, r := range yamlRules {
			if _, err := ruleRepo.CreateRule(ctx, r); err != nil {
				logger, _ := c.Logger()
				logger.Error("failed to seed rule", zap.String("rule_id", r.ID), zap.Error(err))
			}
		}

		logger, _ := c.Logger()
		logger.Info("rules seeded from YAML into PostgreSQL", zap.Int("count", len(yamlRules)))
	}

	return nil
}

// Close gracefully closes all resources in reverse order
func (c *Container) Close() error {
	// Check if event writer was initialized
	if c.eventWriter != nil {
		c.eventWriter.Stop()
	}

	// Check if PostgreSQL was initialized
	if c.postgresDB != nil {
		c.postgresDB.Close()
	}

	// Check if ClickHouse was initialized
	if c.clickHouse != nil {
		c.clickHouse.Close()
	}

	// Check if logger was initialized
	if c.logger != nil {
		c.logger.Sync()
	}

	return nil
}