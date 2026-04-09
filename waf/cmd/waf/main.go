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

	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app"
	"github.com/koreanboi13/traffic_analysis/waf/internal/app/metrics"
	"go.uber.org/zap"
)

func main() {
	// 1. Load configuration
	configPath := os.Getenv("WAF_CONFIG_PATH")
	if configPath == "" {
		configPath = "config.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 2. Create DI container
	container := app.NewContainer(cfg)

	// 3. Get logger for startup messages
	logger, err := container.Logger()
	if err != nil {
		log.Fatalf("failed to get logger: %v", err)
	}
	defer container.Close()

	// 4. Seed defaults (admin user, rules)
	seedCtx := context.Background()
	if err := container.SeedDefaults(seedCtx); err != nil {
		logger.Error("seed failed", zap.Error(err))
		// Continue even if seed fails - maybe rules already exist
	}

	// 5. Get routers
	proxyRouter, err := container.ProxyRouter()
	if err != nil {
		logger.Fatal("failed to create proxy router", zap.Error(err))
	}

	adminRouter, err := container.AdminRouter()
	if err != nil {
		logger.Fatal("failed to create admin router", zap.Error(err))
	}

	// 6. Get metrics server
	m, err := container.Metrics()
	if err != nil {
		logger.Fatal("failed to get metrics", zap.Error(err))
	}
	metricsSrv := metrics.NewServer(cfg.Metrics.ListenAddr, m)

	// 7. Start servers with graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxyServer := &http.Server{Addr: cfg.Proxy.ListenAddr, Handler: proxyRouter}
	adminServer := &http.Server{Addr: cfg.AdminAPI.ListenAddr, Handler: adminRouter}

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