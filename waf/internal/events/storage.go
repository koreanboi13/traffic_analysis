package events

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"go.uber.org/zap"
)

// Storage manages ClickHouse connection and event persistence.
type Storage struct {
	conn   clickhouse.Conn
	logger *zap.Logger
}

// NewStorage connects to ClickHouse via the native protocol and runs auto-migration.
func NewStorage(addr, database string, logger *zap.Logger) (*Storage, error) {
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Username: "default",
			Password: "",
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout:     5 * time.Second,
		ConnMaxLifetime: time.Hour,
	})
	if err != nil {
		return nil, fmt.Errorf("clickhouse open: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("clickhouse ping: %w", err)
	}

	s := &Storage{
		conn:   conn,
		logger: logger,
	}

	if err := s.migrate(ctx, database); err != nil {
		return nil, fmt.Errorf("clickhouse migrate: %w", err)
	}

	logger.Info("clickhouse storage ready", zap.String("addr", addr), zap.String("database", database))
	return s, nil
}

// migrate creates the database and waf_events table if they do not exist.
func (s *Storage) migrate(ctx context.Context, database string) error {
	createDB := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", database)
	if err := s.conn.Exec(ctx, createDB); err != nil {
		return fmt.Errorf("create database: %w", err)
	}

	createTable := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s.waf_events (
			event_id     UUID,
			timestamp    DateTime64(3),
			request_id   String,
			client_ip    String,
			host         String,
			method       String,
			path         String,
			verdict      Enum8('allow'=1, 'block'=2, 'log_only'=3),
			status_code  UInt16,
			latency_ms   Float32
		) ENGINE = MergeTree
		PARTITION BY toYYYYMMDD(timestamp)
		ORDER BY (timestamp, host, client_ip)
		TTL timestamp + INTERVAL 90 DAY
	`, database)
	if err := s.conn.Exec(ctx, createTable); err != nil {
		return fmt.Errorf("create table waf_events: %w", err)
	}

	return nil
}

// Close closes the ClickHouse connection.
func (s *Storage) Close() error {
	return s.conn.Close()
}

// Ping checks the ClickHouse connection health.
func (s *Storage) Ping(ctx context.Context) error {
	return s.conn.Ping(ctx)
}
