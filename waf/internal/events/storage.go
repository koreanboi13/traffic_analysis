package events

import (
	"context"
	"fmt"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"go.uber.org/zap"
)

// Storage manages ClickHouse connection and event persistence.
type Storage struct {
	conn     clickhouse.Conn
	logger   *zap.Logger
	database string
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
		conn:     conn,
		logger:   logger,
		database: database,
	}

	if err := s.migrate(ctx, database); err != nil {
		return nil, fmt.Errorf("clickhouse migrate: %w", err)
	}

	if err := s.migrateNewColumns(ctx, database); err != nil {
		return nil, fmt.Errorf("clickhouse migrate new columns: %w", err)
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

// migrateNewColumns adds new columns to the waf_events table if they don't exist.
// Each column is added with its own ALTER TABLE statement because ClickHouse
// doesn't support multiple ADD COLUMN in one ALTER.
func (s *Storage) migrateNewColumns(ctx context.Context, database string) error {
	columns := []struct {
		name     string
		typ      string
		modifier string // DEFAULT, etc.
	}{
		{"raw_query", "String", ""},
		{"normalized_query", "String", ""},
		{"raw_body", "String", ""},
		{"normalized_body", "String", ""},
		{"query_params", "String", ""},
		{"body_params", "String", ""},
		{"headers", "String", ""},
		{"user_agent", "String", ""},
		{"content_type", "LowCardinality(String)", ""},
		{"referer", "String", ""},
		{"cookies", "String", ""},
		{"body_truncated", "UInt8", ""},
		{"body_size", "UInt32", ""},
		{"rule_ids", "Array(String)", ""},
		{"score", "Float32", "DEFAULT 0"},
	}

	for _, col := range columns {
		alterQuery := fmt.Sprintf("ALTER TABLE %s.waf_events ADD COLUMN IF NOT EXISTS %s %s",
			database, col.name, col.typ)
		
		if col.modifier != "" {
			alterQuery += " " + col.modifier
		}
		
		if err := s.conn.Exec(ctx, alterQuery); err != nil {
			// Логируем ошибку, но продолжаем миграцию
			// Некоторые колонки могли уже существовать
			s.logger.Warn("failed to add column",
				zap.String("column", col.name),
				zap.Error(err),
			)
			// Не возвращаем ошибку, чтобы не блокировать запуск
			// Колонка может уже существовать
		}
	}

	s.logger.Info("new columns migration completed", zap.Int("columns_count", len(columns)))
	return nil
}

// InsertBatch inserts a batch of events into ClickHouse.
// The order of fields must match exactly the table schema:
// - First 10 fields: base fields (CREATE TABLE order)
// - Next 15 fields: new fields (ALTER TABLE order)
func (s *Storage) InsertBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	// Prepare batch for insertion
	batch, err := s.conn.PrepareBatch(ctx, fmt.Sprintf(`
		INSERT INTO %s.waf_events (
			event_id, timestamp, request_id, client_ip, host, method, path,
			verdict, status_code, latency_ms,
			raw_query, normalized_query, raw_body, normalized_body,
			query_params, body_params, headers, user_agent, content_type,
			referer, cookies, body_truncated, body_size, rule_ids, score
		) VALUES (
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?
		)
	`, s.database))
	if err != nil {
		return fmt.Errorf("prepare batch: %w", err)
	}

	// Append each event to the batch
	for _, event := range events {
		// Convert verdict string to the appropriate type
		// ClickHouse driver handles Enum8 conversion automatically from string
		
		// Convert bool to uint8 (0 or 1) for body_truncated
		bodyTruncated := event.BodyTruncated
		
		err := batch.Append(
			// Base fields (10 fields)
			event.EventID,
			time.UnixMilli(event.Timestamp),
			event.RequestID,
			event.ClientIP,
			event.Host,
			event.Method,
			event.Path,
			event.Verdict, // String -> Enum8('allow','block','log_only')
			event.StatusCode,
			event.LatencyMs,
			// New fields (15 fields)
			event.RawQuery,
			event.NormalizedQuery,
			event.RawBody,
			event.NormalizedBody,
			event.QueryParams,
			event.BodyParams,
			event.Headers,
			event.UserAgent,
			event.ContentType,
			event.Referer,
			event.Cookies,
			bodyTruncated,
			event.BodySize,
			event.TriggeredRulesIDs,
			event.RiskScore,
		)
		if err != nil {
			return fmt.Errorf("append event to batch: %w (event_id: %s)", err, event.EventID)
		}
	}

	// Send the batch to ClickHouse
	if err := batch.Send(); err != nil {
		return fmt.Errorf("send batch: %w", err)
	}

	s.logger.Debug("batch inserted successfully", zap.Int("batch_size", len(events)))
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

// Exec executes an arbitrary SQL query (for testing/admin purposes)
func (s *Storage) Exec(ctx context.Context, query string) error {
	return s.conn.Exec(ctx, query)
}

// Query executes a SELECT query and returns rows (for testing/admin purposes)
func (s *Storage) Query(ctx context.Context, query string) (driver.Rows, error) {
	return s.conn.Query(ctx, query)
}