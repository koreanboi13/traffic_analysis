package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// DB wraps a pgxpool.Pool and provides auto-migration on startup.
type DB struct {
	Pool   *pgxpool.Pool
	logger *zap.Logger
}

// NewDB creates a new DB, connects to PostgreSQL, pings, and runs auto-migration.
func NewDB(ctx context.Context, dsn string, logger *zap.Logger) (*DB, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("pgxpool.New: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pgx ping: %w", err)
	}
	db := &DB{Pool: pool, logger: logger}
	if err := db.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	logger.Info("postgres storage ready")
	return db, nil
}

// Close releases the connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}

// migrate creates users and rules tables if they do not exist.
func (db *DB) migrate(ctx context.Context) error {
	_, err := db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id         SERIAL PRIMARY KEY,
			username   VARCHAR(64) UNIQUE NOT NULL,
			password   VARCHAR(255) NOT NULL,
			role       VARCHAR(16) NOT NULL DEFAULT 'analyst',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create users table: %w", err)
	}

	_, err = db.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS rules (
			id         SERIAL PRIMARY KEY,
			rule_id    VARCHAR(64) UNIQUE NOT NULL,
			name       VARCHAR(255) NOT NULL,
			type       VARCHAR(32) NOT NULL,
			category   VARCHAR(32) NOT NULL,
			pattern    TEXT,
			heuristic  VARCHAR(64),
			threshold  DOUBLE PRECISION DEFAULT 0,
			targets    TEXT[] DEFAULT '{}',
			weight     REAL NOT NULL DEFAULT 1.0,
			enabled    BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("create rules table: %w", err)
	}

	return nil
}
