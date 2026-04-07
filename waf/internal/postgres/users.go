package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// User represents a row in the users table.
type User struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"-"`    // bcrypt hash, never serialized
	Role      string    `json:"role"` // "admin" | "analyst"
	CreatedAt time.Time `json:"created_at"`
}

// GetUserByUsername returns a user by username, or (nil, nil) if not found.
func (db *DB) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`SELECT id, username, password, role, created_at FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user with a pre-hashed password and returns the created user.
func (db *DB) CreateUser(ctx context.Context, username, passwordHash, role string) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role, created_at`,
		username, passwordHash, role,
	).Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}
