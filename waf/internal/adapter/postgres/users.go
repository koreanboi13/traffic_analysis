package postgres

import (
	"context"
	"fmt"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// UserRepository implements admin.UserRepository using PostgreSQL.
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new UserRepository.
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// GetUserByUsername returns a user by username, or (nil, nil) if not found.
func (r *UserRepository) GetUserByUsername(ctx context.Context, username string) (*domain.User, error) {
	query, args, err := psql.
		Select("id", "username", "password", "role", "created_at").
		From("users").
		Where(sq.Eq{"username": username}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("get user build query: %w", err)
	}

	var u domain.User
	err = r.db.Pool.QueryRow(ctx, query, args...).
		Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user with a pre-hashed password and returns the created domain.User.
func (r *UserRepository) CreateUser(ctx context.Context, username, passwordHash, role string) (*domain.User, error) {
	query, args, err := psql.
		Insert("users").
		Columns("username", "password", "role").
		Values(username, passwordHash, role).
		Suffix("RETURNING id, username, role, created_at").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("create user build query: %w", err)
	}

	var u domain.User
	err = r.db.Pool.QueryRow(ctx, query, args...).
		Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	// password hash is not returned by the INSERT RETURNING, set it explicitly
	u.Password = passwordHash
	return &u, nil
}

// ListUsers returns all users ordered by creation date.
func (r *UserRepository) ListUsers(ctx context.Context) ([]domain.User, error) {
	query, args, err := psql.
		Select("id", "username", "role", "created_at").
		From("users").
		OrderBy("created_at ASC").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("list users build query: %w", err)
	}

	rows, err := r.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("list users scan: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// DeleteUser deletes a user by ID. Returns true if a row was deleted.
func (r *UserRepository) DeleteUser(ctx context.Context, id int) (bool, error) {
	query, args, err := psql.
		Delete("users").
		Where(sq.Eq{"id": id}).
		ToSql()
	if err != nil {
		return false, fmt.Errorf("delete user build query: %w", err)
	}

	tag, err := r.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return false, fmt.Errorf("delete user: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}
