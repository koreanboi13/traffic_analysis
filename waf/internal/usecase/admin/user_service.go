package admin

import (
	"context"
	"fmt"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// UserRepo defines the user operations needed by UserService.
type UserRepo interface {
	ListUsers(ctx context.Context) ([]domain.User, error)
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
	CreateUser(ctx context.Context, username, passwordHash, role string) (*domain.User, error)
	DeleteUser(ctx context.Context, id int) (bool, error)
}

// UserService handles user management for the admin panel.
type UserService struct {
	users UserRepo
}

// NewUserService creates a UserService.
func NewUserService(users UserRepo) *UserService {
	return &UserService{users: users}
}

// ListUsers returns all users.
func (s *UserService) ListUsers(ctx context.Context) ([]domain.User, error) {
	return s.users.ListUsers(ctx)
}

// CreateUser creates a new user with the given credentials and role.
func (s *UserService) CreateUser(ctx context.Context, username, password, role string) (*domain.User, error) {
	existing, err := s.users.GetUserByUsername(ctx, username)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, fmt.Errorf("user %q already exists", username)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	return s.users.CreateUser(ctx, username, string(hash), role)
}

// DeleteUser deletes a user by ID. Returns error if user not found.
func (s *UserService) DeleteUser(ctx context.Context, id int) error {
	deleted, err := s.users.DeleteUser(ctx, id)
	if err != nil {
		return err
	}
	if !deleted {
		return fmt.Errorf("user not found")
	}
	return nil
}
