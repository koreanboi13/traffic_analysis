package admin

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// ErrInvalidCredentials is an alias for domain.ErrInvalidCredentials kept for
// backward compatibility. Callers should prefer domain.ErrInvalidCredentials.
var ErrInvalidCredentials = domain.ErrInvalidCredentials

// jwtClaims holds JWT payload fields for panel sessions.
type jwtClaims struct {
	UserID   int    `json:"uid"`
	Username string `json:"sub"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// UserRepository defines the user lookup operations needed by AuthService.
type UserRepository interface {
	GetUserByUsername(ctx context.Context, username string) (*domain.User, error)
}

// AuthService handles admin panel authentication.
type AuthService struct {
	users     UserRepository
	jwtSecret []byte
	tokenTTL  time.Duration
}

// NewAuthService creates an AuthService with the given user repository and JWT settings.
func NewAuthService(users UserRepository, jwtSecret []byte, tokenTTL time.Duration) *AuthService {
	return &AuthService{
		users:     users,
		jwtSecret: jwtSecret,
		tokenTTL:  tokenTTL,
	}
}

// Login validates credentials and returns a signed JWT token string and its expiry Unix timestamp.
// Returns ErrInvalidCredentials when the username is not found or the password does not match.
func (s *AuthService) Login(ctx context.Context, username, password string) (token string, expiresAt int64, err error) {
	user, err := s.users.GetUserByUsername(ctx, username)
	if err != nil {
		return "", 0, err
	}
	if user == nil {
		return "", 0, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", 0, ErrInvalidCredentials
	}

	now := time.Now()
	expiry := now.Add(s.tokenTTL)
	claims := &jwtClaims{
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiry),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := t.SignedString(s.jwtSecret)
	if err != nil {
		return "", 0, err
	}

	return tokenString, expiry.Unix(), nil
}
