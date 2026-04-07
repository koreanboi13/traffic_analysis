package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// AuthService defines the authentication operations needed by the auth handler.
type AuthService interface {
	Login(ctx context.Context, username, password string) (token string, expiresAt int64, err error)
}

// LoginRequest is the request body for POST /api/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response for successful login.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
}

// HandleLogin returns an http.HandlerFunc that authenticates a user via
// username/password and issues a JWT token on success.
func HandleLogin(authService AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		token, expiresAt, err := authService.Login(r.Context(), req.Username, req.Password)
		if err != nil {
			if errors.Is(err, domain.ErrInvalidCredentials) {
				writeError(w, http.StatusUnauthorized, "invalid credentials")
				return
			}
			logger.Error("login failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		writeJSON(w, http.StatusOK, LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		})
	}
}
