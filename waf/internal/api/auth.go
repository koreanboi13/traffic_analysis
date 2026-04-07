package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/api/middleware"
	"github.com/koreanboi13/traffic_analysis/waf/internal/postgres"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// HandleLogin returns an http.HandlerFunc that authenticates a user via
// username/password and issues a JWT token on success.
// Uses bcrypt.CompareHashAndPassword for timing-safe comparison (T-05-05).
func HandleLogin(db *postgres.DB, secret []byte, ttl time.Duration, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		user, err := db.GetUserByUsername(r.Context(), req.Username)
		if err != nil {
			logger.Error("failed to get user", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if user == nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		now := time.Now()
		claims := &middleware.Claims{
			UserID:   user.ID,
			Username: user.Username,
			Role:     user.Role,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
				IssuedAt:  jwt.NewNumericDate(now),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(secret)
		if err != nil {
			logger.Error("failed to sign JWT", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(LoginResponse{
			Token:     tokenString,
			ExpiresAt: claims.ExpiresAt.Unix(),
		})
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}
