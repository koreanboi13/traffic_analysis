package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// UserService defines the user operations needed by the user handlers.
type UserService interface {
	ListUsers(ctx context.Context) ([]domain.User, error)
	CreateUser(ctx context.Context, username, password, role string) (*domain.User, error)
	DeleteUser(ctx context.Context, id int) error
}

// UserResponse is the JSON representation of a user (no password hash).
type UserResponse struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateUserRequest is the request body for POST /api/users.
type CreateUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

func toUserResponse(u domain.User) UserResponse {
	return UserResponse{
		ID:        u.ID,
		Username:  u.Username,
		Role:      u.Role,
		CreatedAt: u.CreatedAt,
	}
}

// HandleListUsers returns an http.HandlerFunc that lists all users.
func HandleListUsers(svc UserService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := svc.ListUsers(r.Context())
		if err != nil {
			logger.Error("list users failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		resp := make([]UserResponse, len(users))
		for i, u := range users {
			resp[i] = toUserResponse(u)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// HandleCreateUser returns an http.HandlerFunc that creates a new user.
func HandleCreateUser(svc UserService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		var req CreateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Username == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, "username and password are required")
			return
		}

		if req.Role != "admin" && req.Role != "analyst" {
			writeError(w, http.StatusBadRequest, "role must be 'admin' or 'analyst'")
			return
		}

		if len(req.Password) < 6 {
			writeError(w, http.StatusBadRequest, "password must be at least 6 characters")
			return
		}

		user, err := svc.CreateUser(r.Context(), req.Username, req.Password, req.Role)
		if err != nil {
			if err.Error() == "user \""+req.Username+"\" already exists" {
				writeError(w, http.StatusConflict, "user already exists")
				return
			}
			logger.Error("create user failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		writeJSON(w, http.StatusCreated, toUserResponse(*user))
	}
}

// HandleDeleteUser returns an http.HandlerFunc that deletes a user by ID.
func HandleDeleteUser(svc UserService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		idStr := chi.URLParam(r, "id")
		id, err := strconv.Atoi(idStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user id")
			return
		}

		if err := svc.DeleteUser(r.Context(), id); err != nil {
			if err.Error() == "user not found" {
				writeError(w, http.StatusNotFound, "user not found")
				return
			}
			logger.Error("delete user failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
