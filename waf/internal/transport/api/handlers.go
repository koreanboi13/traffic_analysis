package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// RuleService defines the rule operations needed by the API handlers.
type RuleService interface {
	ListRules(ctx context.Context) ([]domain.Rule, error)
	GetRule(ctx context.Context, id string) (*domain.Rule, error)
	CreateRule(ctx context.Context, rule domain.Rule) (*domain.Rule, error)
	UpdateRule(ctx context.Context, id string, rule domain.Rule) (*domain.Rule, error)
	DeleteRule(ctx context.Context, id string) error
}

// AuthService defines the authentication operations needed by the API handlers.
type AuthService interface {
	Login(ctx context.Context, username, password string) (token string, expiresAt int64, err error)
}

// EventService defines the event query operations needed by the API handlers.
type EventService interface {
	ListEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, int64, error)
	ExportEvents(ctx context.Context, filter domain.EventFilter) ([]domain.Event, error)
}

// HandleLogin returns an http.HandlerFunc that authenticates a user via
// username/password and issues a JWT token on success.
func HandleLogin(authService AuthService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
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

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(LoginResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		})
	}
}

// HandleListRules returns an http.HandlerFunc that lists all rules.
// GET /api/rules
func HandleListRules(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := ruleService.ListRules(r.Context())
		if err != nil {
			logger.Error("failed to list rules", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if rules == nil {
			rules = []domain.Rule{}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rules)
	}
}

// HandleGetRule returns an http.HandlerFunc that retrieves a single rule by ID.
// GET /api/rules/{id}
func HandleGetRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		rule, err := ruleService.GetRule(r.Context(), ruleID)
		if err != nil {
			logger.Error("failed to get rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if rule == nil {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rule)
	}
}

// HandleCreateRule returns an http.HandlerFunc that creates a new rule.
// After successful creation, the service reloads the detector.
// POST /api/rules — returns 201 Created.
func HandleCreateRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
		var req RuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.RuleID == "" || req.Name == "" || req.Type == "" || req.Category == "" {
			writeError(w, http.StatusBadRequest, "rule_id, name, type, and category are required")
			return
		}
		if req.Weight <= 0 {
			writeError(w, http.StatusBadRequest, "weight must be greater than 0")
			return
		}

		rule := domain.Rule{
			ID:        req.RuleID,
			Name:      req.Name,
			Type:      req.Type,
			Category:  req.Category,
			Pattern:   req.Pattern,
			Heuristic: req.Heuristic,
			Threshold: req.Threshold,
			Targets:   req.Targets,
			Weight:    req.Weight,
			Enabled:   req.Enabled,
		}

		created, err := ruleService.CreateRule(r.Context(), rule)
		if err != nil {
			logger.Error("failed to create rule", zap.String("rule_id", req.RuleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(created)
	}
}

// HandleUpdateRule returns an http.HandlerFunc that updates an existing rule by ID.
// After successful update, the service reloads the detector.
// PUT /api/rules/{id} — returns 200 OK or 404 if not found.
func HandleUpdateRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
		var req RuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		if req.Name == "" || req.Type == "" || req.Category == "" {
			writeError(w, http.StatusBadRequest, "name, type, and category are required")
			return
		}
		if req.Weight <= 0 {
			writeError(w, http.StatusBadRequest, "weight must be greater than 0")
			return
		}

		rule := domain.Rule{
			ID:        ruleID,
			Name:      req.Name,
			Type:      req.Type,
			Category:  req.Category,
			Pattern:   req.Pattern,
			Heuristic: req.Heuristic,
			Threshold: req.Threshold,
			Targets:   req.Targets,
			Weight:    req.Weight,
			Enabled:   req.Enabled,
		}

		updated, err := ruleService.UpdateRule(r.Context(), ruleID, rule)
		if err != nil {
			logger.Error("failed to update rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if updated == nil {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(updated)
	}
}

// HandleDeleteRule returns an http.HandlerFunc that deletes a rule by ID.
// After successful deletion, the service reloads the detector.
// DELETE /api/rules/{id} — returns 204 No Content or 404 if not found.
func HandleDeleteRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		err := ruleService.DeleteRule(r.Context(), ruleID)
		if err != nil {
			logger.Error("failed to delete rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// HandleListEvents returns a handler for GET /api/events with query-param filtering.
func HandleListEvents(eventService EventService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		limit := 20
		if v := q.Get("limit"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		if limit > 100 {
			limit = 100
		}

		offset := 0
		if v := q.Get("offset"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
				offset = parsed
			}
		}

		f := domain.EventFilter{
			IP:      q.Get("ip"),
			Verdict: q.Get("verdict"),
			RuleID:  q.Get("rule_id"),
			Limit:   limit,
			Offset:  offset,
		}

		if v := q.Get("from"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ms := t.UnixMilli()
				f.From = &ms
			}
		}
		if v := q.Get("to"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				ms := t.UnixMilli()
				f.To = &ms
			}
		}

		events, total, err := eventService.ListEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to query events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []domain.Event{}
		}

		resp := EventsListResponse{
			Data:   events,
			Total:  total,
			Offset: offset,
			Limit:  limit,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// HandleExportEvents returns a handler for POST /api/events/export.
func HandleExportEvents(eventService EventService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
		var body ExportFilter
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}

		limit := body.Limit
		if limit <= 0 || limit > 10000 {
			limit = 10000
		}

		f := domain.EventFilter{
			IP:      body.IP,
			Verdict: body.Verdict,
			RuleID:  body.RuleID,
			Limit:   limit,
		}

		if body.From != nil {
			ms := body.From.UnixMilli()
			f.From = &ms
		}
		if body.To != nil {
			ms := body.To.UnixMilli()
			f.To = &ms
		}

		events, err := eventService.ExportEvents(r.Context(), f)
		if err != nil {
			logger.Error("failed to export events", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}

		if events == nil {
			events = []domain.Event{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(events)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{Error: msg})
}
