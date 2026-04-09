package handler

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

// RuleService defines the rule operations needed by the rule handlers.
type RuleService interface {
	ListRules(ctx context.Context) ([]domain.Rule, error)
	GetRule(ctx context.Context, id string) (*domain.Rule, error)
	CreateRule(ctx context.Context, rule domain.Rule) (*domain.Rule, error)
	UpdateRule(ctx context.Context, id string, rule domain.Rule) (*domain.Rule, error)
	DeleteRule(ctx context.Context, id string) error
}

// RuleRequest is the request body for creating/updating a rule.
type RuleRequest struct {
	RuleID    string   `json:"rule_id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Category  string   `json:"category"`
	Pattern   string   `json:"pattern,omitempty"`
	Heuristic string   `json:"heuristic,omitempty"`
	Threshold float64  `json:"threshold,omitempty"`
	Targets   []string `json:"targets"`
	Weight    float32  `json:"weight"`
	Enabled   bool     `json:"enabled"`
	LogOnly   bool     `json:"log_only"`
}

// HandleListRules returns an http.HandlerFunc that lists all rules.
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

		writeJSON(w, http.StatusOK, rules)
	}
}

// HandleGetRule returns an http.HandlerFunc that retrieves a single rule by ID.
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

		writeJSON(w, http.StatusOK, rule)
	}
}

// HandleCreateRule returns an http.HandlerFunc that creates a new rule.
func HandleCreateRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
			LogOnly:   req.LogOnly,
		}

		created, err := ruleService.CreateRule(r.Context(), rule)
		if err != nil {
			logger.Error("failed to create rule", zap.String("rule_id", req.RuleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		writeJSON(w, http.StatusCreated, created)
	}
}

// HandleUpdateRule returns an http.HandlerFunc that updates an existing rule by ID.
func HandleUpdateRule(ruleService RuleService, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
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
			LogOnly:   req.LogOnly,
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

		writeJSON(w, http.StatusOK, updated)
	}
}

// HandleDeleteRule returns an http.HandlerFunc that deletes a rule by ID.
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
