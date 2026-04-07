package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/postgres"
	"github.com/koreanboi13/traffic_analysis/waf/internal/rules"
	"go.uber.org/zap"
)

// HandleListRules returns an http.HandlerFunc that lists all rules.
// GET /api/rules
func HandleListRules(db *postgres.DB, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := db.ListRules(r.Context())
		if err != nil {
			logger.Error("failed to list rules", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		if rows == nil {
			rows = []postgres.RuleRow{}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(rows)
	}
}

// HandleGetRule returns an http.HandlerFunc that retrieves a single rule by ID.
// GET /api/rules/{id}
func HandleGetRule(db *postgres.DB, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		row, err := db.GetRule(r.Context(), ruleID)
		if err != nil {
			logger.Error("failed to get rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if row == nil {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(row)
	}
}

// HandleCreateRule returns an http.HandlerFunc that creates a new rule.
// After successful creation, it reloads the RuleEngine with all rules from DB.
// POST /api/rules — returns 201 Created.
func HandleCreateRule(db *postgres.DB, engine *rules.RuleEngine, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		rule := rules.Rule{
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

		row, err := db.CreateRule(r.Context(), rule)
		if err != nil {
			logger.Error("failed to create rule", zap.String("rule_id", req.RuleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		reloadEngine(r.Context(), db, engine, logger)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(row)
	}
}

// HandleUpdateRule returns an http.HandlerFunc that updates an existing rule by ID.
// After successful update, it reloads the RuleEngine with all rules from DB.
// PUT /api/rules/{id} — returns 200 OK or 404 if not found.
func HandleUpdateRule(db *postgres.DB, engine *rules.RuleEngine, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		var req RuleRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		rule := rules.Rule{
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

		row, err := db.UpdateRule(r.Context(), ruleID, rule)
		if err != nil {
			logger.Error("failed to update rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		if row == nil {
			writeError(w, http.StatusNotFound, "rule not found")
			return
		}

		reloadEngine(r.Context(), db, engine, logger)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(row)
	}
}

// HandleDeleteRule returns an http.HandlerFunc that deletes a rule by ID.
// After successful deletion, it reloads the RuleEngine with all rules from DB.
// DELETE /api/rules/{id} — returns 204 No Content or 404 if not found.
func HandleDeleteRule(db *postgres.DB, engine *rules.RuleEngine, logger *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ruleID := chi.URLParam(r, "id")

		err := db.DeleteRule(r.Context(), ruleID)
		if err != nil {
			if err == pgx.ErrNoRows {
				writeError(w, http.StatusNotFound, "rule not found")
				return
			}
			logger.Error("failed to delete rule", zap.String("rule_id", ruleID), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal server error")
			return
		}

		reloadEngine(r.Context(), db, engine, logger)

		w.WriteHeader(http.StatusNoContent)
	}
}

// reloadEngine fetches all rules from DB and reloads the RuleEngine.
func reloadEngine(ctx context.Context, db *postgres.DB, engine *rules.RuleEngine, logger *zap.Logger) {
	allRules, err := db.ListRules(ctx)
	if err != nil {
		logger.Error("failed to list rules for engine reload", zap.Error(err))
		return
	}

	engineRules := make([]rules.Rule, len(allRules))
	for i, r := range allRules {
		engineRules[i] = r.ToRule()
	}
	engine.Reload(engineRules)
	logger.Info("rule engine reloaded", zap.Int("rule_count", len(engineRules)))
}
