package api

import (
	"time"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// LoginRequest is the request body for POST /api/auth/login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse is the response for successful login.
type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

// ErrorResponse is the standard error envelope.
type ErrorResponse struct {
	Error string `json:"error"`
}

// RuleRequest is the request body for creating/updating a rule.
type RuleRequest struct {
	RuleID    string   `json:"rule_id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`     // "regex" | "heuristic"
	Category  string   `json:"category"` // "sqli" | "xss"
	Pattern   string   `json:"pattern,omitempty"`
	Heuristic string   `json:"heuristic,omitempty"`
	Threshold float64  `json:"threshold,omitempty"`
	Targets   []string `json:"targets"`
	Weight    float32  `json:"weight"`
	Enabled   bool     `json:"enabled"`
}

// EventsListResponse is the response for GET /api/events.
type EventsListResponse struct {
	Data   []domain.Event `json:"data"`
	Total  int64          `json:"total"`
	Offset int            `json:"offset"`
	Limit  int            `json:"limit"`
}

// ExportFilter is the request body for POST /api/events/export.
type ExportFilter struct {
	From    *time.Time `json:"from"`
	To      *time.Time `json:"to"`
	IP      string     `json:"ip"`
	Verdict string     `json:"verdict"`
	RuleID  string     `json:"rule_id"`
	Limit   int        `json:"limit"`
}
