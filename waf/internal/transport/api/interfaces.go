package api

import (
	"context"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
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
