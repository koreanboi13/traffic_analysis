package admin

import (
	"context"
	"fmt"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// RuleRepository defines the persistence operations needed by RuleService.
type RuleRepository interface {
	ListRules(ctx context.Context) ([]domain.Rule, error)
	GetRule(ctx context.Context, ruleID string) (*domain.Rule, error)
	CreateRule(ctx context.Context, rule domain.Rule) (*domain.Rule, error)
	UpdateRule(ctx context.Context, ruleID string, rule domain.Rule) (*domain.Rule, error)
	DeleteRule(ctx context.Context, ruleID string) error
}

// Detector defines the detection engine operations needed by RuleService.
type Detector interface {
	Evaluate(zoneData map[string][]string) domain.EvaluationResult
	Reload(rules []domain.Rule)
}

// RuleService orchestrates rule CRUD and engine reloads.
type RuleService struct {
	repo     RuleRepository
	detector Detector
}

// NewRuleService creates a RuleService backed by the given repository and detector.
func NewRuleService(repo RuleRepository, detector Detector) *RuleService {
	return &RuleService{repo: repo, detector: detector}
}

// ListRules returns all rules from the repository.
func (s *RuleService) ListRules(ctx context.Context) ([]domain.Rule, error) {
	return s.repo.ListRules(ctx)
}

// GetRule returns a single rule by ID.
// Returns nil, nil when the rule does not exist.
func (s *RuleService) GetRule(ctx context.Context, id string) (*domain.Rule, error) {
	return s.repo.GetRule(ctx, id)
}

// CreateRule persists a new rule and reloads the detection engine.
func (s *RuleService) CreateRule(ctx context.Context, rule domain.Rule) (*domain.Rule, error) {
	created, err := s.repo.CreateRule(ctx, rule)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	s.reloadEngine(ctx)
	return created, nil
}

// UpdateRule updates an existing rule by ID and reloads the detection engine.
// Returns nil, nil when the rule does not exist.
func (s *RuleService) UpdateRule(ctx context.Context, id string, rule domain.Rule) (*domain.Rule, error) {
	updated, err := s.repo.UpdateRule(ctx, id, rule)
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	if updated != nil {
		s.reloadEngine(ctx)
	}
	return updated, nil
}

// DeleteRule removes a rule by ID and reloads the detection engine.
func (s *RuleService) DeleteRule(ctx context.Context, id string) error {
	if err := s.repo.DeleteRule(ctx, id); err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	s.reloadEngine(ctx)
	return nil
}

// reloadEngine fetches all current rules and pushes them into the detector.
// Errors are silently swallowed — a failed reload leaves the engine with stale rules,
// which is preferable to surfacing an internal error to the caller.
func (s *RuleService) reloadEngine(ctx context.Context) {
	rules, err := s.repo.ListRules(ctx)
	if err != nil {
		return
	}
	s.detector.Reload(rules)
}
