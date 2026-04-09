package postgres

import (
	"context"
	"fmt"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// psql is the shared squirrel statement builder configured for PostgreSQL
// placeholder format ($1, $2, ...) as required by pgx.
var psql = sq.StatementBuilder.PlaceholderFormat(sq.Dollar)

// ruleColumns is the ordered list of columns used in every SELECT / RETURNING clause.
const ruleColumns = "id, rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled, log_only, created_at, updated_at"

// ruleRow is a private struct for scanning DB rows, with DB metadata fields.
type ruleRow struct {
	id        int
	ruleID    string
	name      string
	ruleType  string
	category  string
	pattern   string
	heuristic string
	threshold float64
	targets   []string
	weight    float32
	enabled   bool
	logOnly   bool
	createdAt time.Time
	updatedAt time.Time
}

// toDomain converts a ruleRow to a domain.Rule.
func (r *ruleRow) toDomain() domain.Rule {
	return domain.Rule{
		ID:        r.ruleID,
		Name:      r.name,
		Type:      r.ruleType,
		Category:  r.category,
		Pattern:   r.pattern,
		Heuristic: r.heuristic,
		Threshold: r.threshold,
		Targets:   r.targets,
		Weight:    r.weight,
		Enabled:   r.enabled,
		LogOnly:   r.logOnly,
	}
}

// scanRuleRow scans a pgx row into a ruleRow.
func scanRuleRow(scanner interface {
	Scan(dest ...any) error
}, row *ruleRow) error {
	return scanner.Scan(
		&row.id, &row.ruleID, &row.name, &row.ruleType, &row.category,
		&row.pattern, &row.heuristic, &row.threshold, &row.targets,
		&row.weight, &row.enabled, &row.logOnly, &row.createdAt, &row.updatedAt,
	)
}

// RuleRepository implements admin.RuleRepository using PostgreSQL.
type RuleRepository struct {
	db *DB
}

// NewRuleRepository creates a new RuleRepository.
func NewRuleRepository(db *DB) *RuleRepository {
	return &RuleRepository{db: db}
}

// ListRules returns all rules ordered by id.
func (r *RuleRepository) ListRules(ctx context.Context) ([]domain.Rule, error) {
	query, args, err := psql.
		Select(ruleColumns).
		From("rules").
		OrderBy("id").
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("list rules build query: %w", err)
	}

	rows, err := r.db.Pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var result []domain.Rule
	for rows.Next() {
		var row ruleRow
		if err := scanRuleRow(rows, &row); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		result = append(result, row.toDomain())
	}
	return result, rows.Err()
}

// GetRule returns a single rule by rule_id, or (nil, nil) if not found.
func (r *RuleRepository) GetRule(ctx context.Context, ruleID string) (*domain.Rule, error) {
	query, args, err := psql.
		Select(ruleColumns).
		From("rules").
		Where(sq.Eq{"rule_id": ruleID}).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("get rule build query: %w", err)
	}

	var row ruleRow
	if err := scanRuleRow(r.db.Pool.QueryRow(ctx, query, args...), &row); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get rule: %w", err)
	}
	d := row.toDomain()
	return &d, nil
}

// CreateRule inserts a new rule and returns the created domain.Rule.
func (r *RuleRepository) CreateRule(ctx context.Context, rule domain.Rule) (*domain.Rule, error) {
	query, args, err := psql.
		Insert("rules").
		Columns("rule_id", "name", "type", "category", "pattern", "heuristic", "threshold", "targets", "weight", "enabled", "log_only").
		Values(rule.ID, rule.Name, rule.Type, rule.Category, rule.Pattern, rule.Heuristic, rule.Threshold, rule.Targets, rule.Weight, rule.Enabled, rule.LogOnly).
		Suffix("RETURNING " + ruleColumns).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("create rule build query: %w", err)
	}

	var row ruleRow
	if err := scanRuleRow(r.db.Pool.QueryRow(ctx, query, args...), &row); err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	d := row.toDomain()
	return &d, nil
}

// UpdateRule updates an existing rule by rule_id and returns the updated domain.Rule.
// Returns (nil, nil) if the rule_id does not exist.
func (r *RuleRepository) UpdateRule(ctx context.Context, ruleID string, rule domain.Rule) (*domain.Rule, error) {
	query, args, err := psql.
		Update("rules").
		SetMap(map[string]interface{}{
			"name":       rule.Name,
			"type":       rule.Type,
			"category":   rule.Category,
			"pattern":    rule.Pattern,
			"heuristic":  rule.Heuristic,
			"threshold":  rule.Threshold,
			"targets":    rule.Targets,
			"weight":     rule.Weight,
			"enabled":    rule.Enabled,
			"log_only":   rule.LogOnly,
			"updated_at": sq.Expr("NOW()"),
		}).
		Where(sq.Eq{"rule_id": ruleID}).
		Suffix("RETURNING " + ruleColumns).
		ToSql()
	if err != nil {
		return nil, fmt.Errorf("update rule build query: %w", err)
	}

	var row ruleRow
	if err := scanRuleRow(r.db.Pool.QueryRow(ctx, query, args...), &row); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("update rule: %w", err)
	}
	d := row.toDomain()
	return &d, nil
}

// DeleteRule removes a rule by rule_id. Returns pgx.ErrNoRows if not found.
func (r *RuleRepository) DeleteRule(ctx context.Context, ruleID string) error {
	query, args, err := psql.
		Delete("rules").
		Where(sq.Eq{"rule_id": ruleID}).
		ToSql()
	if err != nil {
		return fmt.Errorf("delete rule build query: %w", err)
	}

	tag, err := r.db.Pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
