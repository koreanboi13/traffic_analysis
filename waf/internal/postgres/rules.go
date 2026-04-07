package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/koreanboi13/traffic_analysis/waf/internal/rules"
)

// RuleRow represents a row in the rules table with DB metadata.
type RuleRow struct {
	ID        int       `json:"id"`
	RuleID    string    `json:"rule_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Category  string    `json:"category"`
	Pattern   string    `json:"pattern,omitempty"`
	Heuristic string    `json:"heuristic,omitempty"`
	Threshold float64   `json:"threshold"`
	Targets   []string  `json:"targets"`
	Weight    float32   `json:"weight"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ToRule converts a RuleRow to a rules.Rule domain object.
func (r *RuleRow) ToRule() rules.Rule {
	return rules.Rule{
		ID:        r.RuleID,
		Name:      r.Name,
		Type:      r.Type,
		Category:  r.Category,
		Pattern:   r.Pattern,
		Heuristic: r.Heuristic,
		Threshold: r.Threshold,
		Targets:   r.Targets,
		Weight:    r.Weight,
		Enabled:   r.Enabled,
	}
}

// ListRules returns all rules ordered by id.
func (db *DB) ListRules(ctx context.Context) ([]RuleRow, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled, created_at, updated_at
		 FROM rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()

	var result []RuleRow
	for rows.Next() {
		var r RuleRow
		if err := rows.Scan(&r.ID, &r.RuleID, &r.Name, &r.Type, &r.Category,
			&r.Pattern, &r.Heuristic, &r.Threshold, &r.Targets,
			&r.Weight, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

// GetRule returns a single rule by rule_id, or (nil, nil) if not found.
func (db *DB) GetRule(ctx context.Context, ruleID string) (*RuleRow, error) {
	var r RuleRow
	err := db.Pool.QueryRow(ctx,
		`SELECT id, rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled, created_at, updated_at
		 FROM rules WHERE rule_id = $1`, ruleID,
	).Scan(&r.ID, &r.RuleID, &r.Name, &r.Type, &r.Category,
		&r.Pattern, &r.Heuristic, &r.Threshold, &r.Targets,
		&r.Weight, &r.Enabled, &r.CreatedAt, &r.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get rule: %w", err)
	}
	return &r, nil
}

// CreateRule inserts a new rule and returns the created row.
func (db *DB) CreateRule(ctx context.Context, r rules.Rule) (*RuleRow, error) {
	var row RuleRow
	err := db.Pool.QueryRow(ctx,
		`INSERT INTO rules (rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 RETURNING id, rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled, created_at, updated_at`,
		r.ID, r.Name, r.Type, r.Category, r.Pattern, r.Heuristic, r.Threshold, r.Targets, r.Weight, r.Enabled,
	).Scan(&row.ID, &row.RuleID, &row.Name, &row.Type, &row.Category,
		&row.Pattern, &row.Heuristic, &row.Threshold, &row.Targets,
		&row.Weight, &row.Enabled, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	return &row, nil
}

// UpdateRule updates an existing rule by rule_id and returns the updated row.
// Returns (nil, nil) if the rule_id does not exist.
func (db *DB) UpdateRule(ctx context.Context, ruleID string, r rules.Rule) (*RuleRow, error) {
	var row RuleRow
	err := db.Pool.QueryRow(ctx,
		`UPDATE rules SET name=$1, type=$2, category=$3, pattern=$4, heuristic=$5, threshold=$6,
		 targets=$7, weight=$8, enabled=$9, updated_at=NOW()
		 WHERE rule_id=$10
		 RETURNING id, rule_id, name, type, category, pattern, heuristic, threshold, targets, weight, enabled, created_at, updated_at`,
		r.Name, r.Type, r.Category, r.Pattern, r.Heuristic, r.Threshold, r.Targets, r.Weight, r.Enabled, ruleID,
	).Scan(&row.ID, &row.RuleID, &row.Name, &row.Type, &row.Category,
		&row.Pattern, &row.Heuristic, &row.Threshold, &row.Targets,
		&row.Weight, &row.Enabled, &row.CreatedAt, &row.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("update rule: %w", err)
	}
	return &row, nil
}

// DeleteRule removes a rule by rule_id. Returns pgx.ErrNoRows if not found.
func (db *DB) DeleteRule(ctx context.Context, ruleID string) error {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM rules WHERE rule_id = $1`, ruleID)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}
