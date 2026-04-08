package rulesfile

import (
	"fmt"
	"os"
	"regexp"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"gopkg.in/yaml.v3"
)

// yamlRule is a private struct used for YAML unmarshalling.
// It mirrors domain.Rule but adds yaml struct tags.
type yamlRule struct {
	ID        string   `yaml:"id"`
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`                // "regex" | "heuristic"
	Category  string   `yaml:"category"`            // "sqli" | "xss"
	Pattern   string   `yaml:"pattern,omitempty"`   // regex pattern for type="regex"
	Heuristic string   `yaml:"heuristic,omitempty"` // function name for type="heuristic"
	Threshold float64  `yaml:"threshold,omitempty"` // threshold for heuristic functions
	Targets   []string `yaml:"targets"`             // "query", "headers", "cookies", "body", "path"; empty = all
	Weight    float32  `yaml:"weight"`              // 1-10
	Enabled   bool     `yaml:"enabled"`
	LogOnly   bool     `yaml:"log_only,omitempty"`
}

// toDomain converts a yamlRule to a domain.Rule.
func (y yamlRule) toDomain() domain.Rule {
	return domain.Rule{
		ID:        y.ID,
		Name:      y.Name,
		Type:      y.Type,
		Category:  y.Category,
		Pattern:   y.Pattern,
		Heuristic: y.Heuristic,
		Threshold: y.Threshold,
		Targets:   y.Targets,
		Weight:    y.Weight,
		Enabled:   y.Enabled,
		LogOnly:   y.LogOnly,
	}
}

// rulesFile is the top-level YAML document structure.
type rulesFile struct {
	Rules []yamlRule `yaml:"rules"`
}

// Loader loads and validates rules from YAML files.
type Loader struct{}

// NewLoader creates a new Loader.
func NewLoader() *Loader {
	return &Loader{}
}

// Load reads and validates rules from a YAML file, returning []domain.Rule.
func (l *Loader) Load(path string) ([]domain.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %s: %w", path, err)
	}

	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules file %s: %w", path, err)
	}

	result := make([]domain.Rule, 0, len(rf.Rules))
	for i, r := range rf.Rules {
		if r.ID == "" {
			return nil, fmt.Errorf("rule at index %d: ID must not be empty", i)
		}
		if r.Type != "regex" && r.Type != "heuristic" {
			return nil, fmt.Errorf("rule %q: type must be \"regex\" or \"heuristic\", got %q", r.ID, r.Type)
		}
		if r.Weight < 1 || r.Weight > 10 {
			return nil, fmt.Errorf("rule %q: weight must be 1-10, got %v", r.ID, r.Weight)
		}
		if r.Type == "regex" && r.Pattern != "" {
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return nil, fmt.Errorf("rule %q: invalid regex pattern: %w", r.ID, err)
			}
		}
		result = append(result, r.toDomain())
	}

	return result, nil
}
