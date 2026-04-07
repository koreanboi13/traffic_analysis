package rules

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type rulesFile struct {
	Rules []Rule `yaml:"rules"`
}

// LoadFromFile reads and validates rules from a YAML file.
func LoadFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %s: %w", path, err)
	}

	var rf rulesFile
	if err := yaml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules file %s: %w", path, err)
	}

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
	}

	return rf.Rules, nil
}
