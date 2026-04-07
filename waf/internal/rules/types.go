package rules

// Rule represents a single detection rule loaded from rules.yaml.
type Rule struct {
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
}

// RuleMatch records a single rule match during evaluation.
type RuleMatch struct {
	RuleID   string
	RuleName string
	Category string
	Weight   float32
	Zone     string // which zone matched
	Value    string // matched value (truncated to 200 chars for logging)
}

// EvaluationResult holds the outcome of evaluating all rules against a request.
type EvaluationResult struct {
	Verdict        string // "allow", "log_only", "block"
	Score          float32
	MatchedRuleIDs []string
	Matches        []RuleMatch
}
