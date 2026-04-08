package domain

// Rule represents a single WAF detection rule.
type Rule struct {
	ID        string
	Name      string
	Type      string   // "regex" | "heuristic"
	Category  string   // "sqli" | "xss"
	Pattern   string   // regex pattern for type="regex"
	Heuristic string   // function name for type="heuristic"
	Threshold float64  // threshold for heuristic functions
	Targets   []string // "query", "headers", "cookies", "body", "path"; empty = all
	Weight    float32  // 1-10
	Enabled   bool
	LogOnly   bool
}

// RuleMatch records a single rule match during evaluation.
type RuleMatch struct {
	RuleID   string
	RuleName string
	Category string
	Weight   float32
	Zone     string // which zone matched
	Value    string // matched value (truncated for logging)
}

// EvaluationResult holds the outcome of evaluating all rules against a request.
type EvaluationResult struct {
	Verdict        string // "allow", "log_only", "block"
	Score          float32
	MatchedRuleIDs []string
	Matches        []RuleMatch
}
