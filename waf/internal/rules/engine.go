package rules

import (
	"regexp"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/koreanboi13/traffic_analysis/waf/config"
)

// RuleEngine evaluates detection rules against parsed requests.
type RuleEngine struct {
	mu         sync.RWMutex
	rules      []Rule
	regexCache *lru.Cache[string, *regexp.Regexp]
	cfg        config.DetectionConfig
}

// NewRuleEngine creates a RuleEngine with the given rules and config.
func NewRuleEngine(rules []Rule, cfg config.DetectionConfig) (*RuleEngine, error) {
	cache, err := lru.New[string, *regexp.Regexp](256)
	if err != nil {
		return nil, err
	}
	return &RuleEngine{rules: rules, regexCache: cache, cfg: cfg}, nil
}

// Reload atomically replaces the rule set and purges the regex cache.
// It is safe to call concurrently with Evaluate.
func (e *RuleEngine) Reload(newRules []Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = newRules
	e.regexCache.Purge()
}

// Evaluate runs all enabled rules against zone data and returns the result.
// zoneData maps zone names ("query", "path", "headers", "cookies", "body") to their values.
func (e *RuleEngine) Evaluate(zoneData map[string][]string) EvaluationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matches []RuleMatch
	var score float32

	allZones := []string{"query", "path", "headers", "cookies", "body"}

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		zones := rule.Targets
		if len(zones) == 0 {
			zones = allZones
		}

		for _, zone := range zones {
			values := zoneData[zone]
			for _, val := range values {
				if val == "" {
					continue
				}
				matched := false
				switch rule.Type {
				case "regex":
					matched = e.matchRegex(rule, val)
				case "heuristic":
					matched = matchHeuristic(rule, val)
				}
				if matched {
					truncated := val
					if len(truncated) > 200 {
						truncated = truncated[:200]
					}
					matches = append(matches, RuleMatch{
						RuleID:   rule.ID,
						RuleName: rule.Name,
						Category: rule.Category,
						Weight:   rule.Weight,
						Zone:     zone,
						Value:    truncated,
					})
					score += rule.Weight
					goto nextRule
				}
			}
		}
	nextRule:
	}

	ruleIDs := make([]string, 0, len(matches))
	seen := make(map[string]bool, len(matches))
	for _, m := range matches {
		if !seen[m.RuleID] {
			ruleIDs = append(ruleIDs, m.RuleID)
			seen[m.RuleID] = true
		}
	}

	verdict := "allow"
	if score >= e.cfg.BlockThreshold {
		verdict = "block"
	} else if score >= e.cfg.LogThreshold {
		verdict = "log_only"
	}

	return EvaluationResult{
		Verdict:        verdict,
		Score:          score,
		MatchedRuleIDs: ruleIDs,
		Matches:        matches,
	}
}

func (e *RuleEngine) getCompiledRegex(rule Rule) (*regexp.Regexp, error) {
	if cached, ok := e.regexCache.Get(rule.ID); ok {
		return cached, nil
	}
	compiled, err := regexp.Compile(rule.Pattern)
	if err != nil {
		return nil, err
	}
	e.regexCache.Add(rule.ID, compiled)
	return compiled, nil
}

func (e *RuleEngine) matchRegex(rule Rule, value string) bool {
	re, err := e.getCompiledRegex(rule)
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func matchHeuristic(rule Rule, value string) bool {
	switch rule.Heuristic {
	case "special_char_ratio":
		return specialCharRatio(value) > rule.Threshold
	case "html_tags":
		return containsHTMLTags(value)
	case "sqli_sequences":
		return hasSQLiHeuristic(value)
	default:
		return false
	}
}
