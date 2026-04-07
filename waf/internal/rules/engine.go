package rules

import (
	"regexp"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/koreanboi13/traffic_analysis/waf/internal/middleware"
)

// RuleEngine evaluates detection rules against parsed requests.
type RuleEngine struct {
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

// Evaluate runs all enabled rules against the request and returns the result.
func (e *RuleEngine) Evaluate(pr *middleware.ParsedRequest) EvaluationResult {
	var matches []RuleMatch
	var score float32

	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}

		zones := rule.Targets
		if len(zones) == 0 {
			zones = []string{"query", "path", "headers", "cookies", "body"}
		}

		for _, zone := range zones {
			values := extractZoneValues(pr, zone)
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
					goto nextRule // one match per rule is enough
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

func extractZoneValues(pr *middleware.ParsedRequest, zone string) []string {
	switch zone {
	case "query":
		vals := make([]string, 0, len(pr.NormalizedParams))
		for _, v := range pr.NormalizedParams {
			vals = append(vals, v)
		}
		if pr.NormalizedQuery != "" {
			vals = append(vals, pr.NormalizedQuery)
		}
		return vals
	case "path":
		return []string{pr.NormalizedPath}
	case "headers":
		vals := make([]string, 0, len(pr.Headers))
		for _, v := range pr.Headers {
			vals = append(vals, v)
		}
		return vals
	case "cookies":
		vals := make([]string, 0, len(pr.Cookies))
		for _, v := range pr.Cookies {
			vals = append(vals, v)
		}
		return vals
	case "body":
		var vals []string
		if pr.NormalizedBody != "" {
			vals = append(vals, pr.NormalizedBody)
		}
		for _, bp := range pr.NormalizedBodyParams {
			vals = append(vals, bp.Value)
		}
		return vals
	default:
		return nil
	}
}
