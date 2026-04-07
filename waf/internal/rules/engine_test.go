package rules

import (
	"testing"

	"github.com/koreanboi13/traffic_analysis/waf/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEngine(t *testing.T, rules []Rule) *RuleEngine {
	t.Helper()
	cfg := config.DetectionConfig{
		LogThreshold:   3,
		BlockThreshold: 7,
		Enabled:        true,
	}
	engine, err := NewRuleEngine(rules, cfg)
	require.NoError(t, err)
	return engine
}

func zd(query, body, path string, headers, cookies map[string]string) map[string][]string {
	m := map[string][]string{}
	if query != "" {
		m["query"] = []string{query}
	}
	if body != "" {
		m["body"] = []string{body}
	}
	if path != "" {
		m["path"] = []string{path}
	}
	for _, v := range headers {
		m["headers"] = append(m["headers"], v)
	}
	for _, v := range cookies {
		m["cookies"] = append(m["cookies"], v)
	}
	return m
}

func TestRuleEngine_SQLiUnionSelect(t *testing.T) {
	rules := []Rule{
		{ID: "sqli-sig-001", Name: "SQLi UNION SELECT", Type: "regex", Category: "sqli",
			Pattern: "(?i)(?:union)\\s+(?:all\\s+)?(?:select)", Targets: []string{"query"}, Weight: 9, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("1 union select 1,2,3", "", "", nil, nil))
	assert.GreaterOrEqual(t, result.Score, float32(9))
	assert.Contains(t, result.MatchedRuleIDs, "sqli-sig-001")
	assert.Equal(t, "block", result.Verdict)
}

func TestRuleEngine_XSSScriptTag(t *testing.T) {
	rules := []Rule{
		{ID: "xss-sig-001", Name: "XSS script", Type: "regex", Category: "xss",
			Pattern: "(?i)<script[\\s>]", Targets: []string{}, Weight: 9, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("<script>alert(1)</script>", "", "", nil, nil))
	assert.GreaterOrEqual(t, result.Score, float32(9))
	assert.Contains(t, result.MatchedRuleIDs, "xss-sig-001")
}

func TestRuleEngine_BenignQuery(t *testing.T) {
	rules := []Rule{
		{ID: "sqli-sig-001", Name: "SQLi UNION SELECT", Type: "regex", Category: "sqli",
			Pattern: "(?i)(?:union)\\s+(?:all\\s+)?(?:select)", Targets: []string{"query"}, Weight: 9, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("select color red", "", "", nil, nil))
	assert.Empty(t, result.MatchedRuleIDs)
	assert.Equal(t, "allow", result.Verdict)
}

func TestRuleEngine_ScoreAccumulation(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Rule1", Type: "regex", Category: "sqli",
			Pattern: "(?i)union", Targets: []string{"query"}, Weight: 4, Enabled: true},
		{ID: "r2", Name: "Rule2", Type: "regex", Category: "sqli",
			Pattern: "(?i)select", Targets: []string{"query"}, Weight: 4, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("union select 1", "", "", nil, nil))
	assert.Equal(t, float32(8), result.Score)
	assert.Len(t, result.MatchedRuleIDs, 2)
}

func TestRuleEngine_VerdictAllow(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Low", Type: "regex", Category: "sqli",
			Pattern: "test", Targets: []string{"query"}, Weight: 2, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("test", "", "", nil, nil))
	assert.Equal(t, "allow", result.Verdict)
	assert.Equal(t, float32(2), result.Score)
}

func TestRuleEngine_VerdictLogOnly(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Med", Type: "regex", Category: "sqli",
			Pattern: "test", Targets: []string{"query"}, Weight: 5, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("test", "", "", nil, nil))
	assert.Equal(t, "log_only", result.Verdict)
}

func TestRuleEngine_VerdictBlock(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "High", Type: "regex", Category: "sqli",
			Pattern: "test", Targets: []string{"query"}, Weight: 8, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("test", "", "", nil, nil))
	assert.Equal(t, "block", result.Verdict)
}

func TestRuleEngine_ZoneTargeting(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Query only", Type: "regex", Category: "sqli",
			Pattern: "attack", Targets: []string{"query"}, Weight: 9, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	// Body has "attack" but rule targets only query
	result := engine.Evaluate(zd("", "attack payload here", "", nil, nil))
	assert.Empty(t, result.MatchedRuleIDs, "query-only rule should not match body content")
}

func TestRuleEngine_EmptyTargetsMatchesAll(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "All zones", Type: "regex", Category: "xss",
			Pattern: "attack", Targets: []string{}, Weight: 9, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("", "attack in body", "", nil, nil))
	assert.Contains(t, result.MatchedRuleIDs, "r1")
}

func TestRuleEngine_DisabledRuleSkipped(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Disabled", Type: "regex", Category: "sqli",
			Pattern: "attack", Targets: []string{"query"}, Weight: 9, Enabled: false},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("attack", "", "", nil, nil))
	assert.Empty(t, result.MatchedRuleIDs)
	assert.Equal(t, "allow", result.Verdict)
}

func TestRuleEngine_HeuristicSpecialCharRatio(t *testing.T) {
	rules := []Rule{
		{ID: "h1", Name: "Special chars", Type: "heuristic", Category: "sqli",
			Heuristic: "special_char_ratio", Threshold: 0.3, Targets: []string{"query"}, Weight: 3, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("' OR 1=1--", "", "", nil, nil))
	assert.Contains(t, result.MatchedRuleIDs, "h1")
}

func TestRuleEngine_HeuristicHTMLTags(t *testing.T) {
	rules := []Rule{
		{ID: "h2", Name: "HTML tags", Type: "heuristic", Category: "xss",
			Heuristic: "html_tags", Targets: []string{"query"}, Weight: 2, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("<div>test</div>", "", "", nil, nil))
	assert.Contains(t, result.MatchedRuleIDs, "h2")
}

func TestRuleEngine_HeuristicSQLiSequences(t *testing.T) {
	rules := []Rule{
		{ID: "h3", Name: "SQLi seq", Type: "heuristic", Category: "sqli",
			Heuristic: "sqli_sequences", Targets: []string{"query"}, Weight: 3, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	result := engine.Evaluate(zd("' OR 1=1", "", "", nil, nil))
	assert.Contains(t, result.MatchedRuleIDs, "h3")
}

func TestRuleEngine_ValueTruncation(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Name: "Match", Type: "regex", Category: "sqli",
			Pattern: "attack", Targets: []string{"query"}, Weight: 5, Enabled: true},
	}
	engine := newTestEngine(t, rules)

	longValue := "attack" + string(make([]byte, 300))
	result := engine.Evaluate(map[string][]string{"query": {longValue}})
	require.Len(t, result.Matches, 1)
	assert.LessOrEqual(t, len(result.Matches[0].Value), 200)
}
