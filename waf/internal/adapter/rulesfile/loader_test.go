package rulesfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestRules(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")
	err := os.WriteFile(path, []byte(content), 0644)
	require.NoError(t, err)
	return path
}

func TestLoad_ValidRules(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "sqli-001"
    name: "SQLi UNION"
    type: "regex"
    category: "sqli"
    pattern: "(?i)union\\s+select"
    targets: ["query", "body"]
    weight: 9
    enabled: true
  - id: "xss-001"
    name: "XSS script"
    type: "regex"
    category: "xss"
    pattern: "(?i)<script"
    targets: []
    weight: 8
    enabled: true
  - id: "heur-001"
    name: "Special chars"
    type: "heuristic"
    category: "sqli"
    heuristic: "special_char_ratio"
    threshold: 0.3
    targets: ["query"]
    weight: 3
    enabled: true
`)

	loader := NewLoader()
	rules, err := loader.Load(path)
	require.NoError(t, err)
	assert.Len(t, rules, 3)

	assert.Equal(t, "sqli-001", rules[0].ID)
	assert.Equal(t, "regex", rules[0].Type)
	assert.Equal(t, float32(9), rules[0].Weight)
	assert.Equal(t, []string{"query", "body"}, rules[0].Targets)
	assert.True(t, rules[0].Enabled)

	assert.Equal(t, "heuristic", rules[2].Type)
	assert.Equal(t, "special_char_ratio", rules[2].Heuristic)
	assert.Equal(t, 0.3, rules[2].Threshold)
}

func TestLoad_InvalidRegex(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "bad-regex"
    name: "Bad"
    type: "regex"
    category: "sqli"
    pattern: "[invalid("
    targets: []
    weight: 5
    enabled: true
`)

	loader := NewLoader()
	_, err := loader.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid regex pattern")
}

func TestLoad_MissingFile(t *testing.T) {
	loader := NewLoader()
	_, err := loader.Load("/nonexistent/rules.yaml")
	assert.Error(t, err)
}

func TestLoad_EmptyTargetsMeansAll(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "test-001"
    name: "Test"
    type: "regex"
    category: "xss"
    pattern: "test"
    targets: []
    weight: 5
    enabled: true
`)

	loader := NewLoader()
	rules, err := loader.Load(path)
	require.NoError(t, err)
	assert.Empty(t, rules[0].Targets)
}

func TestLoad_DisabledRule(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "disabled-001"
    name: "Disabled"
    type: "regex"
    category: "sqli"
    pattern: "test"
    targets: []
    weight: 5
    enabled: false
`)

	loader := NewLoader()
	rules, err := loader.Load(path)
	require.NoError(t, err)
	assert.Len(t, rules, 1)
	assert.False(t, rules[0].Enabled)
}

func TestLoad_EmptyID(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: ""
    name: "No ID"
    type: "regex"
    category: "sqli"
    pattern: "test"
    targets: []
    weight: 5
    enabled: true
`)

	loader := NewLoader()
	_, err := loader.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID must not be empty")
}

func TestLoad_InvalidType(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "bad-type"
    name: "Bad Type"
    type: "unknown"
    category: "sqli"
    pattern: "test"
    targets: []
    weight: 5
    enabled: true
`)

	loader := NewLoader()
	_, err := loader.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "type must be")
}

func TestLoad_WeightOutOfRange(t *testing.T) {
	path := writeTestRules(t, `
rules:
  - id: "heavy"
    name: "Too Heavy"
    type: "regex"
    category: "sqli"
    pattern: "test"
    targets: []
    weight: 15
    enabled: true
`)

	loader := NewLoader()
	_, err := loader.Load(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "weight must be 1-10")
}
