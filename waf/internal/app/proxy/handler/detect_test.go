package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/wafcontext"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"github.com/koreanboi13/traffic_analysis/waf/internal/usecase/detection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func newTestDetect(t *testing.T, rulesList []domain.Rule, allowEntries []detection.AllowlistEntry, enabled bool) *Detect {
	t.Helper()
	engine, err := detection.NewRuleEngine(rulesList, 7, 3)
	require.NoError(t, err)

	al, err := detection.NewAllowlist(allowEntries)
	require.NoError(t, err)

	return NewDetect(engine, al, enabled, zap.NewNop())
}

func testRules() []domain.Rule {
	return []domain.Rule{
		{ID: "sqli-sig-001", Name: "SQLi UNION SELECT", Type: "regex", Category: "sqli",
			Pattern: "(?i)(?:union)\\s+(?:all\\s+)?(?:select)", Targets: []string{"query"}, Weight: 9, Enabled: true},
		{ID: "xss-sig-001", Name: "XSS script tag", Type: "regex", Category: "xss",
			Pattern: "(?i)<script[\\s>]", Targets: []string{}, Weight: 9, Enabled: true},
	}
}

func executeDetect(t *testing.T, detect *Detect, pr *domain.ParsedRequest) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = req.WithContext(wafcontext.WithParsedRequest(req.Context(), pr))
	rec := httptest.NewRecorder()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	detect.Handler(next).ServeHTTP(rec, req)
	return rec, nextCalled
}

func TestDetect_SQLiBlocked(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-001",
		NormalizedParams: map[string]string{"q": "1 union select 1,2,3"},
	}

	rec, nextCalled := executeDetect(t, detect, pr)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, nextCalled, "blocked request must not reach backend")

	var body blockResponse
	err := json.Unmarshal(rec.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "req-001", body.RequestID)
	assert.Contains(t, body.MatchedRules, "sqli-sig-001")
	assert.Equal(t, "Request blocked by WAF", body.Message)
	assert.Greater(t, body.Score, float32(0))
}

func TestDetect_XSSBlocked(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-002",
		NormalizedParams: map[string]string{"q": "<script>alert(1)</script>"},
	}

	rec, nextCalled := executeDetect(t, detect, pr)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, nextCalled)
}

func TestDetect_BenignPasses(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-003",
		NormalizedParams: map[string]string{"q": "hello world"},
	}

	rec, nextCalled := executeDetect(t, detect, pr)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, nextCalled)
	assert.Equal(t, "allow", pr.Verdict)
}

func TestDetect_AllowlistedIP(t *testing.T) {
	detect := newTestDetect(t, testRules(), []detection.AllowlistEntry{
		{IPs: []string{"127.0.0.1"}},
	}, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-004",
		ClientIP:         "127.0.0.1",
		NormalizedParams: map[string]string{"q": "1 union select 1,2,3"},
	}

	rec, nextCalled := executeDetect(t, detect, pr)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, nextCalled, "allowlisted request should pass through")
	assert.Equal(t, "allow", pr.Verdict)
}

func TestDetect_AllowlistedPath(t *testing.T) {
	detect := newTestDetect(t, testRules(), []detection.AllowlistEntry{
		{Paths: []string{"/healthz"}},
	}, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-005",
		NormalizedPath:   "/healthz",
		NormalizedParams: map[string]string{"q": "<script>alert(1)</script>"},
	}

	_, nextCalled := executeDetect(t, detect, pr)

	assert.True(t, nextCalled)
	assert.Equal(t, "allow", pr.Verdict)
}

func TestDetect_DisabledPassesThrough(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, false)
	pr := &domain.ParsedRequest{
		RequestID:        "req-006",
		NormalizedParams: map[string]string{"q": "1 union select 1,2,3"},
	}

	rec, nextCalled := executeDetect(t, detect, pr)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, nextCalled)
	assert.Equal(t, "allow", pr.Verdict)
}

func TestDetect_BlockSetsFieldsBeforeResponse(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-007",
		NormalizedParams: map[string]string{"q": "1 union select 1,2,3"},
	}

	executeDetect(t, detect, pr)

	assert.Equal(t, "block", pr.Verdict)
	assert.Contains(t, pr.RuleIDs, "sqli-sig-001")
	assert.Greater(t, pr.Score, float32(0))
}

func TestDetect_BlockResponseJSON(t *testing.T) {
	detect := newTestDetect(t, testRules(), nil, true)
	pr := &domain.ParsedRequest{
		RequestID:        "req-008",
		NormalizedParams: map[string]string{"q": "1 union select 1,2,3"},
	}

	rec, _ := executeDetect(t, detect, pr)

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]interface{}
	err := json.Unmarshal(rec.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Contains(t, body, "request_id")
	assert.Contains(t, body, "message")
	assert.Contains(t, body, "matched_rules")
	assert.Contains(t, body, "risk_score")
}
