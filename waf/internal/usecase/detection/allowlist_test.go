package detection

import (
	"testing"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowlist_ContainsIP_CIDR(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"192.168.1.0/24"}},
	})
	require.NoError(t, err)
	assert.True(t, al.ContainsIP("192.168.1.5"))
	assert.False(t, al.ContainsIP("10.0.0.1"))
}

func TestAllowlist_ContainsIP_Exact(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"10.0.0.1"}},
	})
	require.NoError(t, err)
	assert.True(t, al.ContainsIP("10.0.0.1"))
	assert.False(t, al.ContainsIP("10.0.0.2"))
}

func TestAllowlist_ContainsIP_NotInList(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"192.168.1.0/24"}},
	})
	require.NoError(t, err)
	assert.False(t, al.ContainsIP("8.8.8.8"))
}

func TestAllowlist_ContainsPath_Prefix(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Paths: []string{"/api/health"}},
	})
	require.NoError(t, err)
	assert.True(t, al.ContainsPath("/api/health"))
	assert.True(t, al.ContainsPath("/api/healthcheck"))
	assert.False(t, al.ContainsPath("/admin/users"))
}

func TestAllowlist_MatchesHeaders_Match(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Headers: map[string]string{"X-Internal": "true"}},
	})
	require.NoError(t, err)
	assert.True(t, al.MatchesHeaders(map[string]string{"x-internal": "true"}))
}

func TestAllowlist_MatchesHeaders_WrongValue(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Headers: map[string]string{"X-Internal": "true"}},
	})
	require.NoError(t, err)
	assert.False(t, al.MatchesHeaders(map[string]string{"x-internal": "false"}))
}

func TestAllowlist_MatchesUserAgent_Match(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{UserAgents: []string{"Googlebot"}},
	})
	require.NoError(t, err)
	assert.True(t, al.MatchesUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1)"))
}

func TestAllowlist_MatchesUserAgent_NoMatch(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{UserAgents: []string{"Googlebot"}},
	})
	require.NoError(t, err)
	assert.False(t, al.MatchesUserAgent("curl/7.68"))
}

func TestAllowlist_MatchesParams_Match(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Params: map[string]string{"api_key": "trusted-key"}},
	})
	require.NoError(t, err)
	assert.True(t, al.MatchesParams(map[string]string{"api_key": "trusted-key"}))
}

func TestAllowlist_MatchesParams_NoMatch(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Params: map[string]string{"api_key": "trusted-key"}},
	})
	require.NoError(t, err)
	assert.False(t, al.MatchesParams(map[string]string{"other": "value"}))
}

func TestAllowlist_IsRuleExcluded(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{RuleIDs: []string{"sqli-sig-001"}},
	})
	require.NoError(t, err)
	assert.True(t, al.IsRuleExcluded("sqli-sig-001"))
	assert.False(t, al.IsRuleExcluded("xss-sig-001"))
}

func TestAllowlist_InvalidCIDR(t *testing.T) {
	_, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"999.999.999.999/99"}},
	})
	assert.Error(t, err)
}

func TestAllowlist_EmptyEntries(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{})
	require.NoError(t, err)
	assert.False(t, al.ContainsIP("1.2.3.4"))
	assert.False(t, al.ContainsPath("/anything"))
}

func TestAllowlist_ShouldBypass_IP(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"127.0.0.1"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{ClientIP: "127.0.0.1"}
	assert.True(t, al.ShouldBypass(pr))
}

func TestAllowlist_ShouldBypass_Path(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Paths: []string{"/healthz"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{NormalizedPath: "/healthz"}
	assert.True(t, al.ShouldBypass(pr))
}

func TestAllowlist_ShouldBypass_Header(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Headers: map[string]string{"X-Internal": "true"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{Headers: map[string]string{"x-internal": "true"}}
	assert.True(t, al.ShouldBypass(pr))
}

func TestAllowlist_ShouldBypass_UserAgent(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{UserAgents: []string{"Googlebot"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{UserAgent: "Googlebot/2.1"}
	assert.True(t, al.ShouldBypass(pr))
}

func TestAllowlist_ShouldBypass_Param(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{Params: map[string]string{"key": "val"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{QueryParams: map[string]string{"key": "val"}}
	assert.True(t, al.ShouldBypass(pr))
}

func TestAllowlist_ShouldBypass_NoMatch(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"10.0.0.1"}, Paths: []string{"/admin"}},
	})
	require.NoError(t, err)
	pr := &domain.ParsedRequest{
		ClientIP:       "8.8.8.8",
		NormalizedPath: "/api/data",
	}
	assert.False(t, al.ShouldBypass(pr))
}

func TestAllowlist_NilAllowlist(t *testing.T) {
	var al *Allowlist
	assert.False(t, al.ContainsIP("1.2.3.4"))
	assert.False(t, al.ContainsPath("/test"))
	assert.False(t, al.MatchesHeaders(nil))
	assert.False(t, al.MatchesUserAgent("test"))
	assert.False(t, al.MatchesParams(nil))
	assert.False(t, al.IsRuleExcluded("r1"))
	assert.False(t, al.ShouldBypass(nil))
}

func TestAllowlist_IPv6(t *testing.T) {
	al, err := NewAllowlist([]AllowlistEntry{
		{IPs: []string{"::1"}},
	})
	require.NoError(t, err)
	assert.True(t, al.ContainsIP("::1"))
	assert.False(t, al.ContainsIP("::2"))
}
