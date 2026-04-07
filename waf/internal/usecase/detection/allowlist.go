package detection

import (
	"fmt"
	"net"
	"strings"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

// AllowlistEntry represents a single allowlist configuration entry.
type AllowlistEntry struct {
	Comment    string            `yaml:"comment,omitempty" mapstructure:"comment"`
	IPs        []string          `yaml:"ips,omitempty" mapstructure:"ips"`
	Paths      []string          `yaml:"paths,omitempty" mapstructure:"paths"`
	Headers    map[string]string `yaml:"headers,omitempty" mapstructure:"headers"`
	UserAgents []string          `yaml:"user_agents,omitempty" mapstructure:"user_agents"`
	Params     map[string]string `yaml:"params,omitempty" mapstructure:"params"`
	RuleIDs    []string          `yaml:"rule_ids,omitempty" mapstructure:"rule_ids"`
}

// Allowlist holds pre-parsed allowlist data for fast runtime checks.
type Allowlist struct {
	nets       []*net.IPNet
	ips        []net.IP
	paths      []string
	headers    map[string]string
	userAgents []string
	params     map[string]string
	ruleIDs    map[string]bool
}

// NewAllowlist creates an Allowlist from config entries, pre-parsing all CIDRs.
func NewAllowlist(entries []AllowlistEntry) (*Allowlist, error) {
	a := &Allowlist{
		headers: make(map[string]string),
		params:  make(map[string]string),
		ruleIDs: make(map[string]bool),
	}

	for _, e := range entries {
		for _, ipStr := range e.IPs {
			if strings.Contains(ipStr, "/") {
				_, ipNet, err := net.ParseCIDR(ipStr)
				if err != nil {
					return nil, fmt.Errorf("invalid CIDR %q: %w", ipStr, err)
				}
				a.nets = append(a.nets, ipNet)
			} else {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return nil, fmt.Errorf("invalid IP %q", ipStr)
				}
				a.ips = append(a.ips, ip)
			}
		}

		a.paths = append(a.paths, e.Paths...)

		for k, v := range e.Headers {
			a.headers[strings.ToLower(k)] = strings.ToLower(v)
		}

		a.userAgents = append(a.userAgents, e.UserAgents...)

		for k, v := range e.Params {
			a.params[k] = v
		}

		for _, rid := range e.RuleIDs {
			a.ruleIDs[rid] = true
		}
	}

	return a, nil
}

// ContainsIP returns true if the client IP is in the allowlist.
func (a *Allowlist) ContainsIP(clientIP string) bool {
	if a == nil {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, ipNet := range a.nets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	for _, allowedIP := range a.ips {
		if allowedIP.Equal(ip) {
			return true
		}
	}
	return false
}

// ContainsPath returns true if the path matches a prefix in the allowlist.
func (a *Allowlist) ContainsPath(path string) bool {
	if a == nil {
		return false
	}
	for _, p := range a.paths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// MatchesHeaders returns true if any allowlisted header key-value matches.
func (a *Allowlist) MatchesHeaders(headers map[string]string) bool {
	if a == nil || len(a.headers) == 0 {
		return false
	}
	for k, v := range a.headers {
		if hv, ok := headers[k]; ok && strings.EqualFold(hv, v) {
			return true
		}
	}
	return false
}

// MatchesUserAgent returns true if the user-agent contains any allowlisted substring.
func (a *Allowlist) MatchesUserAgent(userAgent string) bool {
	if a == nil {
		return false
	}
	lower := strings.ToLower(userAgent)
	for _, ua := range a.userAgents {
		if strings.Contains(lower, strings.ToLower(ua)) {
			return true
		}
	}
	return false
}

// MatchesParams returns true if any allowlisted query param key-value matches.
func (a *Allowlist) MatchesParams(params map[string]string) bool {
	if a == nil || len(a.params) == 0 {
		return false
	}
	for k, v := range a.params {
		if pv, ok := params[k]; ok && pv == v {
			return true
		}
	}
	return false
}

// IsRuleExcluded returns true if the rule ID is in the exclusion list.
func (a *Allowlist) IsRuleExcluded(ruleID string) bool {
	if a == nil {
		return false
	}
	return a.ruleIDs[ruleID]
}

// ShouldBypass returns true if the request should bypass detection entirely.
func (a *Allowlist) ShouldBypass(req *domain.ParsedRequest) bool {
	if a == nil || req == nil {
		return false
	}
	return a.ContainsIP(req.ClientIP) ||
		a.ContainsPath(req.NormalizedPath) ||
		a.MatchesHeaders(req.Headers) ||
		a.MatchesUserAgent(req.UserAgent) ||
		a.MatchesParams(req.QueryParams)
}
