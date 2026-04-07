package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/koreanboi13/traffic_analysis/waf/internal/rules"
	"go.uber.org/zap"
)

type blockResponse struct {
	RequestID    string   `json:"request_id"`
	Message      string   `json:"message"`
	MatchedRules []string `json:"matched_rules"`
	Score        float32  `json:"risk_score"`
}

// Detect middleware evaluates requests against detection rules.
type Detect struct {
	engine    *rules.RuleEngine
	allowlist *Allowlist
	enabled   bool
	logger    *zap.Logger
}

// NewDetect creates a new Detect middleware.
func NewDetect(engine *rules.RuleEngine, allowlist *Allowlist, enabled bool, logger *zap.Logger) *Detect {
	return &Detect{engine: engine, allowlist: allowlist, enabled: enabled, logger: logger}
}

// Handler returns the middleware handler function.
func (d *Detect) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr := GetParsedRequest(r.Context())

		if pr == nil || !d.enabled {
			if pr != nil {
				pr.Verdict = "allow"
			}
			next.ServeHTTP(w, r)
			return
		}

		if d.allowlist.ShouldBypass(pr) {
			pr.Verdict = "allow"
			d.logger.Debug("request allowlisted",
				zap.String("request_id", pr.RequestID),
				zap.String("client_ip", pr.ClientIP),
			)
			next.ServeHTTP(w, r)
			return
		}

		result := d.engine.Evaluate(extractZoneData(pr))

		// Set detection results on ParsedRequest BEFORE writing response,
		// so RecordEvent (which wraps this middleware) can read them.
		pr.Verdict = result.Verdict
		pr.RuleIDs = result.MatchedRuleIDs
		pr.Score = result.Score

		d.logger.Debug("detection result",
			zap.String("request_id", pr.RequestID),
			zap.String("verdict", result.Verdict),
			zap.Float32("score", result.Score),
			zap.Int("matched_rules", len(result.Matches)),
		)

		if result.Verdict == "block" {
			writeBlockResponse(w, pr.RequestID, result.MatchedRuleIDs, result.Score)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractZoneData maps ParsedRequest fields to zone name -> values for the rule engine.
func extractZoneData(pr *ParsedRequest) map[string][]string {
	zd := make(map[string][]string, 5)

	// query zone
	queryVals := make([]string, 0, len(pr.NormalizedParams)+1)
	for _, v := range pr.NormalizedParams {
		queryVals = append(queryVals, v)
	}
	if pr.NormalizedQuery != "" {
		queryVals = append(queryVals, pr.NormalizedQuery)
	}
	zd["query"] = queryVals

	// path zone
	zd["path"] = []string{pr.NormalizedPath}

	// headers zone
	headerVals := make([]string, 0, len(pr.Headers))
	for _, v := range pr.Headers {
		headerVals = append(headerVals, v)
	}
	zd["headers"] = headerVals

	// cookies zone
	cookieVals := make([]string, 0, len(pr.Cookies))
	for _, v := range pr.Cookies {
		cookieVals = append(cookieVals, v)
	}
	zd["cookies"] = cookieVals

	// body zone
	var bodyVals []string
	if pr.NormalizedBody != "" {
		bodyVals = append(bodyVals, pr.NormalizedBody)
	}
	for _, bp := range pr.NormalizedBodyParams {
		bodyVals = append(bodyVals, bp.Value)
	}
	zd["body"] = bodyVals

	return zd
}

func writeBlockResponse(w http.ResponseWriter, requestID string, ruleIDs []string, score float32) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(blockResponse{
		RequestID:    requestID,
		Message:      "Request blocked by WAF",
		MatchedRules: ruleIDs,
		Score:        score,
	})
}
