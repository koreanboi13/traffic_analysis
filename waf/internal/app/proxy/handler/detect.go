package handler

import (
	"encoding/json"
	"net/http"

	"github.com/koreanboi13/traffic_analysis/waf/internal/app/proxy/wafcontext"
	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
	"go.uber.org/zap"
)

type blockResponse struct {
	RequestID    string   `json:"request_id"`
	Message      string   `json:"message"`
	MatchedRules []string `json:"matched_rules"`
	Score        float32  `json:"risk_score"`
}

// RequestBypasser determines if a request should bypass WAF detection.
type RequestBypasser interface {
	ShouldBypass(req *domain.ParsedRequest) bool
}

// Detector evaluates rules against zone data from a parsed request.
type Detector interface {
	Evaluate(zoneData map[string][]string) domain.EvaluationResult
}

// Detect middleware evaluates requests against detection rules.
type Detect struct {
	detector  Detector
	allowlist RequestBypasser
	enabled   bool
	logger    *zap.Logger
}

// NewDetect creates a new Detect middleware.
func NewDetect(detector Detector, allowlist RequestBypasser, enabled bool, logger *zap.Logger) *Detect {
	return &Detect{
		detector:  detector,
		allowlist: allowlist,
		enabled:   enabled,
		logger:    logger,
	}
}

// Handler returns the middleware handler function.
func (d *Detect) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pr := wafcontext.GetParsedRequest(r.Context())

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

		result := d.detector.Evaluate(extractZoneData(pr))

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
			w.Header().Set("X-WAF-Verdict", "block")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(blockResponse{
				RequestID:    pr.RequestID,
				Message:      "Request blocked by WAF",
				MatchedRules: result.MatchedRuleIDs,
				Score:        result.Score,
			})
			return
		}

		w.Header().Set("X-WAF-Verdict", result.Verdict)
		next.ServeHTTP(w, r)
	})
}

func extractZoneData(pr *domain.ParsedRequest) map[string][]string {
	zd := make(map[string][]string, 5)

	queryVals := make([]string, 0, len(pr.NormalizedParams)+1)
	for _, v := range pr.NormalizedParams {
		queryVals = append(queryVals, v)
	}
	if pr.NormalizedQuery != "" {
		queryVals = append(queryVals, pr.NormalizedQuery)
	}
	zd["query"] = queryVals

	zd["path"] = []string{pr.NormalizedPath}

	headerVals := make([]string, 0, len(pr.Headers))
	for _, v := range pr.Headers {
		headerVals = append(headerVals, v)
	}
	zd["headers"] = headerVals

	cookieVals := make([]string, 0, len(pr.Cookies))
	for _, v := range pr.Cookies {
		cookieVals = append(cookieVals, v)
	}
	zd["cookies"] = cookieVals

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
