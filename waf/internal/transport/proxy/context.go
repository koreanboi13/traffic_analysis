package proxy

import (
	"context"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

type ctxKey int

const parsedRequestKey ctxKey = iota

// WithParsedRequest stores a domain.ParsedRequest in the context.
func WithParsedRequest(ctx context.Context, pr *domain.ParsedRequest) context.Context {
	return context.WithValue(ctx, parsedRequestKey, pr)
}

// GetParsedRequest retrieves the domain.ParsedRequest from the context.
// Returns nil if not present.
func GetParsedRequest(ctx context.Context) *domain.ParsedRequest {
	pr, _ := ctx.Value(parsedRequestKey).(*domain.ParsedRequest)
	return pr
}
