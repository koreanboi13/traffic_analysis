package wafcontext

import (
	"context"

	"github.com/koreanboi13/traffic_analysis/waf/internal/domain"
)

type parsedRequestKey struct{}

// WithParsedRequest stores a ParsedRequest in the context.
func WithParsedRequest(ctx context.Context, pr *domain.ParsedRequest) context.Context {
	return context.WithValue(ctx, parsedRequestKey{}, pr)
}

// GetParsedRequest retrieves the ParsedRequest from the context.
func GetParsedRequest(ctx context.Context) *domain.ParsedRequest {
	pr, _ := ctx.Value(parsedRequestKey{}).(*domain.ParsedRequest)
	return pr
}
