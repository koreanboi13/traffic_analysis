package middleware

import "context"

type ctxKey int

const parsedRequestKey ctxKey = iota

// WithParsedRequest stores a ParsedRequest in the context.
func WithParsedRequest(ctx context.Context, pr *ParsedRequest) context.Context {
	return context.WithValue(ctx, parsedRequestKey, pr)
}

// GetParsedRequest retrieves the ParsedRequest from the context.
// Returns nil if not present.
func GetParsedRequest(ctx context.Context) *ParsedRequest {
	pr, _ := ctx.Value(parsedRequestKey).(*ParsedRequest)
	return pr
}
