package middleware

import (
	"net/http"
)

// RequireRole returns middleware that checks whether the authenticated user
// has one of the specified roles. Returns 401 if no claims in context,
// 403 if the user's role is not in the allowed set (T-05-06).
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromCtx(r.Context())
			if claims == nil {
				writeJSON(w, http.StatusUnauthorized, ErrorBody{Error: "unauthorized"})
				return
			}
			if !allowed[claims.Role] {
				writeJSON(w, http.StatusForbidden, ErrorBody{Error: "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
