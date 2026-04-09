package middleware

import (
	"net/http"
)

// RequireRole returns middleware that checks whether the authenticated user
// has one of the specified roles.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromCtx(r.Context())
			if claims == nil {
				writeJSON(w, http.StatusUnauthorized, errorBody{Error: "unauthorized"})
				return
			}
			if !allowed[claims.Role] {
				writeJSON(w, http.StatusForbidden, errorBody{Error: "forbidden"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
