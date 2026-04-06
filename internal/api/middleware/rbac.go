package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/auth"
	"runic/internal/common/log"
)

// RequireRole returns middleware that enforces role-based access control.
// It accepts variadic role strings and allows the request through if the
// authenticated user's role matches any of the provided roles.
// Returns 403 Forbidden with JSON response if the role doesn't match.
func RequireRole(roles ...string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole := auth.RoleFromContext(r.Context())
			for _, role := range roles {
				if userRole == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if err := json.NewEncoder(w).Encode(map[string]string{"error": "forbidden"}); err != nil {
				log.Warn("Failed to encode forbidden error", "error", err)
			}
		})
	}
}
