package middleware

import (
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/auth"
)

// RequireRole returns a middleware that restricts access to users with the specified roles.
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
			common.RespondError(w, http.StatusForbidden, "forbidden")
		})
	}
}
