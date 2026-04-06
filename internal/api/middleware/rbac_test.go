package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"runic/internal/auth"
)

// runRBACtest is a helper that sets up and executes an RBAC middleware test.
// It returns the response recorder and whether the next handler was called,
// allowing callers to perform additional assertions.
func runRBACtest(t *testing.T, userRole, username string, requiredRoles []string, method string, wantStatus int, wantNextCalled bool) (*httptest.ResponseRecorder, bool) {
	t.Helper()

	nextCalled := false
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireRole(requiredRoles...)
	handler := middleware(nextHandler)

	req := httptest.NewRequest(method, "/", nil)
	ctx := auth.SetContextForTest(context.Background(), userRole, username)
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != wantStatus {
		t.Errorf("RequireRole() status = %d, want %d", rr.Code, wantStatus)
	}
	if nextCalled != wantNextCalled {
		t.Errorf("RequireRole() nextCalled = %v, want %v", nextCalled, wantNextCalled)
	}

	return rr, nextCalled
}

// TestRequireRole_SingleRole tests RequireRole middleware with a single role
func TestRequireRole_SingleRole(t *testing.T) {
	tests := []struct {
		name           string
		userRole       string
		requiredRole   string
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "matching role allows access",
			userRole:       "admin",
			requiredRole:   "admin",
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "non-matching role denies access",
			userRole:       "viewer",
			requiredRole:   "admin",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "empty role denies access",
			userRole:       "",
			requiredRole:   "admin",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "user role cannot access admin",
			userRole:       "user",
			requiredRole:   "admin",
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runRBACtest(t, tt.userRole, "testuser", []string{tt.requiredRole}, http.MethodGet, tt.wantStatus, tt.wantNextCalled)
		})
	}
}

// TestRequireRole_MultipleRoles tests RequireRole middleware with multiple allowed roles
func TestRequireRole_MultipleRoles(t *testing.T) {
	tests := []struct {
		name           string
		userRole       string
		requiredRoles  []string
		wantStatus     int
		wantNextCalled bool
	}{
		{
			name:           "first role matches",
			userRole:       "admin",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "middle role matches",
			userRole:       "operator",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "last role matches",
			userRole:       "viewer",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
		{
			name:           "no matching role in list",
			userRole:       "guest",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "empty role against multiple allowed",
			userRole:       "",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
		},
		{
			name:           "two roles with matching second",
			userRole:       "viewer",
			requiredRoles:  []string{"admin", "viewer"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runRBACtest(t, tt.userRole, "testuser", tt.requiredRoles, http.MethodGet, tt.wantStatus, tt.wantNextCalled)
		})
	}
}

// TestRequireRole_UnauthorizedAccess tests unauthorized access handling
func TestRequireRole_UnauthorizedAccess(t *testing.T) {
	tests := []struct {
		name           string
		userRole       string
		requiredRoles  []string
		wantStatus     int
		wantError      string
		wantNextCalled bool
	}{
		{
			name:           "role mismatch returns forbidden",
			userRole:       "guest",
			requiredRoles:  []string{"admin"},
			wantStatus:     http.StatusForbidden,
			wantError:      "forbidden",
			wantNextCalled: false,
		},
		{
			name:           "empty role returns forbidden",
			userRole:       "",
			requiredRoles:  []string{"admin"},
			wantStatus:     http.StatusForbidden,
			wantError:      "forbidden",
			wantNextCalled: false,
		},
		{
			name:           "lower privilege returns forbidden",
			userRole:       "viewer",
			requiredRoles:  []string{"admin", "operator"},
			wantStatus:     http.StatusForbidden,
			wantError:      "forbidden",
			wantNextCalled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr, _ := runRBACtest(t, tt.userRole, "testuser", tt.requiredRoles, http.MethodGet, tt.wantStatus, tt.wantNextCalled)

			// Verify response body contains error
			var response map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Errorf("Failed to parse response body: %v", err)
				return
			}
			if response["error"] != tt.wantError {
				t.Errorf("RequireRole() error response = %q, want %q", response["error"], tt.wantError)
			}

			// Verify content type is set for forbidden responses
			contentType := rr.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("RequireRole() Content-Type = %q, want %q", contentType, "application/json")
			}
		})
	}
}

// TestRequireRole_VerificationLogic tests role verification edge cases
func TestRequireRole_VerificationLogic(t *testing.T) {
	tests := []struct {
		name           string
		userRole       string
		username       string
		requiredRoles  []string
		wantStatus     int
		wantNextCalled bool
		description    string
	}{
		{
			name:           "case sensitive role matching",
			userRole:       "Admin",
			requiredRoles:  []string{"admin"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			description:    "Role matching should be case sensitive",
		},
		{
			name:           "exact role match required",
			userRole:       "admin",
			requiredRoles:  []string{"admin"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			description:    "Exact role match should grant access",
		},
		{
			name:           "role with whitespace mismatch",
			userRole:       " admin ",
			requiredRoles:  []string{"admin"},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			description:    "Whitespace in role should not match",
		},
		{
			name:           "multiple roles grants access if one matches",
			userRole:       "viewer",
			requiredRoles:  []string{"admin", "operator", "viewer"},
			wantStatus:     http.StatusOK,
			wantNextCalled: true,
			description:    "Any one matching role should grant access",
		},
		{
			name:           "empty required roles grants no access",
			userRole:       "admin",
			requiredRoles:  []string{},
			wantStatus:     http.StatusForbidden,
			wantNextCalled: false,
			description:    "Empty required roles should deny all access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runRBACtest(t, tt.userRole, tt.username, tt.requiredRoles, http.MethodGet, tt.wantStatus, tt.wantNextCalled)
		})
	}
}

// TestRequireRole_ResponseFormat tests the response format for forbidden requests
func TestRequireRole_ResponseFormat(t *testing.T) {
	rr, nextCalled := runRBACtest(t, "viewer", "testuser", []string{"admin"}, http.MethodGet, http.StatusForbidden, false)

	if nextCalled {
		t.Error("RequireRole() next handler should not be called")
	}

	// Verify Content-Type header
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("RequireRole() Content-Type = %q, want %q", contentType, "application/json")
	}

	// Verify JSON response body
	var response map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Errorf("Failed to parse response JSON: %v", err)
		return
	}
	if response["error"] != "forbidden" {
		t.Errorf("RequireRole() error = %q, want %q", response["error"], "forbidden")
	}
}

// TestRequireRole_HttpMethods tests the middleware works with different HTTP methods
func TestRequireRole_HttpMethods(t *testing.T) {
	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			runRBACtest(t, "admin", "testuser", []string{"admin"}, method, http.StatusOK, true)
		})
	}
}

// TestRequireRole_ContextPreservation tests that middleware preserves context values.
// This test requires a custom nextHandler to capture context, so it cannot use runRBACtest.
func TestRequireRole_ContextPreservation(t *testing.T) {
	var receivedRole string
	var receivedUsername string

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRole = auth.RoleFromContext(r.Context())
		receivedUsername = auth.UsernameFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	middleware := RequireRole("admin")
	handler := middleware(nextHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := auth.SetContextForTest(context.Background(), "admin", "testuser")
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("RequireRole() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify context values were preserved
	if receivedRole != "admin" {
		t.Errorf("Context role not preserved: got %q, want %q", receivedRole, "admin")
	}
	if receivedUsername != "testuser" {
		t.Errorf("Context username not preserved: got %q, want %q", receivedUsername, "testuser")
	}
}
