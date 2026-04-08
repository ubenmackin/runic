package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"runic/internal/engine"
	"runic/internal/testutil"
)

func TestRouterIntegration(t *testing.T) {
	// Setup test DB and compiler
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewCompiler(db)

	// Create API and Router
	a := NewAPI(db, compiler)
	r := mux.NewRouter()

	tempDir, err := os.MkdirTemp("", "runic-downloads-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	a.RegisterRoutes(r, tempDir)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		checkHeaders   func(*testing.T, http.Header)
	}{
		{
			name:           "Health check",
			method:         "GET",
			path:           "/health",
			expectedStatus: http.StatusOK,
			checkHeaders: func(t *testing.T, h http.Header) {
				if h.Get("Content-Type") != "application/json" {
					t.Errorf("expected application/json, got %s", h.Get("Content-Type"))
				}
				// Security headers (applied globally)
				if h.Get("X-Frame-Options") != "DENY" {
					t.Errorf("expected X-Frame-Options DENY, got %s", h.Get("X-Frame-Options"))
				}
			},
		},
		{
			name:           "API v1 basic info",
			method:         "GET",
			path:           "/api/v1",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Public Setup GET",
			method:         "GET",
			path:           "/api/v1/setup",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Unauthenticated protected route",
			method:         "GET",
			path:           "/api/v1/peers",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid API route",
			method:         "GET",
			path:           "/api/v1/not-found",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.name, tt.expectedStatus, w.Code)
			}

			if tt.checkHeaders != nil {
				tt.checkHeaders(t, w.Header())
			}
		})
	}
}

func TestSecurityMiddlewares(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewCompiler(db)
	a := NewAPI(db, compiler)
	r := mux.NewRouter()
	a.RegisterRoutes(r, "")

	req := httptest.NewRequest("GET", "/api/v1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	headers := w.Header()

	// Check SecurityHeaders (outer layer)
	if headers.Get("Strict-Transport-Security") == "" {
		t.Error("Strict-Transport-Security header missing")
	}

	// Check RequestID middleware
	if headers.Get("X-Request-ID") == "" {
		t.Error("X-Request-ID header missing")
	}

	// Check CSP for API subrouter (testing an endpoint inside the subrouter)
	req2 := httptest.NewRequest("GET", "/api/v1/setup", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	csp := w2.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("Content-Security-Policy header missing for /api/v1/setup")
	} else if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("expected strict API CSP, got %s", csp)
	}
}

func TestCORSMiddleware(t *testing.T) {
	os.Setenv("CORS_ORIGIN", "http://test.com")
	defer os.Unsetenv("CORS_ORIGIN")

	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewCompiler(db)
	a := NewAPI(db, compiler)
	r := mux.NewRouter()
	a.RegisterRoutes(r, "")

	req := httptest.NewRequest("OPTIONS", "/api/v1/setup", nil)
	req.Header.Set("Origin", "http://test.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", w.Code)
	}
	if w.Header().Get("Access-Control-Allow-Origin") != "http://test.com" {
		t.Errorf("CORS mismatch, got %s", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestRateLimiters(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewCompiler(db)
	a := NewAPI(db, compiler)
	r := mux.NewRouter()
	a.RegisterRoutes(r, "")

	// LoginRateLimiter is set to 5 per minute in production.
	// We'll fire 6 requests quickly.
	clientIP := "1.2.3.4"

	for i := 0; i < 6; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = clientIP + ":1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if i < 5 {
			// It should be 401 Unauthorized because we send no body, but NOT 429
			if w.Code == http.StatusTooManyRequests {
				t.Errorf("Rate limited too early at request %d", i+1)
			}
		} else {
			// 6th request should be 429
			if w.Code != http.StatusTooManyRequests {
				t.Errorf("Expected 429 on 6th request, got %d", w.Code)
			}
		}
	}

	// Stop the API to cleanup rate limiter goroutines
	a.Stop()
}
func TestRouterStop(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewCompiler(db)
	a := NewAPI(db, compiler)
	a.RegisterRoutes(mux.NewRouter(), "")

	// Ensure Stop doesn't panic
	a.Stop()
}
