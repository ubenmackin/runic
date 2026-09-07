package api

import (
	"fmt"
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
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
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
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
	r := mux.NewRouter()
	a.RegisterRoutes(r, "")

	req := httptest.NewRequest("GET", "/api/v1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	headers := w.Header()

	if headers.Get("Strict-Transport-Security") == "" {
		t.Error("Strict-Transport-Security header missing")
	}

	if headers.Get("X-Request-ID") == "" {
		t.Error("X-Request-ID header missing")
	}

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
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
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
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
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

func TestLoginRateLimiterIgnoresSpoofedXFF(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
	r := mux.NewRouter()
	a.RegisterRoutes(r, "")

	// Same TCP peer rotating X-Forwarded-For per request must still share one
	// login bucket end to end (header stripping + StrictMiddleware): the
	// first 5 pass through to the handler, the 6th with a fresh spoofed
	// header is still 429.
	remoteAddr := "203.0.113.30:12345"
	spoofed := []string{
		"198.51.100.1",
		"198.51.100.2",
		"198.51.100.3",
		"198.51.100.4",
		"198.51.100.5",
	}
	for i, xff := range spoofed {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", xff)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("Rate limited too early at request %d with spoofed XFF %q", i+1, xff)
		}
	}

	req := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 on 6th request with rotated XFF, got %d (XFF rotation bypassed login limiter)", w.Code)
	}

	a.Stop()
}

func TestDownloadsRateLimiterIgnoresSpoofedXFF(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
	r := mux.NewRouter()
	a.RegisterRoutes(r, t.TempDir())
	defer a.Stop()

	// Same TCP peer rotating X-Forwarded-For/X-Real-IP per request must
	// still share one 60/min downloads bucket (StrictMiddleware keyed on
	// RemoteAddrIP with spoofable headers stripped): the first 60 pass
	// through to the handler (404 for the unstaged binary), the 61st with
	// a fresh spoofed header is still 429.
	remoteAddr := "203.0.113.50:12345"
	for i := 0; i < 60; i++ {
		req := httptest.NewRequest("GET", "/downloads/runic-agent-amd64", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("198.51.100.%d", (i%250)+1))
		req.Header.Set("X-Real-IP", fmt.Sprintf("192.0.2.%d", (i%250)+1))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("Rate limited too early at request %d with rotated XFF", i+1)
		}
	}

	req := httptest.NewRequest("GET", "/downloads/runic-agent-amd64", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	req.Header.Set("X-Real-IP", "192.0.2.99")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 on 61st request with rotated XFF, got %d (XFF rotation bypassed downloads limiter)", w.Code)
	}
}

func TestRouterStop(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()
	compiler := engine.NewTestCompiler(db)

	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)
	defer logsCleanup()

	a := NewAPI(db, compiler, logsDB, ":memory:", nil, nil)
	a.RegisterRoutes(mux.NewRouter(), "")

	// Ensure Stop doesn't panic
	a.Stop()
}
