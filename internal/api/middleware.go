package api

// =============================================================================
// RATE LIMITING STRATEGY
// =============================================================================
//
// This file implements rate limiting using a SLIDING WINDOW algorithm.
// The implementation is in the 'ratelimit.go' file in this package.
//
// Algorithm: Sliding Window
// ----------------
// - Each client IP maintains a sliding window of request timestamps
// - Requests are allowed if the count of requests within the window < limit
// - Old timestamps are filtered out on each check (O(n) where n = requests in window)
// - Background goroutine cleans up stale entries every 5 minutes to prevent memory leaks
//
// Configuration:
// ----------------
// Rate limiters are created in api.go with the following limits:
//   - Login: 5 requests per minute (prevents brute force attacks)
//   - Register: 10 requests per minute (prevents spam registration)
//   - Refresh token: 10 requests per minute
//   - Logout: 10 requests per minute
//   - Downloads: 10 requests per minute (prevents bandwidth abuse)
//
// Covered Endpoints:
// ----------------
// All protected endpoints use rate limiting:
//   - POST /api/v1/auth/login
//   - POST /api/v1/agent/register
//   - POST /api/v1/auth/refresh
//   - POST /api/v1/auth/logout
//   - GET /downloads/{filename}
//
// Future Improvements:
// ----------------
// - Consider token bucket algorithm for burst handling
// - Consider Redis-backed rate limiter for multi-instance deployments
// - Add rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
//
// =============================================================================

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
)

const RequestIDHeader = "X-Request-ID"

const CSPHeader = "Content-Security-Policy"

// CSPNonceHeader is the HTTP header name for the CSP nonce. This can be used by frontend code to access the nonce if needed.
const CSPNonceHeader = "X-CSP-Nonce"

const CSPNonceKey contextKey = "csp-nonce"

// The nonce is a base64-encoded random value suitable for CSP.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is unrecoverable for security — panic is safer than weak nonce
		log.Error("crypto/rand failed in generateNonce", "error", err)
		panic("crypto/rand unavailable — cannot generate secure CSP nonce")
	}
	return base64.URLEncoding.EncodeToString(b)
}

// Using nonce-based CSP is more flexible than hash-based CSP as it doesn't
// require updating hashes when scripts change.
func buildCSPDirectives(nonce string) string {
	return strings.Join([]string{
		"default-src 'self'",
		fmt.Sprintf("script-src 'self' 'nonce-%s'", nonce),
		"style-src 'self' 'unsafe-inline'", // unsafe-inline required: the SPA uses CSS-in-JS and third-party component libraries that inject inline styles at runtime
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

// PanicRecovery returns a middleware that catches panics, logs them with a full stack trace,
// and returns a 500 Internal Server Error response. This must be the outermost middleware
// so that any panic downstream is caught and handled gracefully.
func PanicRecovery() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					stack := string(debug.Stack())
					log.Error("panic recovered",
						"method", r.Method,
						"path", r.URL.Path,
						"query", r.URL.RawQuery,
						"remote_addr", r.RemoteAddr,
						"panic", rec,
						"stack", stack,
					)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// RequestID returns a middleware that injects a request ID into the context and response headers.
// It adds the request ID to the request context and ensures it's also returned in the response header.
func RequestID() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get(RequestIDHeader)

			if requestID == "" {
				requestID = generateRequestID()
			}

			w.Header().Set(RequestIDHeader, requestID)

			ctx := r.Context()
			ctx = log.SetRequestID(ctx, requestID)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetCSPNonce extracts the CSP nonce from the given context.
// Returns the nonce and true if found, otherwise returns empty string and false.
func GetCSPNonce(ctx context.Context) (string, bool) {
	if nonce, ok := ctx.Value(CSPNonceKey).(string); ok {
		return nonce, true
	}
	return "", false
}

func setSecurityHeaders(w http.ResponseWriter, includeHSTS bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	if includeHSTS {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
}

// CSP returns a middleware that sets Content-Security-Policy headers with a per-request nonce.
// This provides server-side CSP enforcement which is authoritative over meta tags.
// The nonce is generated per-request and added to the response header and context.
// The frontend can use the nonce to authorize inline scripts.
func CSP() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			nonce := generateNonce()
			cspDirectives := buildCSPDirectives(nonce)

			w.Header().Set(CSPHeader, cspDirectives)
			w.Header().Set(CSPNonceHeader, nonce)

			ctx := r.Context()
			ctx = context.WithValue(ctx, CSPNonceKey, nonce)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CSPForAPI returns a middleware that sets strict CSP headers for API endpoints.
// API responses have stricter CSP since they don't need scripts, styles, or images.
func CSPForAPI() mux.MiddlewareFunc {
	apiCSP := strings.Join([]string{
		"default-src 'none'",
		"connect-src 'self'",
		"frame-ancestors 'none'",
	}, "; ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set(CSPHeader, apiCSP)
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders returns a middleware that sets common security headers.
// This middleware is applied as the outermost layer to ensure all responses include security headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, true)
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Error("crypto/rand failed in generateRequestID", "error", err)
		panic("crypto/rand unavailable — cannot generate secure request ID")
	}
	return hex.EncodeToString(b)
}

// RequestLogger returns a middleware that logs each request's start and completion with duration.
// It logs both the start of each request and the completion with duration.
// This is useful for tracing redirect paths and debugging request flow.
//
// Logs include:
//   - Request method, path, and query parameters
//   - Response status code
//   - Request duration
//   - Request ID (propagated via context from RequestID middleware)
//
// The middleware uses structured logging via the runiclog package.
// Logging errors are handled gracefully and never break the request.
func RequestLogger() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			ctx := r.Context()
			requestID, _ := log.GetRequestID(ctx)

			log.InfoContext(ctx, "request_started",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"remote_addr", r.RemoteAddr,
				"request_id", requestID,
			)

			rw := common.NewResponseRecorder(w)
			next.ServeHTTP(rw, r)
			duration := time.Since(start)

			log.InfoContext(ctx, "request_completed",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"status", rw.StatusCode(),
				"duration_ms", duration.Milliseconds(),
				"request_id", requestID,
			)
		})
	}
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing headers.
// This is necessary for proper handling of cross-origin requests from the frontend.
// The middleware:
// - Sets appropriate CORS headers for all responses
// - Handles OPTIONS preflight requests by returning 204 immediately
// - Allows credentials for cookie-based authentication
// - Caches preflight responses for 24 hours (86400 seconds)
//
// The allowed origin can be configured via the CORS_ORIGIN environment variable.
// If not set, it defaults to allowing same-origin requests (empty string),
// which works for production deployments where frontend and API share the same origin.
func CORS() mux.MiddlewareFunc {
	// originConfig holds the configured origin mode:
	//   ""     — same-origin only (production default)
	//   "*"    — dev mode: reflect the request's Origin header
	//   other  — explicit origin from CORS_ORIGIN env var
	originConfig := os.Getenv("CORS_ORIGIN")

	if originConfig == "" {
		if os.Getenv("GO_ENV") == "development" {
			// In dev mode, allow requests from common Vite dev server ports
			// The actual origin will be set dynamically based on Origin header
			originConfig = "*"
		}
	}

	allowedMethods := "GET, POST, PUT, DELETE, OPTIONS"
	allowedHeaders := "Content-Type, Authorization, X-Request-ID"
	maxAge := "86400" // 24 hours - cache preflight response

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			originToAllow := ""
			switch originConfig {
			case "*":
				// In wildcard mode (dev), reflect the request origin
				// This allows any origin but maintains credential support
				if origin != "" {
					originToAllow = origin
				}
			case "":
				// Production mode: same-origin only
				// Only allow requests from the same origin (no cross-origin in production without explicit config)
				originToAllow = ""
			default:
				originToAllow = originConfig
			}

			if originToAllow != "" {
				w.Header().Set("Access-Control-Allow-Origin", originToAllow)
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", maxAge)
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRefreshCookie returns a middleware that verifies the refresh token cookie is present.
// This provides an additional layer of protection for the token refresh endpoint by rejecting
// requests that don't include the expected cookie before they reach the handler.
func RequireRefreshCookie() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("runic_refresh_token")
			if err != nil || cookie.Value == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				if _, writeErr := w.Write([]byte(`{"error": "Unauthorized"}`)); writeErr != nil {
					log.Error("failed to write unauthorized response", "error", writeErr)
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
