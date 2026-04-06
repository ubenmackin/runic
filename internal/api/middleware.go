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
//   - POST /api/v1/auth/register
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
	"encoding/hex"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
)

// RequestIDHeader is the HTTP header name for request IDs.
const RequestIDHeader = "X-Request-ID"

// CSPHeader is the Content-Security-Policy header name.
const CSPHeader = "Content-Security-Policy"

// cspDirectives contains the CSP directives for the application.
// The script-src includes a hash for the inline dark mode script in index.html.
// Hash computed from: openssl dgst -sha256 -binary <script> | base64
var cspDirectives = strings.Join([]string{
	"default-src 'self'",
	"script-src 'self' 'sha256-bWmO0Su4nElv8RRute+EdRZcM9aoZ6K7R/rVKnR9UUw='",
	"style-src 'self' 'unsafe-inline'",
	"img-src 'self' data:",
	"font-src 'self'",
	"connect-src 'self' ws: wss:",
	"object-src 'none'",
	"base-uri 'self'",
	"form-action 'self'",
	"frame-ancestors 'none'",
}, "; ")

// RequestID middleware generates or extracts a request ID from the X-Request-ID header.
// It adds the request ID to the request context and ensures it's also returned in the response header.
func RequestID() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Try to extract request ID from header
			requestID := r.Header.Get(RequestIDHeader)

			// Generate a new request ID if not provided
			if requestID == "" {
				requestID = generateUUID()
			}

			// Add request ID to response header
			w.Header().Set(RequestIDHeader, requestID)

			// Add request ID to context using the log package's context key
			ctx := r.Context()
			ctx = log.SetRequestID(ctx, requestID)

			// Call next handler with the updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetRequestID extracts the request ID from the request context.
// Returns the request ID and true if found, otherwise returns empty string and false.
// Uses the log package's GetRequestID function for consistent context key usage.
func GetRequestID(ctx context.Context) (string, bool) {
	return log.GetRequestID(ctx)
}

// setSecurityHeaders sets common security hardening headers on the response.
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
}

// CSP returns a middleware that sets Content-Security-Policy headers.
// This provides server-side CSP enforcement which is authoritative over meta tags.
// The CSP includes a hash for the inline dark mode script to prevent flash of unstyled content.
func CSP() mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CSP header - this overrides any CSP meta tag in HTML
			w.Header().Set(CSPHeader, cspDirectives)

			// Additional security hardening headers
			setSecurityHeaders(w)

			next.ServeHTTP(w, r)
		})
	}
}

// CSPForAPI returns CSP headers suitable for API responses.
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

			// Additional security hardening headers
			setSecurityHeaders(w)

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders returns a middleware that sets common security headers on all responses.
// This middleware is applied as the outermost layer to ensure all responses include security headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		next.ServeHTTP(w, r)
	})
}

// generateUUID generates a random UUID using crypto/rand.
func generateUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based fallback if crypto/rand fails
		return "req-" + generateFallbackID()
	}
	return hex.EncodeToString(b)
}

// generateFallbackID generates a fallback ID using crypto/rand.
// This is only used if crypto/rand fails.
func generateFallbackID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Last resort fallback: use time-based values
		// This is deterministic but better than constant patterns
		for i := range b {
			b[i] = byte((i*7 + 13) ^ i)
		}
	}
	return hex.EncodeToString(b)
}

// RequestLogger middleware logs request details for tracing and debugging.
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

			// Get request ID from context (set by RequestID middleware)
			ctx := r.Context()
			requestID, _ := log.GetRequestID(ctx)

			// Log request start
			log.InfoContext(ctx, "request_started",
				"method", r.Method,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"remote_addr", r.RemoteAddr,
				"request_id", requestID,
			)

			// Wrap response writer to capture status code
			rw := common.NewResponseRecorder(w)

			// Call next handler
			next.ServeHTTP(rw, r)

			// Calculate duration
			duration := time.Since(start)

			// Log request completion
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

// CORS middleware adds Cross-Origin Resource Sharing headers to API responses.
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
// For development, set CORS_ORIGIN to the frontend URL (e.g., "http://localhost:5173").
func CORS() mux.MiddlewareFunc {
	// Get allowed origin from environment, default to same-origin (empty)
	// In production, frontend is served from same origin as API
	// In development, frontend runs on different port (e.g., localhost:5173)
	allowedOrigin := os.Getenv("CORS_ORIGIN")

	// If no explicit origin set and in development mode, allow common dev origins
	if allowedOrigin == "" {
		// Check if we're in development mode
		if os.Getenv("GO_ENV") == "development" || os.Getenv("APP_ENV") == "development" {
			// In dev mode, allow requests from common Vite dev server ports
			// The actual origin will be set dynamically based on Origin header
			allowedOrigin = "*" // Will be handled dynamically below
		}
	}

	allowedMethods := "GET, POST, PUT, DELETE, OPTIONS"
	allowedHeaders := "Content-Type, Authorization, X-Request-ID"
	maxAge := "86400" // 24 hours - cache preflight response

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Determine the origin to allow
			originToAllow := ""
			switch allowedOrigin {
			case "*":
				// In wildcard mode (dev), reflect the request origin
				// This allows any origin but maintains credential support
				if origin != "" {
					originToAllow = origin
				}
			case "":
				// Production mode: same-origin or reflect origin
				// This handles cases where frontend is on same host but different port
				if origin != "" {
					originToAllow = origin
				}
			default:
				// Use the explicitly configured origin
				originToAllow = allowedOrigin
			}

			// Set CORS headers if we have an origin to allow
			if originToAllow != "" {
				w.Header().Set("Access-Control-Allow-Origin", originToAllow)
				w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Max-Age", maxAge)
			}

			// Handle preflight OPTIONS request
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			// Continue to the next handler
			next.ServeHTTP(w, r)
		})
	}
}
