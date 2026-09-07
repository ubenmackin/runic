package api

// =============================================================================
// HTTP MIDDLEWARES
// =============================================================================
//
// This file hosts the API-level middlewares (panic recovery, request ID,
// security headers, CORS, CSP, request logging, etc.) plus the
// RequireRefreshCookie middleware.
//
// Per-endpoint rate limiting lives in internal/api/middleware/ratelimit.go.
// Per-IP rate limiters are configured in api.go and applied to specific
// routes via the .Middleware(...) helper. The per-endpoint limits are:
//
//   - Login:           5 req/min   (brute-force defense)
//   - Register:       10 req/min
//   - Refresh token:  10 req/min
//   - Logout:         10 req/min
//   - Downloads:      10 req/min
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
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
)

const RequestIDHeader = "X-Request-ID"

// requestIDPattern constrains client-supplied request IDs to safe characters
// so header injection and log forgery via crafted IDs is not possible.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9\-_]{1,64}$`)

func isValidRequestID(s string) bool {
	return requestIDPattern.MatchString(s)
}

const CSPHeader = "Content-Security-Policy"

// CSPNonceHeader is the HTTP header name for the CSP nonce. This can be used by frontend code to access the nonce if needed.
const CSPNonceHeader = "X-CSP-Nonce"

// contextKey is the private key type for API-level context values.
// It is intentionally distinct from agents.contextKey so hub keys and
// CSP nonce keys cannot collide across packages.
type contextKey string

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

			if requestID == "" || !isValidRequestID(requestID) {
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

// devCORSAllowedOrigins is the explicit allowlist of dev origins permitted
// when GO_ENV=development. Reflecting an arbitrary Origin while sending
// Access-Control-Allow-Credentials: true is a well-known browser security
// pitfall (any malicious site can drive authenticated cross-site requests),
// so even in dev we restrict to the local Vite dev server ports.
var devCORSAllowedOrigins = map[string]bool{
	"http://localhost:5173": true,
	"http://127.0.0.1:5173": true,
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
			// In dev mode, allow requests from the local Vite dev server. The
			// "*" sentinel here means "look up the request's Origin in the
			// devCORSAllowedOrigins allowlist", NOT "reflect any origin".
			originConfig = "*"
		}
	}

	allowedMethods := "GET, POST, PUT, PATCH, DELETE, OPTIONS"
	allowedHeaders := "Content-Type, Authorization, X-Request-ID, X-CSRF-Token"
	maxAge := "86400" // 24 hours - cache preflight response

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			originToAllow := ""
			switch originConfig {
			case "*":
				// In dev mode, only allow origins in the explicit allowlist.
				// This preserves credentialed CORS for the local Vite dev
				// server while preventing other sites from making
				// credentialed requests to the API.
				if devCORSAllowedOrigins[origin] {
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
				common.RespondError(w, http.StatusUnauthorized, "Unauthorized")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
