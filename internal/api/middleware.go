package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/common/log"
)

// RequestIDHeader is the HTTP header name for request IDs.
const RequestIDHeader = "X-Request-ID"

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
