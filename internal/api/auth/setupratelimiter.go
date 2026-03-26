package auth

import (
	"time"

	"runic/internal/api/middleware"
)

const (
	setupMaxRequests     = 10          // Max 10 requests per window
	setupRateLimitWindow = time.Minute // 1 minute window
)

var (
	// setupRateLimiter is the shared rate limiter for setup endpoints.
	// Using the unified middleware package with periodic cleanup.
	setupRateLimiter = middleware.NewRateLimiter(setupMaxRequests, setupRateLimitWindow)
)

// CheckSetupRateLimit checks if the IP has exceeded the rate limit for setup endpoints.
// Returns nil if allowed, error if rate limited.
// This function maintains backward compatibility with existing code.
func CheckSetupRateLimit(remoteAddr string) error {
	return setupRateLimiter.Check(remoteAddr)
}
