package auth

import (
	"time"

	"runic/internal/api/middleware"
)

const (
	// Setup endpoints have different rate limits for GET (read-only, no side effects)
	// vs POST (creates admin user, writes to database).
	setupGetMaxRequests      = 20               // Max 20 GET requests per window
	setupGetRateLimitWindow  = time.Minute      // 1 minute window
	setupPostMaxRequests     = 5                // Max 5 POST requests per window
	setupPostRateLimitWindow = 10 * time.Minute // 10 minute window
)

var (
	// setupGetRateLimiter is the rate limiter for setup GET (read-only check).
	setupGetRateLimiter = middleware.NewRateLimiter(setupGetMaxRequests, setupGetRateLimitWindow)

	// setupPostRateLimiter is the rate limiter for setup POST (user creation).
	// Stricter than GET since this operation has side effects.
	setupPostRateLimiter = middleware.NewRateLimiter(setupPostMaxRequests, setupPostRateLimitWindow)
)

// CheckSetupGetRateLimit checks the rate limit for setup GET requests.
// Returns nil if allowed, error if rate limited.
func CheckSetupGetRateLimit(remoteAddr string) error {
	return setupGetRateLimiter.Check(remoteAddr)
}

// CheckSetupPostRateLimit checks the rate limit for setup POST requests.
// Returns nil if allowed, error if rate limited.
func CheckSetupPostRateLimit(remoteAddr string) error {
	return setupPostRateLimiter.Check(remoteAddr)
}

// StopSetupRateLimit stops the setup rate limiters' background cleanup goroutines.
// Call during graceful shutdown to prevent goroutine leaks.
func StopSetupRateLimit() {
	setupGetRateLimiter.Stop()
	setupPostRateLimiter.Stop()
}

// ResetSetupRateLimit resets the setup rate limiters. This is intended for testing to ensure test isolation.
func ResetSetupRateLimit() {
	setupGetRateLimiter.Reset()
	setupPostRateLimiter.Reset()
}
