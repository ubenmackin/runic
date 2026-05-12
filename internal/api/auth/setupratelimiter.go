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

// CheckSetupRateLimit checks the setup rate limit. Returns nil if allowed, error if rate limited.
// This function maintains backward compatibility with existing code.
func CheckSetupRateLimit(remoteAddr string) error {
	return setupRateLimiter.Check(remoteAddr)
}

// StopSetupRateLimit stops the setup rate limiter's background cleanup goroutine.
// Call during graceful shutdown to prevent goroutine leaks.
func StopSetupRateLimit() {
	setupRateLimiter.Stop()
}

// ResetSetupRateLimit resets the setup rate limiter. This is intended for testing to ensure test isolation.
func ResetSetupRateLimit() {
	setupRateLimiter.Reset()
}
