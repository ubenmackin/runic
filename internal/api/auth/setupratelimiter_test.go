package auth

import (
	"testing"
	"time"

	"runic/internal/api/middleware"
)

// newTestRateLimiter creates a rate limiter with the same configuration as the production one
func newTestRateLimiter() *middleware.RateLimiter {
	return middleware.NewRateLimiter(setupMaxRequests, setupRateLimitWindow)
}

// TestCheckSetupRateLimit_LimitTests tests that the rate limit is enforced correctly
func TestCheckSetupRateLimit_LimitTests(t *testing.T) {
	testIP := "192.168.1.100:12345"

	// Create a new rate limiter for testing (same limits as production)
	testLimiter := newTestRateLimiter()

	// Make requests up to the limit - all should succeed
	for i := 0; i < setupMaxRequests; i++ {
		err := testLimiter.Check(testIP)
		if err != nil {
			t.Errorf("Request %d: expected success, got error: %v", i+1, err)
		}
	}

	// The next request should fail
	err := testLimiter.Check(testIP)
	if err == nil {
		t.Error("Expected rate limit error after max requests, got nil")
	}
}

// TestCheckSetupRateLimit_WindowReset tests that the limit resets after the time window
func TestCheckSetupRateLimit_WindowReset(t *testing.T) {
	testIP := "192.168.1.101:12345"

	// Create a new rate limiter for testing
	testLimiter := newTestRateLimiter()

	// Make requests up to the limit
	for i := 0; i < setupMaxRequests; i++ {
		err := testLimiter.Check(testIP)
		if err != nil {
			t.Errorf("Request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Verify we're rate limited
	err := testLimiter.Check(testIP)
	if err == nil {
		t.Error("Expected rate limit error before window reset, got nil")
	}

	// Wait for the time window to expire (add a small buffer)
	time.Sleep(setupRateLimitWindow + 100*time.Millisecond)

	// Now the request should succeed
	err = testLimiter.Check(testIP)
	if err != nil {
		t.Errorf("Expected success after window reset, got error: %v", err)
	}

	// Stop the cleanup goroutine
	testLimiter.Stop()
}

// TestCheckSetupRateLimit_IndependentLimits tests that different IPs have independent rate limits
func TestCheckSetupRateLimit_IndependentLimits(t *testing.T) {
	ip1 := "192.168.1.102:12345"
	ip2 := "192.168.1.103:12345"

	// Create a new rate limiter for testing
	testLimiter := newTestRateLimiter()

	// Rate limit IP1 completely
	for i := 0; i < setupMaxRequests; i++ {
		err := testLimiter.Check(ip1)
		if err != nil {
			t.Errorf("IP1 request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Verify IP1 is rate limited
	err := testLimiter.Check(ip1)
	if err == nil {
		t.Error("Expected IP1 to be rate limited, got nil")
	}

	// IP2 should still be able to make requests (independent limit)
	for i := 0; i < setupMaxRequests; i++ {
		err := testLimiter.Check(ip2)
		if err != nil {
			t.Errorf("IP2 request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Stop the cleanup goroutine
	testLimiter.Stop()
}

// TestCheckSetupRateLimit_NormalRequests tests that normal requests work as expected
func TestCheckSetupRateLimit_NormalRequests(t *testing.T) {
	testIP := "192.168.1.104:12345"

	// Create a new rate limiter for testing
	testLimiter := newTestRateLimiter()

	// Make a few normal requests
	for i := 0; i < 3; i++ {
		err := testLimiter.Check(testIP)
		if err != nil {
			t.Errorf("Normal request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Stop the cleanup goroutine
	testLimiter.Stop()
}

// TestCheckSetupRateLimit_PublicAPI tests that the public CheckSetupRateLimit function works
func TestCheckSetupRateLimit_PublicAPI(t *testing.T) {
	// Use unique IPs to avoid interference from other tests
	testIP := "192.168.1.200:54321"

	// Test that the public API function works
	for i := 0; i < 5; i++ {
		err := CheckSetupRateLimit(testIP)
		if err != nil {
			t.Errorf("Public API request %d: expected success, got error: %v", i+1, err)
		}
	}
}
