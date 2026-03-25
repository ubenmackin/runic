package auth

import (
	"testing"
	"time"
)

// TestCheckSetupRateLimit_LimitTests tests that the rate limit is enforced correctly
func TestCheckSetupRateLimit_LimitTests(t *testing.T) {
	testIP := "192.168.1.100"

	// Clean up any existing entries for this IP
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, testIP)
	setupRateLimitMutex.Unlock()

	// Make requests up to the limit - all should succeed
	for i := 0; i < setupMaxRequests; i++ {
		err := CheckSetupRateLimit(testIP)
		if err != nil {
			t.Errorf("Request %d: expected success, got error: %v", i+1, err)
		}
	}

	// The next request should fail
	err := CheckSetupRateLimit(testIP)
	if err == nil {
		t.Error("Expected rate limit error after max requests, got nil")
	}
	if err != nil && err.Error() != "too many setup requests, please try again later" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

// TestCheckSetupRateLimit_WindowReset tests that the limit resets after the time window
func TestCheckSetupRateLimit_WindowReset(t *testing.T) {
	testIP := "192.168.1.101"

	// Clean up any existing entries for this IP
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, testIP)
	setupRateLimitMutex.Unlock()

	// Make requests up to the limit
	for i := 0; i < setupMaxRequests; i++ {
		err := CheckSetupRateLimit(testIP)
		if err != nil {
			t.Errorf("Request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Verify we're rate limited
	err := CheckSetupRateLimit(testIP)
	if err == nil {
		t.Error("Expected rate limit error before window reset, got nil")
	}

	// Wait for the time window to expire (add a small buffer)
	time.Sleep(setupRateLimitWindow + 100*time.Millisecond)

	// Now the request should succeed
	err = CheckSetupRateLimit(testIP)
	if err != nil {
		t.Errorf("Expected success after window reset, got error: %v", err)
	}
}

// TestCheckSetupRateLimit_IndependentLimits tests that different IPs have independent rate limits
func TestCheckSetupRateLimit_IndependentLimits(t *testing.T) {
	ip1 := "192.168.1.102"
	ip2 := "192.168.1.103"

	// Clean up any existing entries
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, ip1)
	delete(setupRateLimitStore, ip2)
	setupRateLimitMutex.Unlock()

	// Rate limit IP1 completely
	for i := 0; i < setupMaxRequests; i++ {
		err := CheckSetupRateLimit(ip1)
		if err != nil {
			t.Errorf("IP1 request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Verify IP1 is rate limited
	err := CheckSetupRateLimit(ip1)
	if err == nil {
		t.Error("Expected IP1 to be rate limited, got nil")
	}

	// IP2 should still be able to make requests (independent limit)
	for i := 0; i < setupMaxRequests; i++ {
		err := CheckSetupRateLimit(ip2)
		if err != nil {
			t.Errorf("IP2 request %d: expected success, got error: %v", i+1, err)
		}
	}
}

// TestCheckSetupRateLimit_NormalRequests tests that normal requests work as expected
func TestCheckSetupRateLimit_NormalRequests(t *testing.T) {
	testIP := "192.168.1.104"

	// Clean up any existing entries for this IP
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, testIP)
	setupRateLimitMutex.Unlock()

	// Make a few normal requests
	for i := 0; i < 3; i++ {
		err := CheckSetupRateLimit(testIP)
		if err != nil {
			t.Errorf("Normal request %d: expected success, got error: %v", i+1, err)
		}
	}
}

// TestCleanupStaleSetupEntries tests that stale entries are cleaned up
func TestCleanupStaleSetupEntries(t *testing.T) {
	testIP := "192.168.1.107"

	// Clean up any existing entries
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, testIP)
	setupRateLimitMutex.Unlock()

	// Add an entry with an old timestamp
	setupRateLimitMutex.Lock()
	setupRateLimitStore[testIP] = &setupRateLimitEntry{
		requests: []time.Time{time.Now().Add(-10 * time.Minute)},
	}
	initialCount := len(setupRateLimitStore)
	setupRateLimitMutex.Unlock()

	// Run cleanup
	CleanupStaleSetupEntries()

	// Verify the entry was removed
	setupRateLimitMutex.Lock()
	_, exists := setupRateLimitStore[testIP]
	finalCount := len(setupRateLimitStore)
	setupRateLimitMutex.Unlock()

	if exists {
		t.Error("Expected stale entry to be removed, but it still exists")
	}

	if finalCount >= initialCount {
		t.Errorf("Expected count to decrease after cleanup, got %d (was %d)", finalCount, initialCount)
	}
}

// TestCleanupStaleSetupEntries_KeepsRecent tests that recent entries are NOT cleaned up
func TestCleanupStaleSetupEntries_KeepsRecent(t *testing.T) {
	testIP := "192.168.1.108"

	// Clean up any existing entries
	setupRateLimitMutex.Lock()
	delete(setupRateLimitStore, testIP)
	setupRateLimitMutex.Unlock()

	// Add an entry with a recent timestamp
	setupRateLimitMutex.Lock()
	setupRateLimitStore[testIP] = &setupRateLimitEntry{
		requests: []time.Time{time.Now().Add(-1 * time.Minute)},
	}
	setupRateLimitMutex.Unlock()

	// Run cleanup
	CleanupStaleSetupEntries()

	// Verify the entry was NOT removed
	setupRateLimitMutex.Lock()
	_, exists := setupRateLimitStore[testIP]
	setupRateLimitMutex.Unlock()

	if !exists {
		t.Error("Expected recent entry to be kept, but it was removed")
	}
}
