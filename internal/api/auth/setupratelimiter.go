package auth

import (
	"fmt"
	"sync"
	"time"
)

// setupRateLimitEntry tracks IP-based request frequency for setup endpoints
type setupRateLimitEntry struct {
	requests []time.Time // Timestamps of recent requests
}

const (
	setupMaxRequests     = 10              // Max 10 requests per window
	setupRateLimitWindow = 1 * time.Minute // 1 minute window
)

var (
	setupRateLimitStore map[string]*setupRateLimitEntry
	setupRateLimitMutex sync.Mutex
)

func init() {
	setupRateLimitStore = make(map[string]*setupRateLimitEntry)

	// Start periodic cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			CleanupStaleSetupEntries()
		}
	}()
}

// CheckSetupRateLimit checks if the IP has exceeded the rate limit for setup endpoints
// Returns nil if allowed, error if rate limited
func CheckSetupRateLimit(remoteAddr string) error {
	setupRateLimitMutex.Lock()
	defer setupRateLimitMutex.Unlock()

	now := time.Now()
	entry, exists := setupRateLimitStore[remoteAddr]
	if !exists {
		entry = &setupRateLimitEntry{}
		setupRateLimitStore[remoteAddr] = entry
	}

	// Remove requests outside the time window
	cutoff := now.Add(-setupRateLimitWindow)
	validRequests := []time.Time{}
	for _, ts := range entry.requests {
		if ts.After(cutoff) {
			validRequests = append(validRequests, ts)
		}
	}
	entry.requests = validRequests

	// Check if limit exceeded
	if len(entry.requests) >= setupMaxRequests {
		return fmt.Errorf("too many setup requests, please try again later")
	}

	// Record this request
	entry.requests = append(entry.requests, now)
	return nil
}

// CleanupStaleSetupEntries removes entries with no recent activity
func CleanupStaleSetupEntries() {
	setupRateLimitMutex.Lock()
	defer setupRateLimitMutex.Unlock()

	now := time.Now()
	cutoff := now.Add(-5 * time.Minute) // Remove after 5 minutes of inactivity

	for ip, entry := range setupRateLimitStore {
		if len(entry.requests) == 0 || entry.requests[0].Before(cutoff) {
			delete(setupRateLimitStore, ip)
		}
	}
}
