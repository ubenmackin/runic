// Package alerts provides alert and notification functionality.
package alerts

import (
	"sync"
	"time"
)

// Throttler tracks alert throttle state per alert type and peer.
// It determines whether an alert should be sent based on the last
// time an alert of the same type/peer was sent.
type Throttler struct {
	mu            sync.RWMutex
	throttleMins  int
	entries       map[string]time.Time // key: alertType:peerID
	now           func() time.Time     // configurable time source for testing
	cleanupPeriod time.Duration        // period for automatic cleanup of old entries
}

// NewThrottler creates a new Throttler with the specified throttle window in minutes.
func NewThrottler(throttleMinutes int) *Throttler {
	return &Throttler{
		throttleMins:  throttleMinutes,
		entries:       make(map[string]time.Time),
		now:           time.Now,
		cleanupPeriod: 0, // no automatic cleanup by default
	}
}

// NewThrottlerWithNow creates a new Throttler with a configurable time source.
func NewThrottlerWithNow(throttleMinutes int, now func() time.Time) *Throttler {
	return &Throttler{
		throttleMins: throttleMinutes,
		entries:      make(map[string]time.Time),
		now:          now,
	}
}

// SetNow sets the time source for testing purposes.
func (t *Throttler) SetNow(now func() time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.now = now
}

// ShouldSend returns true if the alert should be sent (not throttled).
// It returns false if an alert of the same type for the same peer
// was sent within the throttle window.
func (t *Throttler) ShouldSend(alertType string, peerID int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	key := makeKey(alertType, peerID)

	now := t.now()

	if lastAlert, exists := t.entries[key]; exists {
		throttleDuration := time.Duration(t.throttleMins) * time.Minute
		if now.Sub(lastAlert) < throttleDuration {
			return false // throttled
		}
	}

	// Update the last alert time for this key
	t.entries[key] = now
	return true
}

// Cleanup removes entries older than the throttle window.
// This should be called periodically to prevent memory leaks.
func (t *Throttler) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := t.now()
	throttleDuration := time.Duration(t.throttleMins) * time.Minute

	for key, lastAlert := range t.entries {
		if now.Sub(lastAlert) >= throttleDuration {
			delete(t.entries, key)
		}
	}
}

// EntryCount returns the number of tracked entries (for testing).
func (t *Throttler) EntryCount() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}

// makeKey creates a unique key for alert type and peer ID combination.
func makeKey(alertType string, peerID int) string {
	// Use a simple concatenation that handles the peerID properly
	return alertType + "|" + time.Duration(peerID).String()
}
