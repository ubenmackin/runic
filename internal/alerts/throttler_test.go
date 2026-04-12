// Package alerts provides alert and notification functionality.
package alerts

import (
	"sync"
	"testing"
	"time"
)

// TestShouldSend_First tests that the first alert always sends.
func TestShouldSend_First(t *testing.T) {
	throttler := NewThrottler(15) // 15 minute window

	// First alert should always return true
	got := throttler.ShouldSend("blocked_spike", 0)
	if !got {
		t.Error("expected first ShouldSend() to return true, got false")
	}
}

// TestShouldSend_Throttled tests that a second alert within the window is blocked.
func TestShouldSend_Throttled(t *testing.T) {
	now := time.Now()
	throttler := NewThrottlerWithNow(15, func() time.Time {
		return now
	})

	// First call should return true
	first := throttler.ShouldSend("blocked_spike", 0)
	if !first {
		t.Error("expected first ShouldSend() to return true, got false")
	}

	// Second call immediately should return false (throttled)
	second := throttler.ShouldSend("blocked_spike", 0)
	if second {
		t.Error("expected second ShouldSend() to return false (throttled), got true")
	}
}

// TestShouldSend_AfterWindow tests that an alert after the throttle window sends.
func TestShouldSend_AfterWindow(t *testing.T) {
	baseTime := time.Now()
	currentTime := baseTime

	throttler := NewThrottlerWithNow(15, func() time.Time {
		return currentTime
	})

	// First call should return true
	first := throttler.ShouldSend("blocked_spike", 0)
	if !first {
		t.Error("expected first ShouldSend() to return true, got false")
	}

	// Advance time past the throttle window (15 minutes + 1 minute)
	currentTime = baseTime.Add(16 * time.Minute)
	throttler.SetNow(func() time.Time {
		return currentTime
	})

	// After window, should return true again
	third := throttler.ShouldSend("blocked_spike", 0)
	if !third {
		t.Error("expected ShouldSend() after window to return true, got false")
	}
}

// TestShouldSend_DifferentTypes tests that different alert types don't interfere.
func TestShouldSend_DifferentTypes(t *testing.T) {
	now := time.Now()
	throttler := NewThrottlerWithNow(15, func() time.Time {
		return now
	})

	// Send "peer_offline" alert - should return true
	first := throttler.ShouldSend("peer_offline", 0)
	if !first {
		t.Error("expected first 'peer_offline' alert to return true, got false")
	}

	// Send "bundle_failed" immediately - should return true (different type)
	second := throttler.ShouldSend("bundle_failed", 0)
	if !second {
		t.Error("expected 'bundle_failed' alert to return true (different type), got false")
	}

	// Send "peer_offline" again - should return false (throttled)
	third := throttler.ShouldSend("peer_offline", 0)
	if third {
		t.Error("expected second 'peer_offline' alert to return false (throttled), got true")
	}
}

// TestShouldSend_DifferentPeers tests that same type, different peer sends.
func TestShouldSend_DifferentPeers(t *testing.T) {
	now := time.Now()
	throttler := NewThrottlerWithNow(15, func() time.Time {
		return now
	})

	// Send alert for peer_id=1 - should return true
	first := throttler.ShouldSend("peer_offline", 1)
	if !first {
		t.Error("expected alert for peer_id=1 to return true, got false")
	}

	// Send same type alert for peer_id=2 - should return true (different peer)
	second := throttler.ShouldSend("peer_offline", 2)
	if !second {
		t.Error("expected alert for peer_id=2 to return true (different peer), got false")
	}

	// Send same type for peer_id=1 - should return false (throttled)
	third := throttler.ShouldSend("peer_offline", 1)
	if third {
		t.Error("expected second alert for peer_id=1 to return false (throttled), got true")
	}
}

// TestCleanup tests that old entries are cleaned up.
func TestCleanup(t *testing.T) {
	baseTime := time.Now()
	currentTime := baseTime

	throttler := NewThrottlerWithNow(15, func() time.Time {
		return currentTime
	})

	// Add multiple entries
	_ = throttler.ShouldSend("alert_type_1", 1)
	_ = throttler.ShouldSend("alert_type_2", 2)
	_ = throttler.ShouldSend("alert_type_3", 3)

	// Verify we have 3 entries
	if count := throttler.EntryCount(); count != 3 {
		t.Errorf("expected 3 entries before cleanup, got %d", count)
	}

	// Advance time past the throttle window
	currentTime = baseTime.Add(16 * time.Minute)
	throttler.SetNow(func() time.Time {
		return currentTime
	})

	// Run cleanup
	throttler.Cleanup()

	// Verify old entries are removed
	if count := throttler.EntryCount(); count != 0 {
		t.Errorf("expected 0 entries after cleanup, got %d", count)
	}
}

// TestCleanup_PartialCleanup tests that only old entries are removed.
func TestCleanup_PartialCleanup(t *testing.T) {
	baseTime := time.Now()
	currentTime := baseTime

	throttler := NewThrottlerWithNow(15, func() time.Time {
		return currentTime
	})

	// Add entries at different times
	_ = throttler.ShouldSend("old_alert", 1)
	currentTime = baseTime.Add(10 * time.Minute)
	throttler.SetNow(func() time.Time {
		return currentTime
	})
	_ = throttler.ShouldSend("newer_alert", 2)

	// Advance time to make first entry old, but second still within window
	currentTime = baseTime.Add(20 * time.Minute)
	throttler.SetNow(func() time.Time {
		return currentTime
	})

	// Run cleanup
	throttler.Cleanup()

	// Should have 1 entry remaining (newer_alert)
	if count := throttler.EntryCount(); count != 1 {
		t.Errorf("expected 1 entry after partial cleanup, got %d", count)
	}
}

// TestShouldSend_MultipleAlertsOverTime tests sending multiple alerts over time.
func TestShouldSend_MultipleAlertsOverTime(t *testing.T) {
	baseTime := time.Now()
	currentTime := baseTime

	throttler := NewThrottlerWithNow(5, func() time.Time {
		return currentTime
	})

	// Send alert, advance time, send again - should work each time
	for i := 0; i < 5; i++ {
		got := throttler.ShouldSend("test_alert", 1)
		if !got {
			t.Errorf("iteration %d: expected ShouldSend to return true, got false", i)
		}
		// Advance past the 5 minute window
		currentTime = baseTime.Add(time.Duration((i+1)*6) * time.Minute)
		throttler.SetNow(func() time.Time {
			return currentTime
		})
	}
}

// TestShouldSend_EdgeCase_ExactWindow tests behavior at exact window boundary.
func TestShouldSend_EdgeCase_ExactWindow(t *testing.T) {
	baseTime := time.Now()
	currentTime := baseTime

	throttler := NewThrottlerWithNow(15, func() time.Time {
		return currentTime
	})

	// First call
	_ = throttler.ShouldSend("test_alert", 1)

	// At exactly 15 minutes, should still be throttled (uses < comparison)
	currentTime = baseTime.Add(15 * time.Minute)
	throttler.SetNow(func() time.Time {
		return currentTime
	})

	// At exactly the window, the comparison is "now - lastAlert < duration"
	// 15 minutes - 0 = 15 minutes, which is NOT < 15 minutes, so it should send
	got := throttler.ShouldSend("test_alert", 1)
	if !got {
		t.Error("expected ShouldSend at exact window boundary to return true, got false")
	}
}

// TestShouldSend_Concurrent tests concurrent access to ShouldSend.
// This test verifies the thread safety of the Throttler by ensuring that
// exactly one true result is returned for each unique peer_id, even under
// concurrent access from multiple goroutines.
func TestShouldSend_Concurrent(t *testing.T) {
	throttler := NewThrottler(15)

	const goroutines = 100
	const uniquePeers = 10

	results := make([]bool, goroutines)
	var wg sync.WaitGroup
	var startWg sync.WaitGroup

	// Use a barrier to synchronize goroutine start for more predictable execution
	startWg.Add(1)
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			// Wait for all goroutines to be ready
			startWg.Wait()
			// Only 10 unique peers, each peer gets 10 calls
			results[idx] = throttler.ShouldSend("test_alert", idx%uniquePeers)
		}(i)
	}

	// Release all goroutines simultaneously
	startWg.Done()
	wg.Wait()

	// Count true results
	// With proper synchronization, we expect exactly 10 true results
	// (one for each unique peer_id) since the first call for each peer
	// should succeed and subsequent calls should be throttled
	trueCount := 0
	for _, r := range results {
		if r {
			trueCount++
		}
	}

	// We expect exactly uniquePeers (10) true results
	// The Throttler's mutex ensures thread-safe access, so only the first
	// call for each peer_id should return true
	if trueCount != uniquePeers {
		t.Errorf("expected exactly %d true results (one per unique peer_id), got %d", uniquePeers, trueCount)
	}
}

// TestNewThrottler tests the constructor.
func TestNewThrottler(t *testing.T) {
	throttler := NewThrottler(30)
	if throttler == nil {
		t.Fatal("expected non-nil throttler")
	}
	if throttler.throttleMins != 30 {
		t.Errorf("expected throttle minutes 30, got %d", throttler.throttleMins)
	}
	if throttler.entries == nil {
		t.Error("expected entries map to be initialized")
	}
}

// TestThrottleWindow_Zero tests that zero throttle window allows all alerts.
func TestThrottleWindow_Zero(t *testing.T) {
	throttler := NewThrottler(0) // 0 minute window - no throttling

	// All calls should return true
	for i := 0; i < 5; i++ {
		got := throttler.ShouldSend("test_alert", 1)
		if !got {
			t.Errorf("iteration %d: expected ShouldSend with zero window to return true, got false", i)
		}
	}
}

// TestShouldSend_GlobalAlert tests global alerts (peer_id = 0).
func TestShouldSend_GlobalAlert(t *testing.T) {
	now := time.Now()
	throttler := NewThrottlerWithNow(15, func() time.Time {
		return now
	})

	// Global alert (peer_id = 0) should work the same
	first := throttler.ShouldSend("blocked_spike", 0)
	if !first {
		t.Error("expected first global alert to return true, got false")
	}

	// Second global alert should be throttled
	second := throttler.ShouldSend("blocked_spike", 0)
	if second {
		t.Error("expected second global alert to return false (throttled), got true")
	}
}

// TestShouldSend_EdgeCases tests boundary conditions for alert types and peer IDs.
func TestShouldSend_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		alertType string
		peerID    int
	}{
		{
			name:      "negative_peer_id",
			alertType: "peer_offline",
			peerID:    -1,
		},
		{
			name:      "very_large_peer_id",
			alertType: "peer_offline",
			peerID:    1000000,
		},
		{
			name:      "empty_alert_type",
			alertType: "",
			peerID:    1,
		},
		{
			name:      "unicode_alert_type",
			alertType: "防火墙_警报", // Chinese characters for "firewall_alert"
			peerID:    1,
		},
		{
			name:      "emoji_in_alert_type",
			alertType: "alert_🚨_test",
			peerID:    1,
		},
		{
			name:      "negative_peer_id_with_empty_type",
			alertType: "",
			peerID:    -999,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			throttler := NewThrottler(15)

			// First call should always return true regardless of inputs
			got := throttler.ShouldSend(tt.alertType, tt.peerID)
			if !got {
				t.Errorf("expected first ShouldSend to return true for alertType=%q peerID=%d, got false", tt.alertType, tt.peerID)
			}

			// Second call with same parameters should be throttled
			got = throttler.ShouldSend(tt.alertType, tt.peerID)
			if got {
				t.Errorf("expected second ShouldSend to return false (throttled) for alertType=%q peerID=%d, got true", tt.alertType, tt.peerID)
			}

			// Different peerID with same alertType should not be throttled
			got = throttler.ShouldSend(tt.alertType, tt.peerID+1)
			if !got {
				t.Errorf("expected ShouldSend to return true for different peerID with alertType=%q, got false", tt.alertType)
			}
		})
	}
}
