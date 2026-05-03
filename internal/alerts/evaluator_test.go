// Package alerts provides alert condition evaluation functionality.
package alerts

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/store"
	"runic/internal/testutil"
)

// TestCheckPeerOffline tests the CheckPeerOffline helper method.
func TestCheckPeerOffline(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper)

	// Test 1: Peer is online (returns false)
	t.Run("peer is online", func(t *testing.T) {
		result, err := database.Exec(
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
			"online-peer", "10.0.0.1", "key1", "hmac1", "online",
		)
		if err != nil {
			t.Fatalf("failed to insert online peer: %v", err)
		}
		peerID, _ := result.LastInsertId()

		isOffline, duration := evaluator.CheckPeerOffline(ctx, int(peerID))
		if isOffline {
			t.Error("expected online peer to return false for isOffline")
		}
		if duration != 0 {
			t.Errorf("expected duration 0 for online peer, got %v", duration)
		}
	})

	// Test 2: Peer is offline (returns true with duration)
	t.Run("peer is offline", func(t *testing.T) {
		offlineTime := time.Now().Add(-1 * time.Hour)
		result, err := database.Exec(
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status, last_heartbeat) VALUES (?, ?, ?, ?, ?, ?)",
			"offline-peer", "10.0.0.2", "key2", "hmac2", "offline", offlineTime,
		)
		if err != nil {
			t.Fatalf("failed to insert offline peer: %v", err)
		}
		peerID, _ := result.LastInsertId()

		isOffline, duration := evaluator.CheckPeerOffline(ctx, int(peerID))
		if !isOffline {
			t.Error("expected offline peer to return true for isOffline")
		}
		if duration < time.Hour {
			t.Errorf("expected duration >= 1 hour, got %v", duration)
		}
	})

	// Test 3: Peer doesn't exist (returns false)
	t.Run("peer does not exist", func(t *testing.T) {
		isOffline, duration := evaluator.CheckPeerOffline(ctx, 99999)
		if isOffline {
			t.Error("expected non-existent peer to return false for isOffline")
		}
		if duration != 0 {
			t.Errorf("expected duration 0 for non-existent peer, got %v", duration)
		}
	})

	// Test 4: Peer with no heartbeat (uses default duration)
	t.Run("peer with no heartbeat", func(t *testing.T) {
		result, err := database.Exec(
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
			"no-heartbeat-peer", "10.0.0.3", "key3", "hmac3", "offline",
		)
		if err != nil {
			t.Fatalf("failed to insert peer with no heartbeat: %v", err)
		}
		peerID, _ := result.LastInsertId()

		isOffline, duration := evaluator.CheckPeerOffline(ctx, int(peerID))
		if !isOffline {
			t.Error("expected offline peer with no heartbeat to return true for isOffline")
		}
		// Default duration is 24 hours when no heartbeat is present
		if duration < 23*time.Hour {
			t.Errorf("expected duration >= 23 hours (default), got %v", duration)
		}
	})
}

// TestCheckBundleFailed tests the CheckBundleFailed helper method.
func TestCheckBundleFailed(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"test-peer", "10.0.0.1", "key", "hmac", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()

	// Test 1: No failures (returns false)
	t.Run("no failures", func(t *testing.T) {
		// Create a push job but no failures
		_, err := database.Exec(
			"INSERT INTO push_jobs (id, initiated_by, total_peers, status) VALUES (?, ?, ?, ?)",
			"job-no-fail", "admin", 1, "completed",
		)
		if err != nil {
			t.Fatalf("failed to insert push job: %v", err)
		}

		hasFailed, err := evaluator.CheckBundleFailed(ctx, int(peerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasFailed {
			t.Error("expected no bundle failures, but got true")
		}
	})

	// Test 2: Recent failures exist (returns true)
	t.Run("recent failures exist", func(t *testing.T) {
		// Create a push job
		_, err := database.Exec(
			"INSERT INTO push_jobs (id, initiated_by, total_peers, status, created_at) VALUES (?, ?, ?, ?, ?)",
			"job-with-fail", "admin", 1, "completed_with_errors", time.Now().Add(-30*time.Minute),
		)
		if err != nil {
			t.Fatalf("failed to insert push job: %v", err)
		}

		// Create a failed push job peer entry
		_, err = database.Exec(
			"INSERT INTO push_job_peers (job_id, peer_id, peer_hostname, status, error_message) VALUES (?, ?, ?, ?, ?)",
			"job-with-fail", peerID, "test-peer", "failed", "bundle generation failed",
		)
		if err != nil {
			t.Fatalf("failed to insert push job peer: %v", err)
		}

		hasFailed, err := evaluator.CheckBundleFailed(ctx, int(peerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !hasFailed {
			t.Error("expected bundle failures to be detected, but got false")
		}
	})

	// Test 3: Old failures outside window (returns false)
	t.Run("old failures outside window", func(t *testing.T) {
		// Create a peer for this test
		result, err := database.Exec(
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
			"old-failure-peer", "10.0.0.2", "key2", "hmac2", "online",
		)
		if err != nil {
			t.Fatalf("failed to insert peer: %v", err)
		}
		oldPeerID, _ := result.LastInsertId()

		// Create a push job older than 1 hour (the CheckBundleFailed window)
		_, err = database.Exec(
			"INSERT INTO push_jobs (id, initiated_by, total_peers, status, created_at) VALUES (?, ?, ?, ?, ?)",
			"old-job", "admin", 1, "completed_with_errors", time.Now().Add(-2*time.Hour),
		)
		if err != nil {
			t.Fatalf("failed to insert old push job: %v", err)
		}

		// Create a failed push job peer entry (but it's old)
		_, err = database.Exec(
			"INSERT INTO push_job_peers (job_id, peer_id, peer_hostname, status, error_message) VALUES (?, ?, ?, ?, ?)",
			"old-job", oldPeerID, "old-failure-peer", "failed", "old failure",
		)
		if err != nil {
			t.Fatalf("failed to insert old push job peer: %v", err)
		}

		hasFailed, err := evaluator.CheckBundleFailed(ctx, int(oldPeerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if hasFailed {
			t.Error("expected no bundle failures for old failures outside window, but got true")
		}
	})
}

// TestCheckBlockedSpike tests the CheckBlockedSpike helper method.
func TestCheckBlockedSpike(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"test-peer", "10.0.0.1", "key", "hmac", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()

	// Test 1: No blocked traffic (returns false, 0)
	t.Run("no blocked traffic", func(t *testing.T) {
		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, int(peerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if isSpike {
			t.Error("expected no spike when there's no blocked traffic")
		}
		if percentage != 0 {
			t.Errorf("expected percentage 0, got %d", percentage)
		}
	})

	// Test 2: Spike detected (returns true with percentage)
	t.Run("spike detected", func(t *testing.T) {
		// Insert previous blocked traffic (5-10 minutes ago)
		for i := 0; i < 5; i++ {
			_, err := database.Exec(
				"INSERT INTO firewall_logs (peer_id, action, timestamp, src_ip, dst_ip, protocol) VALUES (?, ?, ?, ?, ?, ?)",
				peerID, "DROP", time.Now().Add(-7*time.Minute), "192.168.1.1", "10.0.0.1", "tcp",
			)
			if err != nil {
				t.Fatalf("failed to insert previous firewall log: %v", err)
			}
		}

		// Insert recent blocked traffic (last 5 minutes) - much higher count to create a spike
		for i := 0; i < 50; i++ {
			_, err := database.Exec(
				"INSERT INTO firewall_logs (peer_id, action, timestamp, src_ip, dst_ip, protocol) VALUES (?, ?, ?, ?, ?, ?)",
				peerID, "DROP", time.Now().Add(-2*time.Minute), "192.168.1.1", "10.0.0.1", "tcp",
			)
			if err != nil {
				t.Fatalf("failed to insert recent firewall log: %v", err)
			}
		}

		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, int(peerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !isSpike {
			t.Error("expected spike to be detected")
		}
		if percentage < 50 {
			t.Errorf("expected percentage >= 50 for spike, got %d", percentage)
		}
	})

	// Test 3: No previous traffic baseline
	t.Run("no previous traffic baseline", func(t *testing.T) {
		// Create a new peer for this test
		result, err := database.Exec(
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
			"baseline-peer", "10.0.0.2", "key2", "hmac2", "online",
		)
		if err != nil {
			t.Fatalf("failed to insert peer: %v", err)
		}
		baselinePeerID, _ := result.LastInsertId()

		// Insert more than 10 recent blocked entries (should trigger spike detection)
		for i := 0; i < 15; i++ {
			_, err := database.Exec(
				"INSERT INTO firewall_logs (peer_id, action, timestamp, src_ip, dst_ip, protocol) VALUES (?, ?, ?, ?, ?, ?)",
				baselinePeerID, "LOG_DROP", time.Now().Add(-2*time.Minute), "192.168.1.1", "10.0.0.2", "tcp",
			)
			if err != nil {
				t.Fatalf("failed to insert firewall log: %v", err)
			}
		}

		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, int(baselinePeerID))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// With no previous traffic and > 10 recent blocked, should return true with 100%
		if !isSpike {
			t.Error("expected spike to be detected with no previous baseline and > 10 recent blocked")
		}
		if percentage != 100 {
			t.Errorf("expected percentage 100 for no baseline with significant traffic, got %d", percentage)
		}
	})
}

// TestEvaluateBundleDeployed_FirstAppliedAt tests that evaluateBundleDeployed
// uses first_applied_at (not applied_at) to determine if a bundle was newly
// deployed, preventing duplicate alerts when a bundle is re-applied.
func TestEvaluateBundleDeployed_FirstAppliedAt(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	evaluator := NewConditionEvaluator(databaseWrapper, databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"bundle-peer", "10.0.0.10", "key-bd", "hmac-bd", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()

	// Create an alert rule for bundle_deployed with a 60-minute window
	rule := &AlertRule{
		Name:                   "Bundle Deployed Rule",
		AlertType:              AlertTypeBundleDeployed,
		Enabled:                true,
		ThresholdWindowMinutes: 60,
		ThrottleMinutes:        5,
		PeerID:                 intPtr(int(peerID)),
	}

	// --- Sub-test 1: First deployment triggers an alert ---
	t.Run("first deployment triggers alert", func(t *testing.T) {
		now := time.Now().Truncate(time.Second)

		// Insert a rule bundle with first_applied_at = now (recently deployed)
		_, err := database.Exec(
			"INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, applied_at, first_applied_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			peerID, "v1.0", 1, "{}", "hmactest", now, now,
		)
		if err != nil {
			t.Fatalf("failed to insert rule bundle: %v", err)
		}

		triggered, event, err := evaluator.EvaluateRule(ctx, rule)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !triggered {
			t.Error("expected alert to be triggered for newly deployed bundle")
		}
		if event != nil && event.Type != AlertTypeBundleDeployed {
			t.Errorf("expected event type %s, got %s", AlertTypeBundleDeployed, event.Type)
		}
	})

	// --- Sub-test 2: Re-apply does NOT re-trigger alert ---
	t.Run("re-apply does not re-trigger alert", func(t *testing.T) {
		// First, record that an alert was already sent (simulate alert_history entry)
		// This simulates the alert that was triggered in sub-test 1
		_, err := database.Exec(
			"INSERT INTO alert_history (rule_id, alert_type, peer_id, severity, subject, message, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			0, AlertTypeBundleDeployed, peerID, "info", "Bundle deployed", "Bundle deployed", "sent", time.Now(),
		)
		if err != nil {
			t.Fatalf("failed to insert alert history: %v", err)
		}

		// Now update the bundle's applied_at (simulating a re-apply) but leave first_applied_at unchanged
		laterTime := time.Now().Truncate(time.Second)
		_, err = database.Exec(
			"UPDATE rule_bundles SET applied_at = ? WHERE peer_id = ? AND version = ?",
			laterTime, peerID, "v1.0",
		)
		if err != nil {
			t.Fatalf("failed to update bundle applied_at: %v", err)
		}

		// Verify first_applied_at was NOT changed
		var firstAppliedAt sql.NullTime
		err = database.QueryRow(
			"SELECT first_applied_at FROM rule_bundles WHERE peer_id = ? AND version = ?",
			peerID, "v1.0",
		).Scan(&firstAppliedAt)
		if err != nil {
			t.Fatalf("failed to query first_applied_at: %v", err)
		}
		if !firstAppliedAt.Valid {
			t.Fatal("expected first_applied_at to be set, but got NULL")
		}

		// Evaluate again — should NOT trigger because:
		// 1) first_applied_at is still the old time (within window, but alert_history exists)
		// 2) The NOT EXISTS subquery finds the alert_history entry we inserted
		triggered, _, err := evaluator.EvaluateRule(ctx, rule)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if triggered {
			t.Error("expected alert NOT to be re-triggered for re-applied bundle (alert already sent)")
		}
	})

	// --- Sub-test 3: Old first_applied_at outside window does not trigger ---
	t.Run("old first_applied_at outside window does not trigger", func(t *testing.T) {
		// Clean up previous data for this sub-test
		database.Exec("DELETE FROM alert_history")
		database.Exec("DELETE FROM rule_bundles WHERE peer_id = ?", peerID)

		// Insert a bundle with first_applied_at well outside the 60-minute window.
		// Use local time consistently to avoid UTC/local timezone comparison issues
		// in SQLite DATETIME string comparisons.
		oldTime := time.Now().Add(-2 * time.Hour).Truncate(time.Second)
		now := time.Now().Truncate(time.Second)
		_, err := database.Exec(
			"INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, applied_at, first_applied_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			peerID, "v2.0", 2, "{}", "hmactest2", now, oldTime,
		)
		if err != nil {
			t.Fatalf("failed to insert old rule bundle: %v", err)
		}

		// The first_applied_at is 2 hours ago, which is outside the 60-minute window.
		// Even though applied_at is recent, this should NOT trigger an alert.
		triggered, _, err := evaluator.EvaluateRule(ctx, rule)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if triggered {
			t.Error("expected alert NOT to be triggered for bundle with old first_applied_at outside window")
		}
	})

	// --- Sub-test 4: New bundle deployment (different version) does trigger ---
	t.Run("new bundle version triggers alert", func(t *testing.T) {
		// Clean up previous data for this sub-test
		database.Exec("DELETE FROM alert_history")
		database.Exec("DELETE FROM rule_bundles WHERE peer_id = ?", peerID)

		// Insert a fresh bundle with first_applied_at = now
		now := time.Now().Truncate(time.Second)
		_, err := database.Exec(
			"INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, applied_at, first_applied_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
			peerID, "v3.0", 3, "{}", "hmactest3", now, now,
		)
		if err != nil {
			t.Fatalf("failed to insert new rule bundle: %v", err)
		}

		triggered, event, err := evaluator.EvaluateRule(ctx, rule)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !triggered {
			t.Error("expected alert to be triggered for newly deployed bundle")
		}
		if event != nil && event.PeerName != "bundle-peer" {
			t.Errorf("expected peer name 'bundle-peer', got %s", event.PeerName)
		}
	})
}

// TestUpdateBundleAppliedAt_COALESCE tests that the COALESCE logic in
// UpdateBundleAppliedAt preserves first_applied_at when a bundle is
// re-applied, while updating applied_at.
func TestUpdateBundleAppliedAt_COALESCE(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	peerStore := store.NewPeerStore(databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"coalesce-peer", "10.0.0.20", "key-co", "hmac-co", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()

	// Step 1: Insert a bundle with both applied_at and first_applied_at set
	firstAppliedTime := time.Now().Add(-1 * time.Hour).Truncate(time.Second)
	initialAppliedTime := firstAppliedTime // Same initially
	_, err = database.Exec(
		"INSERT INTO rule_bundles (peer_id, version, version_number, rules_content, hmac, applied_at, first_applied_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		peerID, "v1.0", 1, "{}", "hmactest", initialAppliedTime, firstAppliedTime,
	)
	if err != nil {
		t.Fatalf("failed to insert rule bundle: %v", err)
	}

	// Step 2: Call UpdateBundleAppliedAt to simulate a re-apply
	reAppliedTime := time.Now().Truncate(time.Second)
	err = peerStore.UpdateBundleAppliedAt(ctx, int(peerID), "v1.0", reAppliedTime.Format(time.RFC3339))
	if err != nil {
		t.Fatalf("failed to update bundle applied_at: %v", err)
	}

	// Step 3: Verify first_applied_at is UNCHANGED and applied_at is UPDATED
	var storedAppliedAt sql.NullTime
	var storedFirstAppliedAt sql.NullTime
	err = database.QueryRow(
		"SELECT applied_at, first_applied_at FROM rule_bundles WHERE peer_id = ? AND version = ?",
		peerID, "v1.0",
	).Scan(&storedAppliedAt, &storedFirstAppliedAt)
	if err != nil {
		t.Fatalf("failed to query rule bundle: %v", err)
	}

	if !storedFirstAppliedAt.Valid {
		t.Fatal("expected first_applied_at to be set, but got NULL")
	}
	if !storedAppliedAt.Valid {
		t.Fatal("expected applied_at to be set, but got NULL")
	}

	// first_applied_at should remain at the original time
	if storedFirstAppliedAt.Time.Unix() != firstAppliedTime.Unix() {
		t.Errorf("expected first_applied_at to be %v, got %v (COALESCE should preserve original value)",
			firstAppliedTime, storedFirstAppliedAt.Time)
	}

	// applied_at should be updated to the new re-apply time
	if storedAppliedAt.Time.Unix() != reAppliedTime.Unix() {
		t.Errorf("expected applied_at to be %v, got %v",
			reAppliedTime, storedAppliedAt.Time)
	}
}
