// Package alerts provides alert condition evaluation functionality.
package alerts

import (
	"context"
	"strconv"
	"testing"
	"time"

	"runic/internal/db"
	"runic/internal/testutil"
)

// TestCheckPeerOffline tests the CheckPeerOffline helper method.
func TestCheckPeerOffline(t *testing.T) {
	database, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	databaseWrapper := db.New(database)
	evaluator := NewConditionEvaluator(databaseWrapper)

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

		isOffline, duration := evaluator.CheckPeerOffline(ctx, strconv.FormatInt(peerID, 10))
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

		isOffline, duration := evaluator.CheckPeerOffline(ctx, strconv.FormatInt(peerID, 10))
		if !isOffline {
			t.Error("expected offline peer to return true for isOffline")
		}
		if duration < time.Hour {
			t.Errorf("expected duration >= 1 hour, got %v", duration)
		}
	})

	// Test 3: Peer doesn't exist (returns false)
	t.Run("peer does not exist", func(t *testing.T) {
		isOffline, duration := evaluator.CheckPeerOffline(ctx, "99999")
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

		isOffline, duration := evaluator.CheckPeerOffline(ctx, strconv.FormatInt(peerID, 10))
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
	evaluator := NewConditionEvaluator(databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"test-peer", "10.0.0.1", "key", "hmac", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()
	peerIDStr := strconv.FormatInt(peerID, 10)

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

		hasFailed, err := evaluator.CheckBundleFailed(ctx, peerIDStr)
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

		hasFailed, err := evaluator.CheckBundleFailed(ctx, peerIDStr)
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
		oldPeerIDStr := strconv.FormatInt(oldPeerID, 10)

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

		hasFailed, err := evaluator.CheckBundleFailed(ctx, oldPeerIDStr)
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
	evaluator := NewConditionEvaluator(databaseWrapper)

	// Insert a peer for testing
	result, err := database.Exec(
		"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, status) VALUES (?, ?, ?, ?, ?)",
		"test-peer", "10.0.0.1", "key", "hmac", "online",
	)
	if err != nil {
		t.Fatalf("failed to insert peer: %v", err)
	}
	peerID, _ := result.LastInsertId()
	peerIDStr := strconv.FormatInt(peerID, 10)

	// Test 1: No blocked traffic (returns false, 0)
	t.Run("no blocked traffic", func(t *testing.T) {
		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, peerIDStr)
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

		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, peerIDStr)
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
		baselinePeerIDStr := strconv.FormatInt(baselinePeerID, 10)

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

		isSpike, percentage, err := evaluator.CheckBlockedSpike(ctx, baselinePeerIDStr)
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
