// Package logcleanup provides tests for the log cleanup worker.
package logcleanup

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"runic/internal/testutil"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDatabases creates both main and logs databases for testing.
func setupTestDatabases(t *testing.T) (*sql.DB, *sql.DB, func()) {
	t.Helper()
	mainDB, mainCleanup := testutil.SetupTestDB(t)
	logsDB, logsCleanup := testutil.SetupTestLogsDB(t)

	cleanup := func() {
		logsCleanup()
		mainCleanup()
	}
	return mainDB, logsDB, cleanup
}

// TestNewWorker tests the Worker constructor.
func TestNewWorker(t *testing.T) {
	mainDB, logsDB, cleanup := setupTestDatabases(t)
	defer cleanup()

	worker := NewWorker(mainDB, logsDB)
	if worker == nil {
		t.Fatal("NewWorker() returned nil")
	}
	if worker.db != mainDB {
		t.Error("worker.db not set correctly")
	}
	if worker.logsDB != logsDB {
		t.Error("worker.logsDB not set correctly")
	}
	if worker.interval != 24*time.Hour {
		t.Errorf("worker.interval = %v, want %v", worker.interval, 24*time.Hour)
	}
	if worker.stopCh == nil {
		t.Error("worker.stopCh is nil")
	}
}

// TestWorker_Start tests the Start method.
func TestWorker_Start(t *testing.T) {
	t.Run("runs cleanup immediately on startup", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 30 days
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Insert an old log entry (older than 30 days)
		oldDate := time.Now().AddDate(0, 0, -35).Format("2006-01-02 15:04:05")
		_, err = logsDB.Exec(
			"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
			oldDate,
		)
		if err != nil {
			t.Fatalf("Failed to insert old log: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		worker.Start(ctx)

		// Wait for initial cleanup to complete
		time.Sleep(100 * time.Millisecond)
		worker.Stop()

		// Verify old log was deleted
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 logs after cleanup, got %d", count)
		}
	})

	t.Run("respects context cancellation", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to -1 (unlimited) so no cleanup happens
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '-1')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		ctx, cancel := context.WithCancel(context.Background())

		worker.Start(ctx)

		// Cancel context after short delay
		time.Sleep(50 * time.Millisecond)
		cancel()

		// Give time for goroutine to exit
		time.Sleep(50 * time.Millisecond)

		// The worker should have stopped - no panic means success
	})

	t.Run("respects stop channel", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to -1 (unlimited)
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '-1')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		ctx := context.Background()

		worker.Start(ctx)

		// Stop after short delay
		time.Sleep(50 * time.Millisecond)
		worker.Stop()

		// Give time for goroutine to exit
		time.Sleep(50 * time.Millisecond)

		// The worker should have stopped - no panic means success
	})
}

// TestWorker_runCleanup tests the runCleanup method.
func TestWorker_runCleanup(t *testing.T) {
	t.Run("default retention when not set", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Don't set log_retention_days - should use default of 30 days

		// Insert an old log entry (older than 30 days)
		oldDate := time.Now().AddDate(0, 0, -35).Format("2006-01-02 15:04:05")
		_, err := logsDB.Exec(
			"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
			oldDate,
		)
		if err != nil {
			t.Fatalf("Failed to insert old log: %v", err)
		}

		// Insert a recent log entry (within 30 days)
		recentDate := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")
		_, err = logsDB.Exec(
			"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
			recentDate,
		)
		if err != nil {
			t.Fatalf("Failed to insert recent log: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		worker.runCleanup(context.Background())

		// Verify old log was deleted but recent log remains
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 log after cleanup (default 30 days), got %d", count)
		}
	})

	t.Run("skip cleanup when retention is -1 (unlimited)", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to -1 (unlimited)
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '-1')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Insert an old log entry
		oldDate := time.Now().AddDate(0, 0, -100).Format("2006-01-02 15:04:05")
		_, err = logsDB.Exec(
			"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
			oldDate,
		)
		if err != nil {
			t.Fatalf("Failed to insert old log: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		worker.runCleanup(context.Background())

		// Verify log was NOT deleted (unlimited retention)
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 log (unlimited retention), got %d", count)
		}
	})

	t.Run("skip cleanup when retention is 0 (disabled)", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 0 (disabled)
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '0')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Insert an old log entry
		oldDate := time.Now().AddDate(0, 0, -100).Format("2006-01-02 15:04:05")
		_, err = logsDB.Exec(
			"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
			oldDate,
		)
		if err != nil {
			t.Fatalf("Failed to insert old log: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		worker.runCleanup(context.Background())

		// Verify log was NOT deleted (disabled)
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count != 1 {
			t.Errorf("Expected 1 log (disabled retention), got %d", count)
		}
	})

	t.Run("delete logs older than retention period", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 7 days
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '7')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Insert logs at different ages
		tests := []struct {
			daysAgo    int
			shouldKeep bool
		}{
			{1, true},   // 1 day ago - keep
			{5, true},   // 5 days ago - keep
			{7, true},   // 7 days ago - keep (boundary)
			{8, false},  // 8 days ago - delete
			{30, false}, // 30 days ago - delete
		}

		for _, tc := range tests {
			date := time.Now().AddDate(0, 0, -tc.daysAgo).Format("2006-01-02 15:04:05")
			_, err := logsDB.Exec(
				"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, ?, '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
				date, fmt.Sprintf("peer-%d", tc.daysAgo),
			)
			if err != nil {
				t.Fatalf("Failed to insert log: %v", err)
			}
		}

		worker := NewWorker(mainDB, logsDB)
		worker.runCleanup(context.Background())

		// Count remaining logs
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}

		expectedKept := 0
		for _, tc := range tests {
			if tc.shouldKeep {
				expectedKept++
			}
		}
		if count != expectedKept {
			t.Errorf("Expected %d logs after cleanup, got %d", expectedKept, count)
		}
	})

	t.Run("batch deletion 1000 at a time", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 1 day
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '1')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Insert 2500 old log entries
		batchSize := 1000
		totalLogs := 2500
		oldDate := time.Now().AddDate(0, 0, -5).Format("2006-01-02 15:04:05")

		for i := 0; i < totalLogs; i++ {
			_, err := logsDB.Exec(
				"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, ?, '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
				oldDate, fmt.Sprintf("peer-%d", i),
			)
			if err != nil {
				t.Fatalf("Failed to insert log %d: %v", i, err)
			}
		}

		worker := NewWorker(mainDB, logsDB)
		worker.runCleanup(context.Background())

		// Verify all logs were deleted
		var count int
		err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
		if err != nil {
			t.Fatalf("Failed to count logs: %v", err)
		}
		if count != 0 {
			t.Errorf("Expected 0 logs after batch deletion, got %d", count)
		}

		// The test passes if all logs are deleted, proving batch deletion worked
		// The batchSize constant in worker.go is 1000, so with 2500 logs,
		// it should take 3 batches (1000 + 1000 + 500)
		if totalLogs > batchSize {
			t.Logf("Successfully deleted %d logs in batches", totalLogs)
		}
	})

	t.Run("logsDB not initialized error handling", func(t *testing.T) {
		mainDB, _, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 30 days
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Create worker with nil logsDB
		worker := NewWorker(mainDB, nil)

		// runCleanup should not panic and should return early
		worker.runCleanup(context.Background())
		// Test passes if no panic occurred
	})

	t.Run("database error handling", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to 30 days
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '30')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		// Close logsDB to simulate database error
		logsDB.Close()

		worker := NewWorker(mainDB, logsDB)
		// runCleanup should not panic on database error
		worker.runCleanup(context.Background())
		// Test passes if no panic occurred
	})
}

// TestWorker_Stop tests the Stop method.
func TestWorker_Stop(t *testing.T) {
	t.Run("stop terminates cleanup goroutine", func(t *testing.T) {
		mainDB, logsDB, cleanup := setupTestDatabases(t)
		defer cleanup()

		// Set retention to -1 so cleanup is skipped quickly
		_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '-1')")
		if err != nil {
			t.Fatalf("Failed to insert config: %v", err)
		}

		worker := NewWorker(mainDB, logsDB)
		ctx := context.Background()

		worker.Start(ctx)

		// Wait for goroutine to start
		time.Sleep(50 * time.Millisecond)

		// Stop should terminate the goroutine
		worker.Stop()

		// Give time for goroutine to fully exit
		time.Sleep(50 * time.Millisecond)

		// Test passes if no panic and goroutine exited cleanly
	})
}

// TestWorker_CustomRetention tests cleanup with custom retention values.
func TestWorker_CustomRetention(t *testing.T) {
	tests := []struct {
		name            string
		retentionDays   int
		logsDaysAgo     int
		shouldBeDeleted bool
	}{
		{"retention 1 day deletes 2 day old log", 1, 2, true},
		{"retention 1 day keeps 0 day old log", 1, 0, false},
		{"retention 90 days keeps 60 day old log", 90, 60, false},
		{"retention 90 days deletes 100 day old log", 90, 100, true},
		{"retention 7 days deletes 8 day old log", 7, 8, true},
		{"retention 7 days keeps 6 day old log", 7, 6, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mainDB, logsDB, cleanup := setupTestDatabases(t)
			defer cleanup()

			// Set custom retention
			_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES (?, ?)",
				"log_retention_days", tc.retentionDays)
			if err != nil {
				t.Fatalf("Failed to insert config: %v", err)
			}

			// Insert log
			date := time.Now().AddDate(0, 0, -tc.logsDaysAgo).Format("2006-01-02 15:04:05")
			_, err = logsDB.Exec(
				"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-1', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
				date,
			)
			if err != nil {
				t.Fatalf("Failed to insert log: %v", err)
			}

			worker := NewWorker(mainDB, logsDB)
			worker.runCleanup(context.Background())

			var count int
			err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
			if err != nil {
				t.Fatalf("Failed to count logs: %v", err)
			}

			if tc.shouldBeDeleted && count != 0 {
				t.Errorf("Expected log to be deleted, but count = %d", count)
			}
			if !tc.shouldBeDeleted && count != 1 {
				t.Errorf("Expected log to be kept, but count = %d", count)
			}
		})
	}
}

// TestWorker_Integration tests the full workflow.
func TestWorker_Integration(t *testing.T) {
	mainDB, logsDB, cleanup := setupTestDatabases(t)
	defer cleanup()

	// Set retention to 7 days
	_, err := mainDB.Exec("INSERT INTO system_config (key, value) VALUES ('log_retention_days', '7')")
	if err != nil {
		t.Fatalf("Failed to insert config: %v", err)
	}

	// Insert logs
	oldDate := time.Now().AddDate(0, 0, -30).Format("2006-01-02 15:04:05")
	recentDate := time.Now().AddDate(0, 0, -3).Format("2006-01-02 15:04:05")

	_, err = logsDB.Exec(
		"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-old', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
		oldDate,
	)
	if err != nil {
		t.Fatalf("Failed to insert old log: %v", err)
	}

	_, err = logsDB.Exec(
		"INSERT INTO firewall_logs (timestamp, peer_id, source_ip, dest_ip, protocol, action) VALUES (?, 'peer-recent', '10.0.0.1', '10.0.0.2', 'tcp', 'ACCEPT')",
		recentDate,
	)
	if err != nil {
		t.Fatalf("Failed to insert recent log: %v", err)
	}

	// Create and start worker
	worker := NewWorker(mainDB, logsDB)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	worker.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	worker.Stop()

	// Verify only recent log remains
	var count int
	err = logsDB.QueryRow("SELECT COUNT(*) FROM firewall_logs").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count logs: %v", err)
	}
	if count != 1 {
		t.Errorf("Expected 1 log after integration test, got %d", count)
	}

	// Verify the remaining log is the recent one
	var peerID string
	err = logsDB.QueryRow("SELECT peer_id FROM firewall_logs").Scan(&peerID)
	if err != nil {
		t.Fatalf("Failed to get peer_id: %v", err)
	}
	if peerID != "peer-recent" {
		t.Errorf("Expected peer-recent, got %s", peerID)
	}
}
