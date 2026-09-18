package testutil

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// WaitForPendingRows polls pending_changes until want rows exist for the given
// policy action, failing the test on timeout. The ChangeWorker processes queue
// entries asynchronously, so handler tests must not assert immediately.
func WaitForPendingRows(t *testing.T, database *sql.DB, policyID int, action string, want int) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		var count int
		if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM pending_changes WHERE change_type = 'policy' AND change_id = ? AND change_action = ?`, policyID, action).Scan(&count); err != nil {
			t.Fatalf("count pending_changes failed: %v", err)
		}
		if count == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for pending_changes: policy=%d action=%q want=%d got=%d", policyID, action, want, count)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// PendingPeerIDs returns the ordered peer IDs with pending rows for the given
// policy action.
func PendingPeerIDs(t *testing.T, database *sql.DB, policyID int, action string) []int {
	t.Helper()
	ctx := context.Background()
	rows, err := database.QueryContext(ctx, `SELECT peer_id FROM pending_changes WHERE change_type = 'policy' AND change_id = ? AND change_action = ? ORDER BY peer_id`, policyID, action)
	if err != nil {
		t.Fatalf("query pending peer ids: %v", err)
	}
	var ids []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			t.Fatalf("scan pending peer id: %v", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		t.Fatalf("rows error: %v", err)
	}
	if err := rows.Close(); err != nil {
		t.Fatalf("close pending peer rows: %v", err)
	}
	return ids
}
