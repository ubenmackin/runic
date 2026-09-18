package store

import (
	"context"
	"testing"
)

// TestPendingStore_ManualPeerPendingListing verifies that the pending listing
// includes manual peers while the push fan-out stays agent-only.
func TestPendingStore_ManualPeerPendingListing(t *testing.T) {
	store, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	d := store.db
	pendingStore := NewPendingStore(d)

	insertPeer := func(hostname, ip string, isManual int) int {
		t.Helper()
		result, err := d.ExecContext(ctx,
			`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
			hostname, ip, "agent-key-"+hostname, "hmac-key-"+hostname, isManual)
		if err != nil {
			t.Fatalf("insert peer %s: %v", hostname, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("last insert id %s: %v", hostname, err)
		}
		return int(id)
	}

	agentID := insertPeer("agent-peer", "10.0.0.11", 0)
	manualID := insertPeer("manual-peer", "10.0.0.12", 1)

	for _, peerID := range []int{agentID, manualID} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)`,
			peerID, "policy", 7, "create", "policy change"); err != nil {
			t.Fatalf("insert pending change for peer %d: %v", peerID, err)
		}
	}

	ids, err := pendingStore.GetPeersWithPendingChanges(ctx)
	if err != nil {
		t.Fatalf("GetPeersWithPendingChanges failed: %v", err)
	}
	found := map[int]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found[agentID] {
		t.Errorf("agent peer %d missing from GetPeersWithPendingChanges=%v", agentID, ids)
	}
	if !found[manualID] {
		t.Errorf("manual peer %d missing from GetPeersWithPendingChanges=%v", manualID, ids)
	}
	if len(ids) != 2 {
		t.Errorf("GetPeersWithPendingChanges = %v, want exactly 2 peers", ids)
	}

	manualChanges, err := pendingStore.GetPendingChangesForPeer(ctx, manualID)
	if err != nil {
		t.Fatalf("GetPendingChangesForPeer(manual) failed: %v", err)
	}
	if len(manualChanges) != 1 {
		t.Errorf("manual pending changes = %d, want 1", len(manualChanges))
	}

	manualCount, err := pendingStore.CountPendingChangesForPeer(ctx, int64(manualID))
	if err != nil {
		t.Fatalf("CountPendingChangesForPeer(manual) failed: %v", err)
	}
	if manualCount != 1 {
		t.Errorf("manual pending count = %d, want 1", manualCount)
	}

	agentBased, err := store.ListAgentBasedPeers(ctx)
	if err != nil {
		t.Fatalf("ListAgentBasedPeers failed: %v", err)
	}
	for _, p := range agentBased {
		if p.ID == manualID {
			t.Errorf("manual peer %d must stay excluded from ListAgentBasedPeers (push is agent-only)", manualID)
		}
	}
	if len(agentBased) != 1 {
		t.Errorf("ListAgentBasedPeers = %d peers, want 1 (agent only)", len(agentBased))
	}
}
