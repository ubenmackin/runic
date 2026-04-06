package pending

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"runic/internal/engine"
	"runic/internal/testutil"
)

// muxVars is a helper to set gorilla/mux URL variables
var muxVars = testutil.MuxVars

// =============================================================================
// Test ListPendingChanges
// =============================================================================

func TestListPendingChanges_EmptyTable(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Create handler with nil for optional dependencies
	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []peerChangeGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(groups) != 0 {
		t.Errorf("expected empty groups list, got %d groups", len(groups))
	}
}

func TestListPendingChanges_WithPeers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Insert pending changes for peer
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy 'test-policy'")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "service", 2, "update", "Update service 'test-service'")

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []peerChangeGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(groups))
	}

	if groups[0].Hostname != "peer-one" {
		t.Errorf("expected hostname 'peer-one', got %s", groups[0].Hostname)
	}

	if groups[0].ChangesCount != 2 {
		t.Errorf("expected changes count 2, got %d", groups[0].ChangesCount)
	}
}

func TestListPendingChanges_MultiplePeers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peers
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-two", "10.0.0.2", "key2", "hmac2")

	// Insert pending changes for peer 1
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	// Insert pending changes for peer 2
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		2, "service", 1, "delete", "Remove service")

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []peerChangeGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
}

// =============================================================================
// Test GetPeerPendingChanges
// =============================================================================

func TestGetPeerPendingChanges_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/invalid", nil)
	r = muxVars(r, map[string]string{"peerId": "invalid"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestGetPeerPendingChanges_PeerNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/999", nil)
	r = muxVars(r, map[string]string{"peerId": "999"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestGetPeerPendingChanges_NoChanges(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer (no pending changes)
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	changes := response["changes"].([]interface{})
	if len(changes) != 0 {
		t.Errorf("expected empty changes, got %d", len(changes))
	}
}

func TestGetPeerPendingChanges_WithChanges(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Insert pending changes
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy 'test-policy'")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "service", 2, "update", "Update service 'test-service'")

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["hostname"] != "peer-one" {
		t.Errorf("expected hostname 'peer-one', got %s", response["hostname"])
	}

	changes := response["changes"].([]interface{})
	if len(changes) != 2 {
		t.Errorf("expected 2 changes, got %d", len(changes))
	}
}

// =============================================================================
// Test PreviewPeerPendingBundle
// =============================================================================

func TestPreviewPeerPendingBundle_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewCompiler(db)
	handler := NewHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/preview/invalid", nil)
	r = muxVars(r, map[string]string{"peerId": "invalid"})

	handler.PreviewPeerPendingBundle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPreviewPeerPendingBundle_PeerNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewCompiler(db)
	handler := NewHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/preview/999", nil)
	r = muxVars(r, map[string]string{"peerId": "999"})

	handler.PreviewPeerPendingBundle(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPreviewPeerPendingBundle_PeerFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer with required data for bundle compilation
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Insert a group (required for bundle)
	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	// Insert a policy
	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)

	// Insert policy group assignment
	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)

	// Insert peer group assignment
	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)

	compiler := engine.NewCompiler(db)
	handler := NewHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/preview/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.PreviewPeerPendingBundle(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["version"] == nil {
		t.Error("expected version in response")
	}

	if response["rules_content"] == nil {
		t.Error("expected rules_content in response")
	}
}

// =============================================================================
// Test ApplyPeerPendingBundle
// =============================================================================

func TestApplyPeerPendingBundle_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewCompiler(db)
	handler := NewHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply/invalid", nil)
	r = muxVars(r, map[string]string{"peerId": "invalid"})

	handler.ApplyPeerPendingBundle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestApplyPeerPendingBundle_PeerNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewCompiler(db)
	handler := NewHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply/999", nil)
	r = muxVars(r, map[string]string{"peerId": "999"})

	handler.ApplyPeerPendingBundle(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// =============================================================================
// Test ApplyAllPendingBundles
// =============================================================================

func TestApplyAllPendingBundles_NoChanges(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Insert test peer without pending changes
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	handler := NewHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply-all", nil)

	handler.ApplyAllPendingBundles(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["status"] != "no_pending_changes" {
		t.Errorf("expected status 'no_pending_changes', got %s", response["status"])
	}

	if response["applied"].(float64) != 0 {
		t.Errorf("expected applied 0, got %v", response["applied"])
	}
}
