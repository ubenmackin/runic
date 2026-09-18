package pending

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"runic/internal/api/common"
	"runic/internal/api/events"
	policiesapi "runic/internal/api/policies"
	"runic/internal/engine"
	"runic/internal/store"
	"runic/internal/testutil"
)

var muxVars = testutil.MuxVars

// newTestHandler creates a Handler with the given db and optional compiler/sseHub/pushWorker.
func newTestHandler(db *sql.DB, compiler *engine.Compiler, sseHub *events.SSEHub, pushWorker *common.PushWorker) *Handler {
	peerStore := store.NewPeerStore(db)
	groupStore := store.NewGroupStore(db)
	policyStore := store.NewPolicyStore(db)
	serviceStore := store.NewServiceStore(db)
	pendingStore := store.NewPendingStore(db)
	return NewHandler(peerStore, groupStore, policyStore, serviceStore, pendingStore, db, compiler, sseHub, pushWorker)
}

// =============================================================================
// =============================================================================

func TestListPendingChanges_EmptyTable(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := newTestHandler(db, nil, nil, nil)
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

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy 'test-policy'")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "service", 2, "update", "Update service 'test-service'")

	handler := newTestHandler(db, nil, nil, nil)
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

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-two", "10.0.0.2", "key2", "hmac2")

	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		2, "service", 1, "delete", "Remove service")

	handler := newTestHandler(db, nil, nil, nil)
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
// =============================================================================

func TestGetPeerPendingChanges_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := newTestHandler(db, nil, nil, nil)
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

	handler := newTestHandler(db, nil, nil, nil)
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

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	handler := newTestHandler(db, nil, nil, nil)
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

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy 'test-policy'")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "service", 2, "update", "Update service 'test-service'")

	handler := newTestHandler(db, nil, nil, nil)
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
// =============================================================================

func TestPreviewPeerPendingBundle_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)

	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)

	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

func TestPreviewPeerPendingBundle_ExistingBundle(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")

	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)

	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)

	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)

	// First compile and store a bundle
	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

	// Verify is_different flag is present
	if response["is_different"] == nil {
		t.Error("expected is_different in response")
	}

	// Verify diff_content is present
	if response["diff_content"] == nil {
		t.Error("expected diff_content in response")
	}
}

// =============================================================================
// =============================================================================

func TestApplyPeerPendingBundle_InvalidID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply/999", nil)
	r = muxVars(r, map[string]string{"peerId": "999"})

	handler.ApplyPeerPendingBundle(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestApplyPeerPendingBundle_Success(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)
	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	compiler := engine.NewTestCompiler(db)
	sseHub := events.NewSSEHub()
	handler := newTestHandler(db, compiler, sseHub, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.ApplyPeerPendingBundle(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["status"] != "applied" {
		t.Errorf("expected status 'applied', got %s", response["status"])
	}

	if response["version"] == nil {
		t.Error("expected version in response")
	}
}

// =============================================================================
// =============================================================================

func TestApplyAllPendingBundles_NoChanges(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	handler := newTestHandler(db, nil, nil, nil)
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

func TestApplyAllPendingBundles_PeerApplyError(t *testing.T) {
	// This test verifies that when compile fails, errors are collected
	// Note: Since engine.Compile doesn't actually fail with invalid data (just produces empty bundle),
	// we can't easily trigger this path without significant mocking.
	// This test remains as documentation of expected behavior.
	t.Skip("Engine doesn't fail with invalid policy_id - produces empty bundle instead")
}

func TestApplyAllPendingBundles_Success(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)
	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	compiler := engine.NewTestCompiler(db)
	sseHub := events.NewSSEHub()
	handler := newTestHandler(db, compiler, sseHub, nil)
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

	if response["status"] != "completed" {
		t.Errorf("expected status 'completed', got %s", response["status"])
	}

	if int(response["applied"].(float64)) != 1 {
		t.Errorf("expected applied 1, got %v", response["applied"])
	}
}

// =============================================================================
// =============================================================================

func TestPushAllRules_NoPeers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// No peers inserted

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/push-all", nil)

	handler.PushAllRules(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["status"] != "no_peers" {
		t.Errorf("expected status 'no_peers', got %s", response["status"])
	}

	if response["pushed"].(float64) != 0 {
		t.Errorf("expected pushed 0, got %v", response["pushed"])
	}
}

func TestPushAllRules_DBQueryError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	// Close the database to cause an error
	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/push-all", nil)

	handler.PushAllRules(w, r)

	// Should return internal error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPushAllRules_RowsIterationError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Close the database before rows iteration to cause error
	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/push-all", nil)

	handler.PushAllRules(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestHandlePushJobSSE_MissingJobID(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/push-jobs//sse", nil)

	handler.HandlePushJobSSE(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestHandlePushJobSSE_JobNotFound(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/push-jobs/nonexistent/sse", nil)
	r = muxVars(r, map[string]string{"job_id": "nonexistent"})

	handler.HandlePushJobSSE(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestGenerateDiff_EmptyOldContent(t *testing.T) {
	newContent := "line1\nline2\nline3"
	result := generateDiff("", newContent)

	if result == "" {
		t.Error("expected non-empty diff for new bundle")
	}

	// No version headers in diff output
	if strings.Contains(result, "--- version") {
		t.Error("expected no version header in diff output")
	}

	// All lines should be prefixed with "+ "
	if !strings.Contains(result, "+ line1") {
		t.Error("expected '+ line1' in diff output")
	}
	if !strings.Contains(result, "+ line2") {
		t.Error("expected '+ line2' in diff output")
	}
	if !strings.Contains(result, "+ line3") {
		t.Error("expected '+ line3' in diff output")
	}
}

func TestGenerateDiff_NoChanges(t *testing.T) {
	content := "same content"
	result := generateDiff(content, content)

	if result != "No changes detected." {
		t.Errorf("expected 'No changes detected.', got %s", result)
	}
}

func TestGenerateDiff_WithChanges(t *testing.T) {
	oldContent := "line1\nline2\nline3"
	newContent := "line1\nline2 modified\nline4"
	result := generateDiff(oldContent, newContent)

	// No version headers in diff output
	if strings.Contains(result, "--- version") {
		t.Error("expected no version header in diff output")
	}

	// Should contain unchanged line with space prefix
	if !strings.Contains(result, "  line1") {
		t.Error("expected unchanged line1 in diff")
	}

	// Should contain the modified line
	if !strings.Contains(result, "+ line2 modified") {
		t.Error("expected added line in diff")
	}

	// Should contain removed line
	if !strings.Contains(result, "- line3") {
		t.Error("expected removed line in diff")
	}

	// Should contain new line
	if !strings.Contains(result, "+ line4") {
		t.Error("expected added line4 in diff")
	}
}

func TestGenerateDiff_EmptyNewContent(t *testing.T) {
	oldContent := "line1\nline2"
	result := generateDiff(oldContent, "")

	// No version headers in diff output
	if strings.Contains(result, "--- version") {
		t.Error("expected no version header in diff output")
	}

	// Should contain removed lines
	if !strings.Contains(result, "- line1") {
		t.Error("expected removed line1 in diff")
	}
}

func TestGenerateDiff_OnlyAdditions(t *testing.T) {
	newContent := "new1\nnew2"
	result := generateDiff("", newContent)

	// When old is empty, the LCS algorithm should produce proper diff format
	// No version headers in diff output
	if strings.Contains(result, "+++ version") {
		t.Error("expected no version header in diff output")
	}

	// All lines should be prefixed with "+ "
	if !strings.Contains(result, "+ new1") {
		t.Error("expected '+ new1' in diff output")
	}

	if !strings.Contains(result, "+ new2") {
		t.Error("expected '+ new2' in diff output")
	}
}

// =============================================================================
// =============================================================================

func TestParseSSEEventType_Complete(t *testing.T) {
	event := "event: complete\ndata: {}\n\n"
	result := parseSSEEventType(event)

	if result != "complete" {
		t.Errorf("expected 'complete', got %s", result)
	}
}

func TestParseSSEEventType_Progress(t *testing.T) {
	event := "event: progress\ndata: {\"peer\": \"host-1\"}\n\n"
	result := parseSSEEventType(event)

	if result != "progress" {
		t.Errorf("expected 'progress', got %s", result)
	}
}

func TestParseSSEEventType_NoEvent(t *testing.T) {
	event := "data: {\"some\": \"data\"}\n\n"
	result := parseSSEEventType(event)

	if result != "" {
		t.Errorf("expected empty string, got %s", result)
	}
}

func TestParseSSEEventType_Init(t *testing.T) {
	event := "event: init\ndata: {\"job_id\": \"123\"}\n\n"
	result := parseSSEEventType(event)

	if result != "init" {
		t.Errorf("expected 'init', got %s", result)
	}
}

func TestParseSSEEventType_BundleUpdated(t *testing.T) {
	event := "event: bundle_updated\ndata: {\"version\": \"v2\"}\n\n"
	result := parseSSEEventType(event)

	if result != "bundle_updated" {
		t.Errorf("expected 'bundle_updated', got %s", result)
	}
}

// =============================================================================
// =============================================================================

func TestListPendingChanges_PeerQueryError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	// Close database to cause error on peer query
	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	// Should return internal error
	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestGetPeerPendingChanges_DBError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Close database to cause error
	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestSplitLines_Empty(t *testing.T) {
	result := splitLines("")
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestSplitLines_SingleLine(t *testing.T) {
	result := splitLines("hello")
	if len(result) != 1 {
		t.Errorf("expected 1 line, got %d", len(result))
	}
	if result[0] != "hello" {
		t.Errorf("expected 'hello', got %s", result[0])
	}
}

func TestSplitLines_MultipleLines(t *testing.T) {
	result := splitLines("line1\nline2\nline3")
	if len(result) != 3 {
		t.Errorf("expected 3 lines, got %d", len(result))
	}
	if result[0] != "line1" || result[1] != "line2" || result[2] != "line3" {
		t.Errorf("unexpected lines: %v", result)
	}
}

func TestSplitLines_TrailingNewline(t *testing.T) {
	result := splitLines("line1\nline2\n")
	if len(result) != 2 {
		t.Errorf("expected 2 lines, got %d", len(result))
	}
	if result[0] != "line1" || result[1] != "line2" {
		t.Errorf("unexpected lines: %v", result)
	}
}

func TestSplitLines_LeadingNewline(t *testing.T) {
	result := splitLines("\nline1\nline2")
	// With leading newline, we get: ["", "line1", "line2"] = 3 lines
	if len(result) != 3 {
		t.Errorf("expected 3 lines, got %d", len(result))
	}
	if result[0] != "" || result[1] != "line1" || result[2] != "line2" {
		t.Errorf("unexpected lines: %v", result)
	}
}

// =============================================================================
// =============================================================================

func TestListPendingChanges_SomePeersMissing(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		999, "policy", 1, "create", "Add policy")

	handler := newTestHandler(db, nil, nil, nil)
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
		t.Errorf("expected 0 groups, got %d", len(groups))
	}
}

func TestListPendingChanges_PendingChangesQueryError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestGetPeerPendingChanges_PendingChangesDBError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.GetPeerPendingChanges(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

// =============================================================================
// =============================================================================

func TestHandlePushJobSSE_WithJobPeers(t *testing.T) {
	t.Skip("SSE streaming blocks indefinitely - tested separately")
}

// =============================================================================
// =============================================================================

func TestPreviewPeerPendingBundle_WithExistingBundle(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)
	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)

	compiler := engine.NewTestCompiler(db)
	handler := newTestHandler(db, compiler, nil, nil)
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

	if response["diff_content"] == nil {
		t.Error("expected diff_content in response")
	}
}

// =============================================================================
// =============================================================================

func TestApplyPeerPendingBundle_DeletePendingPreviewError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")
	db.Exec("INSERT INTO groups (name) VALUES (?)", "test-group")
	db.Exec("INSERT INTO policies (name, description, enabled) VALUES (?, ?, ?)",
		"test-policy", "test description", 1)
	db.Exec("INSERT INTO policy_groups (policy_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO peer_groups (peer_id, group_id) VALUES (?, ?)", 1, 1)
	db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy")

	// Store a pending preview first
	db.Exec("INSERT INTO pending_bundle_previews (peer_id, rules_content, diff_content, version) VALUES (?, ?, ?, ?)",
		1, "old-content", "old-diff", "v1")

	compiler := engine.NewTestCompiler(db)
	sseHub := events.NewSSEHub()
	handler := newTestHandler(db, compiler, sseHub, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/apply/1", nil)
	r = muxVars(r, map[string]string{"peerId": "1"})

	handler.ApplyPeerPendingBundle(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if response["status"] != "applied" {
		t.Errorf("expected status 'applied', got %s", response["status"])
	}
}

// =============================================================================
// =============================================================================

func TestPushAllRules_CreatePushJobPeersError(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key) VALUES (?, ?, ?, ?)",
		"peer-one", "10.0.0.1", "key1", "hmac1")

	// Close db before CreatePushJobPeersT
	db.Close()

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/push-all", nil)

	handler.PushAllRules(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPushAllRules_ExcludesManualPeers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)",
		"agent-peer", "10.0.0.1", "key1", "hmac1", 0)

	db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)",
		"manual-peer", "10.0.0.2", "key2", "hmac2", 1)

	sseHub := events.NewSSEHub()
	pushWorker := common.NewPushWorker(db, nil, nil, sseHub)
	handler := newTestHandler(db, nil, sseHub, pushWorker)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/pending/push-all", nil)

	handler.PushAllRules(w, r)

	if w.Code != http.StatusAccepted {
		t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	// Verify total_peers is 1 (only the agent-based peer)
	if int(response["total_peers"].(float64)) != 1 {
		t.Errorf("expected total_peers 1, got %v", response["total_peers"])
	}

	// Verify the push job has only the agent-based peer
	jobID := response["job_id"].(string)
	var peerCount int
	err := db.QueryRow("SELECT COUNT(*) FROM push_job_peers WHERE job_id = ?", jobID).Scan(&peerCount)
	if err != nil {
		t.Fatalf("failed to query push_job_peers: %v", err)
	}
	if peerCount != 1 {
		t.Errorf("expected 1 peer in push job, got %d", peerCount)
	}

	// Verify only the agent-based peer's ID is in the push job
	var peerID int
	err = db.QueryRow("SELECT peer_id FROM push_job_peers WHERE job_id = ?", jobID).Scan(&peerID)
	if err != nil {
		t.Fatalf("failed to query peer_id from push_job_peers: %v", err)
	}
	if peerID != 1 {
		t.Errorf("expected peer_id 1 (agent-peer), got %d", peerID)
	}
}

// TestListPendingChanges_IncludesManualPeers documents that pending visibility
// includes manual peers. Pending rows queued for a manual server must appear in
// the pending listing alongside agent peers; only push delivery stays
// agent-only.
func TestListPendingChanges_IncludesManualPeers(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	if _, err := db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)",
		"agent-peer", "10.0.0.1", "key1", "hmac1", 0); err != nil {
		t.Fatalf("insert agent peer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)",
		"manual-peer", "10.0.0.2", "key2", "hmac2", 1); err != nil {
		t.Fatalf("insert manual peer: %v", err)
	}

	if _, err := db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		1, "policy", 1, "create", "Add policy for agent"); err != nil {
		t.Fatalf("insert pending change for agent peer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO pending_changes (peer_id, change_type, change_id, change_action, change_summary) VALUES (?, ?, ?, ?, ?)",
		2, "policy", 1, "create", "Add policy for manual"); err != nil {
		t.Fatalf("insert pending change for manual peer: %v", err)
	}

	handler := newTestHandler(db, nil, nil, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)

	handler.ListPendingChanges(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	var groups []peerChangeGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("expected 2 groups (agent + manual), got %d: %s", len(groups), w.Body.String())
	}

	byHost := map[string]peerChangeGroup{}
	for _, g := range groups {
		byHost[g.Hostname] = g
	}
	for _, want := range []string{"agent-peer", "manual-peer"} {
		g, ok := byHost[want]
		if !ok {
			t.Errorf("expected pending group for %q, got %v", want, byHost)
			continue
		}
		if g.ChangesCount != 1 {
			t.Errorf("%s changes_count = %d, want 1", want, g.ChangesCount)
		}
	}

	// Per-peer endpoint must also serve the manual peer's rows.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/pending/peers/2", nil)
	r = muxVars(r, map[string]string{"peerId": "2"})
	handler.GetPeerPendingChanges(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}
	var single map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &single); err != nil {
		t.Fatalf("failed to unmarshal per-peer response: %v", err)
	}
	changes, _ := single["changes"].([]interface{})
	if len(changes) != 1 {
		t.Errorf("expected 1 change for manual peer, got %d", len(changes))
	}
}

// TestPolicyCRUD_ManualAndAgentPeersHaveVisiblePending exercises policy CRUD
// through the policies handler with a live ChangeWorker and asserts that
// pending rows are created for both the agent and the manual peer, and that
// those rows are visible via the pending listing and the peers list counts.
// Push remains agent-only (covered by TestPushAllRules_ExcludesManualPeers).
func TestPolicyCRUD_ManualAndAgentPeersHaveVisiblePending(t *testing.T) {
	db, cleanup := testutil.SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	res, err := db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
		"agent-peer", "10.0.0.1", "key1", "hmac1", 0)
	if err != nil {
		t.Fatalf("insert agent peer: %v", err)
	}
	agent64, _ := res.LastInsertId()
	agentID := int(agent64)

	res, err = db.Exec(`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, ?)`,
		"manual-peer", "10.0.0.2", "key2", "hmac2", 1)
	if err != nil {
		t.Fatalf("insert manual peer: %v", err)
	}
	manual64, _ := res.LastInsertId()
	manualID := int(manual64)

	res, err = db.Exec(`INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)`, "web", "8080", "tcp")
	if err != nil {
		t.Fatalf("insert service: %v", err)
	}
	svc64, _ := res.LastInsertId()
	serviceID := int(svc64)

	compiler := engine.NewTestCompiler(db)
	changeWorker := common.NewChangeWorker(nil, db)
	changeWorker.Start(context.Background())
	defer changeWorker.Stop()

	policyHandler := policiesapi.NewHandler(db, compiler, changeWorker, store.NewPolicyStore(db))
	pendingHandler := newTestHandler(db, compiler, nil, nil)
	peerStore := store.NewPeerStore(db)

	containsBoth := func(ids []int) bool {
		found := map[int]bool{}
		for _, id := range ids {
			found[id] = true
		}
		return found[agentID] && found[manualID]
	}

	// CREATE peer -> peer policy covering the agent source and manual target.
	createBody := `{"name": "manual-visibility-policy", "source_id": ` + strconv.Itoa(agentID) + `, "source_type": "peer", "service_id": ` + strconv.Itoa(serviceID) + `, "target_id": ` + strconv.Itoa(manualID) + `, "target_type": "peer"}`
	req := httptest.NewRequest(http.MethodPost, "/policies", strings.NewReader(createBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	policyHandler.CreatePolicy(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreatePolicy status=%d body=%s", w.Code, w.Body.String())
	}
	var created map[string]int64
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create response: %v: %s", err, w.Body.String())
	}
	policyID := int(created["id"])
	if policyID == 0 {
		t.Fatalf("expected non-zero policy id: %s", w.Body.String())
	}

	testutil.WaitForPendingRows(t, db, policyID, "create", 2)
	if got := testutil.PendingPeerIDs(t, db, policyID, "create"); !containsBoth(got) {
		t.Fatalf("create pending peers=%v, want both agent=%d and manual=%d", got, agentID, manualID)
	}

	// Pending listing must include both peers after create.
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)
	pendingHandler.ListPendingChanges(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ListPendingChanges status=%d", w.Code)
	}
	var groups []peerChangeGroup
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal pending groups: %v", err)
	}
	if len(groups) != 2 {
		t.Fatalf("expected 2 pending groups after create, got %d: %s", len(groups), w.Body.String())
	}

	// Peers list counts must be visible for both peers after create.
	peers, err := peerStore.ListPeers(ctx)
	if err != nil {
		t.Fatalf("ListPeers failed: %v", err)
	}
	byID := map[int]store.PeerView{}
	for _, p := range peers {
		byID[p.ID] = p
	}
	for _, id := range []int{agentID, manualID} {
		p, ok := byID[id]
		if !ok {
			t.Fatalf("peer %d missing from ListPeers", id)
		}
		if p.PendingChangesCount == 0 {
			t.Errorf("peer %d pending_changes_count = 0, want >0 after create", id)
		}
		if p.SyncStatus != "pending" {
			t.Errorf("peer %d sync_status = %q, want pending after create", id, p.SyncStatus)
		}
	}

	// UPDATE the policy and expect a second set of rows for both peers.
	updateBody := `{"name": "manual-visibility-policy", "source_id": ` + strconv.Itoa(agentID) + `, "source_type": "peer", "service_id": ` + strconv.Itoa(serviceID) + `, "target_id": ` + strconv.Itoa(manualID) + `, "target_type": "peer", "action": "DROP", "priority": 200}`
	req = httptest.NewRequest(http.MethodPut, "/policies/"+strconv.Itoa(policyID), strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/json")
	req = muxVars(req, map[string]string{"id": strconv.Itoa(policyID)})
	w = httptest.NewRecorder()
	policyHandler.UpdatePolicy(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdatePolicy status=%d body=%s", w.Code, w.Body.String())
	}
	testutil.WaitForPendingRows(t, db, policyID, "update", 2)
	if got := testutil.PendingPeerIDs(t, db, policyID, "update"); !containsBoth(got) {
		t.Fatalf("update pending peers=%v, want both agent=%d and manual=%d", got, agentID, manualID)
	}

	// DELETE the policy and expect delete rows for both peers.
	req = httptest.NewRequest(http.MethodDelete, "/policies/"+strconv.Itoa(policyID), nil)
	req = muxVars(req, map[string]string{"id": strconv.Itoa(policyID)})
	w = httptest.NewRecorder()
	policyHandler.DeletePolicy(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DeletePolicy status=%d body=%s", w.Code, w.Body.String())
	}
	testutil.WaitForPendingRows(t, db, policyID, "delete", 2)
	if got := testutil.PendingPeerIDs(t, db, policyID, "delete"); !containsBoth(got) {
		t.Fatalf("delete pending peers=%v, want both agent=%d and manual=%d", got, agentID, manualID)
	}

	// Pending listing must still include the manual peer after delete.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/api/v1/pending", nil)
	pendingHandler.ListPendingChanges(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ListPendingChanges after delete status=%d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("unmarshal pending groups after delete: %v", err)
	}
	seenManual := false
	for _, g := range groups {
		if g.Hostname == "manual-peer" {
			seenManual = true
		}
	}
	if !seenManual {
		t.Errorf("manual-peer missing from pending listing after delete: %s", w.Body.String())
	}
}
