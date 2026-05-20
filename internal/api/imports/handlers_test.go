package imports

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/importer"
	"runic/internal/models"
)

// ---------------------------------------------------------------------------
// Mock ImportStore
// ---------------------------------------------------------------------------

type mockImportStore struct {
	getPeerForImportFn    func(context.Context, int64) (bool, string, string, error)
	getPeerHostnameFn     func(context.Context, int64) (string, error)
	getRulesFn            func(context.Context, int64) ([]models.ImportRule, error)
	getGroupsFn           func(context.Context, int64) ([]models.ImportGroupMapping, error)
	getPeersFn            func(context.Context, int64) ([]models.ImportPeerMapping, error)
	getServicesFn         func(context.Context, int64) ([]models.ImportServiceMapping, error)
	getSkippedRulesFn     func(context.Context, int64) ([]models.SkippedRule, error)
	updateRuleFn          func(context.Context, int64, int64, *string, *string, *string, *string, *bool) error
	updateGroupFn         func(context.Context, int64, int64, *string, *int64) error
	updatePeerFn          func(context.Context, int64, int64, *string, *int64) error
	updateServiceFn       func(context.Context, int64, int64, *string, *int64) error
	countApprovedRulesFn  func(context.Context, int64) (int, error)
	getSessionByPeerFn    func(context.Context, int64) (*importer.ImportSession, error)
	createSessionFn       func(context.Context, int64, string, string) (*importer.ImportSession, error)
	getSessionFn          func(context.Context, int64) (*importer.ImportSession, error)
	updateSessionStatusFn func(context.Context, int64, string) error
	applySessionFn        func(context.Context, int64, *common.ChangeWorker) (*importer.ApplyResult, error)
	deleteSessionFn       func(context.Context, int64) error
}

func (m *mockImportStore) GetPeerForImport(ctx context.Context, peerID int64) (bool, string, string, error) {
	if m.getPeerForImportFn != nil {
		return m.getPeerForImportFn(ctx, peerID)
	}
	return false, "", "", nil
}

func (m *mockImportStore) GetPeerHostname(ctx context.Context, peerID int64) (string, error) {
	if m.getPeerHostnameFn != nil {
		return m.getPeerHostnameFn(ctx, peerID)
	}
	return "", nil
}

func (m *mockImportStore) GetRules(ctx context.Context, sessionID int64) ([]models.ImportRule, error) {
	if m.getRulesFn != nil {
		return m.getRulesFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) GetGroups(ctx context.Context, sessionID int64) ([]models.ImportGroupMapping, error) {
	if m.getGroupsFn != nil {
		return m.getGroupsFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) GetPeers(ctx context.Context, sessionID int64) ([]models.ImportPeerMapping, error) {
	if m.getPeersFn != nil {
		return m.getPeersFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) GetServices(ctx context.Context, sessionID int64) ([]models.ImportServiceMapping, error) {
	if m.getServicesFn != nil {
		return m.getServicesFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) GetSkippedRules(ctx context.Context, sessionID int64) ([]models.SkippedRule, error) {
	if m.getSkippedRulesFn != nil {
		return m.getSkippedRulesFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) UpdateRule(ctx context.Context, sessionID, ruleID int64, status, policyName, sourceIP, targetIP *string, enabled *bool) error {
	if m.updateRuleFn != nil {
		return m.updateRuleFn(ctx, sessionID, ruleID, status, policyName, sourceIP, targetIP, enabled)
	}
	return nil
}

func (m *mockImportStore) UpdateGroup(ctx context.Context, sessionID, groupID int64, status *string, existingGroupID *int64) error {
	if m.updateGroupFn != nil {
		return m.updateGroupFn(ctx, sessionID, groupID, status, existingGroupID)
	}
	return nil
}

func (m *mockImportStore) UpdatePeer(ctx context.Context, sessionID, peerID int64, status *string, existingPeerID *int64) error {
	if m.updatePeerFn != nil {
		return m.updatePeerFn(ctx, sessionID, peerID, status, existingPeerID)
	}
	return nil
}

func (m *mockImportStore) UpdateService(ctx context.Context, sessionID, serviceID int64, status *string, existingServiceID *int64) error {
	if m.updateServiceFn != nil {
		return m.updateServiceFn(ctx, sessionID, serviceID, status, existingServiceID)
	}
	return nil
}

func (m *mockImportStore) CountApprovedRules(ctx context.Context, sessionID int64) (int, error) {
	if m.countApprovedRulesFn != nil {
		return m.countApprovedRulesFn(ctx, sessionID)
	}
	return 0, nil
}

func (m *mockImportStore) GetSessionByPeer(ctx context.Context, peerID int64) (*importer.ImportSession, error) {
	if m.getSessionByPeerFn != nil {
		return m.getSessionByPeerFn(ctx, peerID)
	}
	return nil, nil
}

func (m *mockImportStore) CreateSession(ctx context.Context, peerID int64, rawBackup, rawIpsets string) (*importer.ImportSession, error) {
	if m.createSessionFn != nil {
		return m.createSessionFn(ctx, peerID, rawBackup, rawIpsets)
	}
	return nil, nil
}

func (m *mockImportStore) GetSession(ctx context.Context, sessionID int64) (*importer.ImportSession, error) {
	if m.getSessionFn != nil {
		return m.getSessionFn(ctx, sessionID)
	}
	return nil, nil
}

func (m *mockImportStore) UpdateSessionStatus(ctx context.Context, sessionID int64, status string) error {
	if m.updateSessionStatusFn != nil {
		return m.updateSessionStatusFn(ctx, sessionID, status)
	}
	return nil
}

func (m *mockImportStore) ApplySession(ctx context.Context, sessionID int64, changeWorker *common.ChangeWorker) (*importer.ApplyResult, error) {
	if m.applySessionFn != nil {
		return m.applySessionFn(ctx, sessionID, changeWorker)
	}
	return nil, nil
}

func (m *mockImportStore) DeleteSession(ctx context.Context, sessionID int64) error {
	if m.deleteSessionFn != nil {
		return m.deleteSessionFn(ctx, sessionID)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newHandler(store *mockImportStore) *Handler {
	return NewHandler(store, events.NewSSEHub(), nil)
}

func setSessionVars(req *http.Request, sessionID string) *http.Request {
	return mux.SetURLVars(req, map[string]string{"session_id": sessionID})
}

func setPeerVars(req *http.Request, peerID string) *http.Request {
	return mux.SetURLVars(req, map[string]string{"id": peerID})
}

// ---------------------------------------------------------------------------
// Session lifecycle — InitiateImport
// ---------------------------------------------------------------------------

func TestInitiateImport_Success(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, peerID int64) (bool, string, string, error) {
			return false, "test-host", "", nil
		},
		getSessionByPeerFn: func(_ context.Context, _ int64) (*importer.ImportSession, error) {
			return nil, nil // no existing session
		},
		createSessionFn: func(_ context.Context, peerID int64, _, _ string) (*importer.ImportSession, error) {
			return &importer.ImportSession{ID: 42, PeerID: peerID, Status: "pending"}, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/1/import", nil)
	req = setPeerVars(req, "1")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	var resp initiateImportResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, int64(42), resp.SessionID)
	assert.Equal(t, "pending", resp.Status)
}

func TestInitiateImport_InvalidPeerID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPost, "/peers/abc/import", nil)
	req = setPeerVars(req, "abc")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "invalid peer ID", errResp["error"])
}

func TestInitiateImport_PeerNotFound(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, _ int64) (bool, string, string, error) {
			return false, "", "", sql.ErrNoRows
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/999/import", nil)
	req = setPeerVars(req, "999")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "peer not found", errResp["error"])
}

func TestInitiateImport_ManualPeer(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, _ int64) (bool, string, string, error) {
			return true, "manual-host", "", nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/1/import", nil)
	req = setPeerVars(req, "1")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "cannot import rules for manual peer", errResp["error"])
}

func TestInitiateImport_PeerHasBundle(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, _ int64) (bool, string, string, error) {
			return false, "host", "v1", nil // bundleVersion != ""
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/1/import", nil)
	req = setPeerVars(req, "1")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Contains(t, errResp["error"], "already has deployed rules")
}

func TestInitiateImport_ExistingSessionConflict(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, _ int64) (bool, string, string, error) {
			return false, "host", "", nil
		},
		getSessionByPeerFn: func(_ context.Context, _ int64) (*importer.ImportSession, error) {
			return &importer.ImportSession{ID: 7, Status: "pending"}, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/1/import", nil)
	req = setPeerVars(req, "1")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "peer already has an active import session", resp["error"])
	assert.Equal(t, float64(7), resp["session_id"])
}

func TestInitiateImport_StoreError(t *testing.T) {
	store := &mockImportStore{
		getPeerForImportFn: func(_ context.Context, _ int64) (bool, string, string, error) {
			return false, "", "", errors.New("db down")
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/peers/1/import", nil)
	req = setPeerVars(req, "1")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Session lifecycle — GetSession
// ---------------------------------------------------------------------------

func TestGetSession_Success(t *testing.T) {
	store := &mockImportStore{
		getSessionFn: func(_ context.Context, sessionID int64) (*importer.ImportSession, error) {
			return &importer.ImportSession{
				ID: 1, PeerID: 10, Status: "pending",
				TotalRulesFound: 50, ImportableRules: 30, SkippedRules: 5,
				CreatedAt: "2025-01-01 00:00:00", UpdatedAt: "2025-01-01 00:00:00",
			}, nil
		},
		getPeerHostnameFn: func(_ context.Context, peerID int64) (string, error) {
			return "test-host", nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetSession(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp models.ImportSession
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.ID)
	assert.Equal(t, int64(10), resp.PeerID)
	assert.Equal(t, "test-host", resp.PeerHostname)
	assert.Equal(t, "pending", resp.Status)
	assert.Equal(t, 50, resp.TotalRulesFound)
	assert.Equal(t, 30, resp.ImportableRules)
	assert.Equal(t, 5, resp.SkippedRules)
	assert.NotEmpty(t, resp.CreatedAt)
}

func TestGetSession_InvalidSessionID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/abc", nil)
	req = setSessionVars(req, "abc")
	w := httptest.NewRecorder()
	h.GetSession(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetSession_NotFound(t *testing.T) {
	store := &mockImportStore{
		getSessionFn: func(_ context.Context, _ int64) (*importer.ImportSession, error) {
			return nil, sql.ErrNoRows
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/999", nil)
	req = setSessionVars(req, "999")
	w := httptest.NewRecorder()
	h.GetSession(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetSession_DBError(t *testing.T) {
	store := &mockImportStore{
		getSessionFn: func(_ context.Context, _ int64) (*importer.ImportSession, error) {
			return nil, errors.New("db error")
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetSession(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Session lifecycle — CancelSession
// ---------------------------------------------------------------------------

func TestCancelSession_Success(t *testing.T) {
	var deleted bool
	store := &mockImportStore{
		deleteSessionFn: func(_ context.Context, sessionID int64) error {
			deleted = true
			assert.Equal(t, int64(1), sessionID)
			return nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodDelete, "/import-sessions/1", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.CancelSession(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.True(t, deleted)
	var resp statusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "canceled", resp.Status)
}

func TestCancelSession_InvalidSessionID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodDelete, "/import-sessions/abc", nil)
	req = setSessionVars(req, "abc")
	w := httptest.NewRecorder()
	h.CancelSession(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCancelSession_StoreError(t *testing.T) {
	store := &mockImportStore{
		deleteSessionFn: func(_ context.Context, _ int64) error {
			return errors.New("db error")
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodDelete, "/import-sessions/1", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.CancelSession(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Session lifecycle — ApplySession
// ---------------------------------------------------------------------------

func TestApplySession_Success(t *testing.T) {
	store := &mockImportStore{
		updateSessionStatusFn: func(_ context.Context, _ int64, status string) error {
			assert.Equal(t, "reviewing", status)
			return nil
		},
		countApprovedRulesFn: func(_ context.Context, _ int64) (int, error) {
			return 3, nil
		},
		applySessionFn: func(_ context.Context, _ int64, _ *common.ChangeWorker) (*importer.ApplyResult, error) {
			return &importer.ApplyResult{
				PoliciesCreated: 2,
				GroupsCreated:   1,
				PeersCreated:    3,
				ServicesCreated: 0,
			}, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/import-sessions/1/apply", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.ApplySession(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp applyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "applied", resp.Status)
	assert.Equal(t, 2, resp.PoliciesCreated)
	assert.Equal(t, 1, resp.GroupsCreated)
	assert.Equal(t, 3, resp.PeersCreated)
	assert.Equal(t, 0, resp.ServicesCreated)
}

func TestApplySession_InvalidSessionID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPost, "/import-sessions/abc/apply", nil)
	req = setSessionVars(req, "abc")
	w := httptest.NewRecorder()
	h.ApplySession(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestApplySession_NoApprovedRules(t *testing.T) {
	store := &mockImportStore{
		updateSessionStatusFn: func(_ context.Context, _ int64, _ string) error { return nil },
		countApprovedRulesFn:  func(_ context.Context, _ int64) (int, error) { return 0, nil },
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/import-sessions/1/apply", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.ApplySession(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "no approved rules to apply", errResp["error"])
}

func TestApplySession_ApplyStoreError(t *testing.T) {
	store := &mockImportStore{
		updateSessionStatusFn: func(_ context.Context, _ int64, _ string) error { return nil },
		countApprovedRulesFn:  func(_ context.Context, _ int64) (int, error) { return 1, nil },
		applySessionFn: func(_ context.Context, _ int64, _ *common.ChangeWorker) (*importer.ApplyResult, error) {
			return nil, errors.New("apply failed")
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodPost, "/import-sessions/1/apply", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.ApplySession(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Rule mapping — Get endpoints
// ---------------------------------------------------------------------------

func TestGetRules_Success(t *testing.T) {
	expectedRules := []models.ImportRule{
		{ID: 1, Chain: "INPUT", RuleOrder: 1, RawRule: "-A INPUT -s 10.0.0.0/8 -j ACCEPT", Status: "pending"},
		{ID: 2, Chain: "OUTPUT", RuleOrder: 2, RawRule: "-A OUTPUT -d 10.0.0.0/8 -j ACCEPT", Status: "approved"},
	}
	store := &mockImportStore{
		getRulesFn: func(_ context.Context, sessionID int64) ([]models.ImportRule, error) {
			assert.Equal(t, int64(1), sessionID)
			return expectedRules, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/rules", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetRules(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.ImportRule
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 2)
	assert.Equal(t, "INPUT", got[0].Chain)
}

func TestGetGroups_Success(t *testing.T) {
	expected := []models.ImportGroupMapping{
		{ID: 1, GroupName: "web-servers", Status: "pending"},
	}
	store := &mockImportStore{
		getGroupsFn: func(_ context.Context, _ int64) ([]models.ImportGroupMapping, error) {
			return expected, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/groups", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetGroups(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.ImportGroupMapping
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 1)
	assert.Equal(t, "web-servers", got[0].GroupName)
}

func TestGetPeers_Success(t *testing.T) {
	expected := []models.ImportPeerMapping{
		{ID: 1, IPAddress: "192.168.1.100", Hostname: "new-peer", Status: "approved"},
	}
	store := &mockImportStore{
		getPeersFn: func(_ context.Context, _ int64) ([]models.ImportPeerMapping, error) {
			return expected, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/peers", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetPeers(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.ImportPeerMapping
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 1)
	assert.Equal(t, "192.168.1.100", got[0].IPAddress)
}

func TestGetServices_Success(t *testing.T) {
	expected := []models.ImportServiceMapping{
		{ID: 1, Name: "http", Ports: "80,443", Protocol: "tcp", Status: "mapped"},
	}
	store := &mockImportStore{
		getServicesFn: func(_ context.Context, _ int64) ([]models.ImportServiceMapping, error) {
			return expected, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/services", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetServices(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.ImportServiceMapping
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 1)
	assert.Equal(t, "http", got[0].Name)
}

func TestGetSkippedRules_Success(t *testing.T) {
	expected := []models.SkippedRule{
		{ID: 1, Chain: "FORWARD", RuleOrder: 5, RawRule: "-A FORWARD ...", SkipReason: "unsupported action"},
	}
	store := &mockImportStore{
		getSkippedRulesFn: func(_ context.Context, _ int64) ([]models.SkippedRule, error) {
			return expected, nil
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/skipped", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetSkippedRules(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var got []models.SkippedRule
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	assert.Len(t, got, 1)
	assert.Equal(t, "FORWARD", got[0].Chain)
}

func TestGetRules_StoreError(t *testing.T) {
	store := &mockImportStore{
		getRulesFn: func(_ context.Context, _ int64) ([]models.ImportRule, error) {
			return nil, errors.New("db error")
		},
	}
	h := newHandler(store)

	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1/rules", nil)
	req = setSessionVars(req, "1")
	w := httptest.NewRecorder()
	h.GetRules(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetRules_InvalidSessionID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/abc/rules", nil)
	req = setSessionVars(req, "abc")
	w := httptest.NewRecorder()
	h.GetRules(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Update handlers — UpdateRule
// ---------------------------------------------------------------------------

func TestUpdateRule_Success(t *testing.T) {
	var capturedSessionID, capturedRuleID int64
	var capturedStatus *string
	store := &mockImportStore{
		updateRuleFn: func(_ context.Context, sessionID, ruleID int64, status, policyName, sourceIP, targetIP *string, enabled *bool) error {
			capturedSessionID = sessionID
			capturedRuleID = ruleID
			capturedStatus = status
			return nil
		},
	}
	h := newHandler(store)

	body := `{"status":"approved"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", bytes.NewBufferString(body))
	req = setSessionVars(req, "1")
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(1), capturedSessionID)
	assert.Equal(t, int64(10), capturedRuleID)
	require.NotNil(t, capturedStatus)
	assert.Equal(t, "approved", *capturedStatus)

	var resp statusResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "ok", resp.Status)
}

func TestUpdateRule_InvalidSessionID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/abc/rules/1", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "abc", "rule_id": "1"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Contains(t, errResp["error"], "invalid session ID")
}

func TestUpdateRule_InvalidRuleID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "abc"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Contains(t, errResp["error"], "invalid rule_id")
}

func TestUpdateRule_InvalidJSON(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", bytes.NewBufferString(`{invalid json}`))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateRule_RequestBodyTooLarge(t *testing.T) {
	h := newHandler(&mockImportStore{})
	largeBody := make([]byte, 2<<20) // 2MB, exceeds 1MB limit
	for i := range largeBody {
		largeBody[i] = ' '
	}
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", bytes.NewReader(largeBody))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestUpdateRule_InvalidStatus(t *testing.T) {
	h := newHandler(&mockImportStore{})
	body := `{"status":"bogus"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var errResp map[string]string
	json.Unmarshal(w.Body.Bytes(), &errResp)
	assert.Equal(t, "invalid status value", errResp["error"])
}

func TestUpdateRule_StoreError(t *testing.T) {
	store := &mockImportStore{
		updateRuleFn: func(_ context.Context, _, _ int64, _, _, _, _ *string, _ *bool) error {
			return errors.New("db error")
		},
	}
	h := newHandler(store)

	body := `{"status":"approved"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})
	w := httptest.NewRecorder()
	h.UpdateRule(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ---------------------------------------------------------------------------
// Update handlers — UpdateGroup
// ---------------------------------------------------------------------------

func TestUpdateGroup_Success(t *testing.T) {
	var capturedExistingGroupID *int64
	store := &mockImportStore{
		updateGroupFn: func(_ context.Context, _, _ int64, status *string, existingGroupID *int64) error {
			capturedExistingGroupID = existingGroupID
			return nil
		},
	}
	h := newHandler(store)

	body := `{"status":"mapped","existing_group_id":5}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/groups/20", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "group_id": "20"})
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedExistingGroupID)
	assert.Equal(t, int64(5), *capturedExistingGroupID)
}

func TestUpdateGroup_InvalidGroupID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/groups/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "group_id": "abc"})
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateGroup_InvalidMappingStatus(t *testing.T) {
	h := newHandler(&mockImportStore{})
	body := `{"status":"invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/groups/20", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "group_id": "20"})
	w := httptest.NewRecorder()
	h.UpdateGroup(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Update handlers — UpdatePeer
// ---------------------------------------------------------------------------

func TestUpdatePeer_Success(t *testing.T) {
	var capturedExistingPeerID *int64
	store := &mockImportStore{
		updatePeerFn: func(_ context.Context, _, _ int64, status *string, existingPeerID *int64) error {
			capturedExistingPeerID = existingPeerID
			return nil
		},
	}
	h := newHandler(store)

	body := `{"status":"approved"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/peers/30", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "peer_id": "30"})
	w := httptest.NewRecorder()
	h.UpdatePeer(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Nil(t, capturedExistingPeerID)
}

func TestUpdatePeer_InvalidPeerID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/peers/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "peer_id": "abc"})
	w := httptest.NewRecorder()
	h.UpdatePeer(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Update handlers — UpdateService
// ---------------------------------------------------------------------------

func TestUpdateService_Success(t *testing.T) {
	var capturedExistingServiceID *int64
	store := &mockImportStore{
		updateServiceFn: func(_ context.Context, _, _ int64, status *string, existingServiceID *int64) error {
			capturedExistingServiceID = existingServiceID
			return nil
		},
	}
	h := newHandler(store)

	body := `{"status":"mapped","existing_service_id":7}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/services/40", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "service_id": "40"})
	w := httptest.NewRecorder()
	h.UpdateService(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedExistingServiceID)
	assert.Equal(t, int64(7), *capturedExistingServiceID)
}

func TestUpdateService_InvalidServiceID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/services/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "service_id": "abc"})
	w := httptest.NewRecorder()
	h.UpdateService(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateService_InvalidMappingStatus(t *testing.T) {
	h := newHandler(&mockImportStore{})
	body := `{"status":"bad"}`
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/services/40", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "service_id": "40"})
	w := httptest.NewRecorder()
	h.UpdateService(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Helper: getSessionID
// ---------------------------------------------------------------------------

func TestGetSessionID_Success(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/42", nil)
	req = setSessionVars(req, "42")

	id, err := h.getSessionID(req)
	require.NoError(t, err)
	assert.Equal(t, int64(42), id)
}

func TestGetSessionID_Invalid(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/abc", nil)
	req = setSessionVars(req, "abc")

	_, err := h.getSessionID(req)
	assert.Error(t, err)
}

func TestGetSessionID_Missing(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1", nil)
	// No vars set - simulate missing param
	req = mux.SetURLVars(req, map[string]string{})

	_, err := h.getSessionID(req)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Helper: parseUpdateIDs
// ---------------------------------------------------------------------------

func TestParseUpdateIDs_Success(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "10"})

	sessionID, entityID, err := parseUpdateIDs(req, "rule_id")
	require.NoError(t, err)
	assert.Equal(t, int64(1), sessionID)
	assert.Equal(t, int64(10), entityID)
}

func TestParseUpdateIDs_InvalidSessionID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/abc/rules/10", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "abc", "rule_id": "10"})

	_, _, err := parseUpdateIDs(req, "rule_id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid session ID")
}

func TestParseUpdateIDs_InvalidEntityID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1", "rule_id": "abc"})

	_, _, err := parseUpdateIDs(req, "rule_id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid rule_id")
}

func TestParseUpdateIDs_MissingEntityParam(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/import-sessions/1/rules/10", nil)
	req = mux.SetURLVars(req, map[string]string{"session_id": "1"}) // missing rule_id

	_, _, err := parseUpdateIDs(req, "rule_id")
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Named response type usage verification
// ---------------------------------------------------------------------------

func TestStatusResponse_JSON(t *testing.T) {
	b, err := json.Marshal(statusResponse{Status: "ok"})
	require.NoError(t, err)
	assert.Equal(t, `{"status":"ok"}`, string(b))
}

func TestInitiateImportResponse_JSON(t *testing.T) {
	b, err := json.Marshal(initiateImportResponse{SessionID: 42, Status: "pending"})
	require.NoError(t, err)
	assert.Equal(t, `{"session_id":42,"status":"pending"}`, string(b))
}

func TestApplyResponse_JSON(t *testing.T) {
	b, err := json.Marshal(applyResponse{
		Status: "applied", PoliciesCreated: 1, GroupsCreated: 2, PeersCreated: 3, ServicesCreated: 4,
	})
	require.NoError(t, err)
	assert.Equal(t, `{"status":"applied","policies_created":1,"groups_created":2,"peers_created":3,"services_created":4}`, string(b))
}

// ---------------------------------------------------------------------------
// Edge cases — non-numeric peer ID in InitiateImport
// ---------------------------------------------------------------------------

func TestInitiateImport_EmptyPeerID(t *testing.T) {
	h := newHandler(&mockImportStore{})
	req := httptest.NewRequest(http.MethodPost, "/peers//import", nil)
	req = setPeerVars(req, "")
	w := httptest.NewRecorder()
	h.InitiateImport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ---------------------------------------------------------------------------
// Router integration — RegisterRoutes uses correct param names
// ---------------------------------------------------------------------------

func TestRegisterRoutes_UsesSessionIDParam(t *testing.T) {
	// Verify that the route param is named "session_id" (not "id")
	// by sending a request through the router. We provide a mock session
	// so the handler completes without panicking.
	store := &mockImportStore{
		getSessionFn: func(_ context.Context, _ int64) (*importer.ImportSession, error) {
			return &importer.ImportSession{ID: 1, PeerID: 10, Status: "pending"}, nil
		},
		getPeerHostnameFn: func(_ context.Context, _ int64) (string, error) {
			return "test-host", nil
		},
	}
	h := newHandler(store)
	r := mux.NewRouter()
	h.RegisterRoutes(r)

	// GET import-sessions — should match with session_id param
	req := httptest.NewRequest(http.MethodGet, "/import-sessions/1", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "route should match and handler should succeed")
}
