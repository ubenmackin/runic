// Package imports provides HTTP handlers for the iptables import session API.
package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/api/events"
	ic "runic/internal/common"
	runiclog "runic/internal/common/log"
	"runic/internal/importer"
	"runic/internal/models"
)

type ImportStore interface {
	GetPeerForImport(ctx context.Context, peerID int64) (bool, string, string, error)
	GetPeerHostname(ctx context.Context, peerID int64) (string, error)
	GetRules(ctx context.Context, sessionID int64) ([]models.ImportRule, error)
	GetGroups(ctx context.Context, sessionID int64) ([]models.ImportGroupMapping, error)
	GetPeers(ctx context.Context, sessionID int64) ([]models.ImportPeerMapping, error)
	GetServices(ctx context.Context, sessionID int64) ([]models.ImportServiceMapping, error)
	GetSkippedRules(ctx context.Context, sessionID int64) ([]models.SkippedRule, error)
	UpdateRule(ctx context.Context, sessionID, ruleID int64, status, policyName, sourceIP, targetIP *string, enabled *bool) error
	UpdateGroup(ctx context.Context, sessionID, groupID int64, status *string, existingGroupID *int64) error
	UpdatePeer(ctx context.Context, sessionID, peerID int64, status *string, existingPeerID *int64) error
	UpdateService(ctx context.Context, sessionID, serviceID int64, status *string, existingServiceID *int64) error
	CountApprovedRules(ctx context.Context, sessionID int64) (int, error)
	GetSessionByPeer(ctx context.Context, peerID int64) (*importer.ImportSession, error)
	CreateSession(ctx context.Context, peerID int64, rawBackup, rawIpsets string) (*importer.ImportSession, error)
	GetSession(ctx context.Context, sessionID int64) (*importer.ImportSession, error)
	UpdateSessionStatus(ctx context.Context, sessionID int64, status string) error
	ApplySession(ctx context.Context, sessionID int64, changeWorker *common.ChangeWorker) (*importer.ApplyResult, error)
	DeleteSession(ctx context.Context, sessionID int64) error
}

type Handler struct {
	Store        ImportStore
	SSEHub       *events.SSEHub
	ChangeWorker *common.ChangeWorker
}

func NewHandler(store ImportStore, sseHub *events.SSEHub, changeWorker *common.ChangeWorker) *Handler {
	return &Handler{Store: store, SSEHub: sseHub, ChangeWorker: changeWorker}
}

// RegisterRoutes registers all import session routes on the given router.
// RegisterRoutes registers all import session routes. All routes require editor role — the caller is responsible for applying the middleware.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/peers/{id:[0-9]+}/import", h.InitiateImport).Methods("POST")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}", h.GetSession).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/rules", h.GetRules).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/groups", h.GetGroups).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/peers", h.GetPeers).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/services", h.GetServices).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/skipped", h.GetSkippedRules).Methods("GET")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/rules/{rule_id:[0-9]+}", h.UpdateRule).Methods("PUT")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/groups/{group_id:[0-9]+}", h.UpdateGroup).Methods("PUT")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/peers/{peer_id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/services/{service_id:[0-9]+}", h.UpdateService).Methods("PUT")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}/apply", h.ApplySession).Methods("POST")
	r.HandleFunc("/import-sessions/{session_id:[0-9]+}", h.CancelSession).Methods("DELETE")
}

func (h *Handler) InitiateImport(w http.ResponseWriter, r *http.Request) {
	peerIDStr := mux.Vars(r)["id"]
	peerID, err := strconv.ParseInt(peerIDStr, 10, 64)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	isManual, hostname, bundleVersion, err := h.Store.GetPeerForImport(r.Context(), peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if isManual {
		common.RespondError(w, http.StatusBadRequest, "cannot import rules for manual peer")
		return
	}
	if bundleVersion != "" {
		common.RespondError(w, http.StatusBadRequest, "peer already has deployed rules — import not allowed")
		return
	}

	existingSession, err := h.Store.GetSessionByPeer(r.Context(), peerID)
	if err == nil && existingSession != nil {
		common.RespondJSON(w, http.StatusConflict, map[string]interface{}{
			"error":      "peer already has an active import session",
			"session_id": existingSession.ID,
		})
		return
	}

	session, err := h.Store.CreateSession(r.Context(), peerID, "", "")
	if err != nil {
		runiclog.Error("Failed to create import session", "error", err, "peer_id", peerID)
		common.RespondError(w, http.StatusInternalServerError, "failed to create import session")
		return
	}

	// Trigger the agent to fetch and POST its backup via SSE
	hostID := fmt.Sprintf("host-%s", hostname)
	if h.SSEHub != nil {
		if h.SSEHub.NotifyFetchBackup(hostID) {
			runiclog.Info("Sent fetch_backup SSE event to agent", "host_id", hostID, "peer_id", peerID)
		} else {
			runiclog.Warn("NotifyFetchBackup failed: agent not connected", "host_id", hostID)
		}
	}

	common.RespondJSON(w, http.StatusCreated, initiateImportResponse{
		SessionID: session.ID,
		Status:    session.Status,
	})
}

func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	session, err := h.Store.GetSession(r.Context(), sessionID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "session not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}

	peerHostname, _ := h.Store.GetPeerHostname(r.Context(), session.PeerID)

	resp := models.ImportSession{
		ID:              session.ID,
		PeerID:          session.PeerID,
		PeerHostname:    peerHostname,
		Status:          session.Status,
		TotalRulesFound: session.TotalRulesFound,
		ImportableRules: session.ImportableRules,
		SkippedRules:    session.SkippedRules,
		CreatedAt:       ic.FormatSQLiteDatetime(session.CreatedAt),
		UpdatedAt:       ic.FormatSQLiteDatetime(session.UpdatedAt),
	}
	common.RespondJSON(w, http.StatusOK, resp)
}

func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	rules, err := h.Store.GetRules(r.Context(), sessionID)
	if err != nil {
		runiclog.Error("Failed to get rules", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, rules)
}

func (h *Handler) GetGroups(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	groups, err := h.Store.GetGroups(r.Context(), sessionID)
	if err != nil {
		runiclog.Error("Failed to get groups", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, groups)
}

func (h *Handler) GetPeers(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	peers, err := h.Store.GetPeers(r.Context(), sessionID)
	if err != nil {
		runiclog.Error("Failed to get peers", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, peers)
}

func (h *Handler) GetServices(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	services, err := h.Store.GetServices(r.Context(), sessionID)
	if err != nil {
		runiclog.Error("Failed to get services", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, services)
}

func (h *Handler) GetSkippedRules(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	skipped, err := h.Store.GetSkippedRules(r.Context(), sessionID)
	if err != nil {
		runiclog.Error("Failed to get skipped rules", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, skipped)
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	sessionID, ruleID, err := parseUpdateIDs(r, "rule_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Status     *string `json:"status"`
		PolicyName *string `json:"policy_name"`
		Enabled    *bool   `json:"enabled"`
		SourceIP   *string `json:"source_ip"`
		TargetIP   *string `json:"target_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validRuleStatuses := map[string]bool{"pending": true, "resolved": true, "skipped": true, "approved": true, "rejected": true}
	if input.Status != nil && !validRuleStatuses[*input.Status] {
		common.RespondError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	if err := h.Store.UpdateRule(r.Context(), sessionID, ruleID, input.Status, input.PolicyName, input.SourceIP, input.TargetIP, input.Enabled); err != nil {
		runiclog.Warn("UpdateRule failed", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	sessionID, groupID, err := parseUpdateIDs(r, "group_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Status          *string `json:"status"`
		ExistingGroupID *int64  `json:"existing_group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	if input.Status != nil && !validMappingStatuses[*input.Status] {
		common.RespondError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	if err := h.Store.UpdateGroup(r.Context(), sessionID, groupID, input.Status, input.ExistingGroupID); err != nil {
		runiclog.Warn("UpdateGroup failed", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	sessionID, peerID, err := parseUpdateIDs(r, "peer_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Status         *string `json:"status"`
		ExistingPeerID *int64  `json:"existing_peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	if input.Status != nil && !validMappingStatuses[*input.Status] {
		common.RespondError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	if err := h.Store.UpdatePeer(r.Context(), sessionID, peerID, input.Status, input.ExistingPeerID); err != nil {
		runiclog.Warn("UpdatePeer failed", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) UpdateService(w http.ResponseWriter, r *http.Request) {
	sessionID, serviceID, err := parseUpdateIDs(r, "service_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Status            *string `json:"status"`
		ExistingServiceID *int64  `json:"existing_service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	if input.Status != nil && !validMappingStatuses[*input.Status] {
		common.RespondError(w, http.StatusBadRequest, "invalid status value")
		return
	}

	if err := h.Store.UpdateService(r.Context(), sessionID, serviceID, input.Status, input.ExistingServiceID); err != nil {
		runiclog.Warn("UpdateService failed", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	common.RespondJSON(w, http.StatusOK, statusResponse{Status: "ok"})
}

func (h *Handler) ApplySession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	if err := h.Store.UpdateSessionStatus(r.Context(), sessionID, "reviewing"); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}

	// Count approved rules
	approvedCount, err := h.Store.CountApprovedRules(r.Context(), sessionID)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if approvedCount == 0 {
		common.RespondError(w, http.StatusBadRequest, "no approved rules to apply")
		return
	}

	result, err := h.Store.ApplySession(r.Context(), sessionID, h.ChangeWorker)
	if err != nil {
		runiclog.Error("Failed to apply import session", "error", err, "session_id", sessionID)
		common.RespondError(w, http.StatusInternalServerError, "failed to apply import session")
		return
	}

	common.RespondJSON(w, http.StatusOK, applyResponse{
		Status:          "applied",
		PoliciesCreated: result.PoliciesCreated,
		GroupsCreated:   result.GroupsCreated,
		PeersCreated:    result.PeersCreated,
		ServicesCreated: result.ServicesCreated,
	})
}

func (h *Handler) CancelSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid session ID")
		return
	}

	if err := h.Store.DeleteSession(r.Context(), sessionID); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to cancel session")
		return
	}

	common.RespondJSON(w, http.StatusOK, statusResponse{Status: "canceled"})
}

// Response types

type statusResponse struct {
	Status string `json:"status"`
}

type initiateImportResponse struct {
	SessionID int64  `json:"session_id"`
	Status    string `json:"status"`
}

type applyResponse struct {
	Status          string `json:"status"`
	PoliciesCreated int    `json:"policies_created"`
	GroupsCreated   int    `json:"groups_created"`
	PeersCreated    int    `json:"peers_created"`
	ServicesCreated int    `json:"services_created"`
}

// Helper functions

func (h *Handler) getSessionID(r *http.Request) (int64, error) {
	return strconv.ParseInt(mux.Vars(r)["session_id"], 10, 64)
}

func parseUpdateIDs(r *http.Request, entityIDParam string) (sessionID int64, entityID int64, err error) {
	sessionID, err = strconv.ParseInt(mux.Vars(r)["session_id"], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid session ID")
	}
	entityID, err = strconv.ParseInt(mux.Vars(r)[entityIDParam], 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid %s", entityIDParam)
	}
	return sessionID, entityID, nil
}
