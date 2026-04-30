// Package policies provides API policy handlers.
package policies

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	ic "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/models"
	"runic/internal/store"
)

type PolicyStore interface {
	ListPolicies(ctx context.Context) ([]models.PolicyRow, error)
	CreatePolicy(ctx context.Context, p *models.PolicyRow) (int64, error)
	GetPolicy(ctx context.Context, id int) (models.PolicyRow, error)
	GetPolicyName(ctx context.Context, id int) (string, error)
	UpdatePolicy(ctx context.Context, q db.Querier, p *models.PolicyRow) error
	PatchPolicyEnabled(ctx context.Context, q db.Querier, id int, enabled bool) error
	SoftDeletePolicy(ctx context.Context, q db.Querier, id int) error
	Snapshot(ctx context.Context, q db.Querier, action string, policyID int) error
	ListSpecialTargets(ctx context.Context) ([]models.SpecialTargetRow, error)
}

type Handler struct {
	DB           db.DB
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
	Store        PolicyStore
}

func NewHandler(database db.DB, compiler *engine.Compiler, changeWorker *common.ChangeWorker, policyStore PolicyStore) *Handler {
	return &Handler{DB: database, Compiler: compiler, ChangeWorker: changeWorker, Store: policyStore}
}

type policyInput struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	SourceID    int     `json:"source_id"`
	SourceType  string  `json:"source_type"`
	ServiceID   int     `json:"service_id"`
	TargetID    int     `json:"target_id"`
	TargetType  string  `json:"target_type"`
	SourceIP    *string `json:"source_ip"`
	TargetIP    *string `json:"target_ip"`
	Action      string  `json:"action"`
	Priority    int     `json:"priority"`
	Enabled     *bool   `json:"enabled"`
	TargetScope string  `json:"target_scope"`
	Direction   string  `json:"direction"`
}

type policyResponse struct {
	ID              int     `json:"id"`
	Name            string  `json:"name"`
	Description     string  `json:"description"`
	SourceID        int     `json:"source_id"`
	SourceType      string  `json:"source_type"`
	ServiceID       int     `json:"service_id"`
	TargetID        int     `json:"target_id"`
	TargetType      string  `json:"target_type"`
	SourceIP        *string `json:"source_ip"`
	TargetIP        *string `json:"target_ip"`
	Action          string  `json:"action"`
	Priority        int     `json:"priority"`
	Enabled         bool    `json:"enabled"`
	TargetScope     string  `json:"target_scope"`
	Direction       string  `json:"direction"`
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	IsPendingDelete bool    `json:"is_pending_delete"`
}

func validatePolicyInput(input *policyInput, isUpdate bool) error {
	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			return common.NewHTTPError(http.StatusBadRequest, err.Error())
		}
	}
	if len(input.Name) > 255 {
		return common.NewHTTPError(http.StatusBadRequest, "policy name must not exceed 255 characters")
	}

	if !isUpdate {
		if input.Name == "" || input.SourceID == 0 || input.SourceType == "" || input.ServiceID == 0 || input.TargetID == 0 || input.TargetType == "" {
			return common.NewHTTPError(http.StatusBadRequest, "name, source_id, source_type, service_id, target_id, and target_type are required")
		}
	} else {
		if input.Name == "" {
			return common.NewHTTPError(http.StatusBadRequest, "name is required")
		}
	}

	if input.SourceType != "" && !common.IsValidSourceType(input.SourceType) {
		return common.NewHTTPError(http.StatusBadRequest, "source_type must be one of: peer, group, special")
	}
	if input.TargetType != "" && !common.IsValidTargetType(input.TargetType) {
		return common.NewHTTPError(http.StatusBadRequest, "target_type must be one of: peer, group, special")
	}
	if input.SourceIP != nil && *input.SourceIP != "" && input.SourceType != "peer" {
		return common.NewHTTPError(http.StatusBadRequest, "source_ip is only valid when source_type is peer")
	}
	if input.TargetIP != nil && *input.TargetIP != "" && input.TargetType != "peer" {
		return common.NewHTTPError(http.StatusBadRequest, "target_ip is only valid when target_type is peer")
	}
	if input.Direction == "" {
		input.Direction = "both"
	}
	if !common.IsValidDirection(input.Direction) {
		return common.NewHTTPError(http.StatusBadRequest, "direction must be one of: both, forward, backward")
	}
	if input.TargetScope == "" {
		input.TargetScope = "both"
	}
	if input.TargetScope != "both" && input.TargetScope != "host" && input.TargetScope != "docker" {
		return common.NewHTTPError(http.StatusBadRequest, "target_scope must be one of: both, host, docker")
	}
	return nil
}

func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.Store.ListPolicies(r.Context())
	if err != nil {
		log.ErrorContext(r.Context(), "failed to list policies", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query policies")
		return
	}

	var data []policyResponse
	for i := range policies {
		p := &policies[i]
		data = append(data, policyResponse{
			ID:              p.ID,
			Name:            p.Name,
			Description:     p.Description,
			SourceID:        p.SourceID,
			SourceType:      p.SourceType,
			ServiceID:       p.ServiceID,
			TargetID:        p.TargetID,
			TargetType:      p.TargetType,
			SourceIP:        p.SourceIP,
			TargetIP:        p.TargetIP,
			Action:          p.Action,
			Priority:        p.Priority,
			Enabled:         p.Enabled,
			TargetScope:     p.TargetScope,
			Direction:       p.Direction,
			CreatedAt:       ic.FormatSQLiteDatetime(p.CreatedAt.Format("2006-01-02 15:04:05")),
			UpdatedAt:       ic.FormatSQLiteDatetime(p.UpdatedAt.Format("2006-01-02 15:04:05")),
			IsPendingDelete: p.IsPendingDelete,
		})
	}

	common.RespondJSON(w, http.StatusOK, ic.EnsureSlice(data))
}

func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	var input policyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := validatePolicyInput(&input, false); err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if input.Action == "" {
		input.Action = "ACCEPT"
	}
	if input.Priority == 0 {
		input.Priority = 100
	}
	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	if (input.SourceType != "peer") || (input.SourceIP != nil && *input.SourceIP == "") {
		input.SourceIP = nil
	}
	if (input.TargetType != "peer") || (input.TargetIP != nil && *input.TargetIP == "") {
		input.TargetIP = nil
	}

	p := models.PolicyRow{
		Name:        input.Name,
		Description: input.Description,
		SourceID:    input.SourceID,
		SourceType:  input.SourceType,
		ServiceID:   input.ServiceID,
		TargetID:    input.TargetID,
		TargetType:  input.TargetType,
		SourceIP:    input.SourceIP,
		TargetIP:    input.TargetIP,
		Action:      input.Action,
		Priority:    input.Priority,
		Enabled:     enabled,
		TargetScope: input.TargetScope,
		Direction:   input.Direction,
	}

	id, err := h.Store.CreatePolicy(r.Context(), &p)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create policy", "error", err)
		common.InternalError(w)
		return
	}

	if err := h.Store.Snapshot(r.Context(), h.DB, "create", int(id)); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	affectedPeers, err := h.Compiler.GetAffectedPeersByPolicy(r.Context(), int(id))
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to get affected peers", "policy_id", id, "error", err)
	}
	if h.ChangeWorker != nil {
		h.ChangeWorker.QueuePeerChange(r.Context(), h.DB, affectedPeers, "policy", "create", int(id), fmt.Sprintf("Policy '%s' created", input.Name))
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	p, err := h.Store.GetPolicy(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "policy not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query policy", "error", err)
			common.InternalError(w)
		}
		return
	}

	resp := policyResponse{
		ID:              p.ID,
		Name:            p.Name,
		Description:     p.Description,
		SourceID:        p.SourceID,
		SourceType:      p.SourceType,
		ServiceID:       p.ServiceID,
		TargetID:        p.TargetID,
		TargetType:      p.TargetType,
		SourceIP:        p.SourceIP,
		TargetIP:        p.TargetIP,
		Action:          p.Action,
		Priority:        p.Priority,
		Enabled:         p.Enabled,
		TargetScope:     p.TargetScope,
		Direction:       p.Direction,
		CreatedAt:       ic.FormatSQLiteDatetime(p.CreatedAt.Format("2006-01-02 15:04:05")),
		UpdatedAt:       ic.FormatSQLiteDatetime(p.UpdatedAt.Format("2006-01-02 15:04:05")),
		IsPendingDelete: p.IsPendingDelete,
	}

	common.RespondJSON(w, http.StatusOK, resp)
}

func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var input policyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if err := validatePolicyInput(&input, true); err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	enabled := true
	if input.Enabled != nil {
		enabled = *input.Enabled
	}

	if (input.SourceType != "peer") || (input.SourceIP != nil && *input.SourceIP == "") {
		input.SourceIP = nil
	}
	if (input.TargetType != "peer") || (input.TargetIP != nil && *input.TargetIP == "") {
		input.TargetIP = nil
	}

	p := models.PolicyRow{
		ID:          id,
		Name:        input.Name,
		Description: input.Description,
		SourceID:    input.SourceID,
		SourceType:  input.SourceType,
		ServiceID:   input.ServiceID,
		TargetID:    input.TargetID,
		TargetType:  input.TargetType,
		SourceIP:    input.SourceIP,
		TargetIP:    input.TargetIP,
		Action:      input.Action,
		Priority:    input.Priority,
		Enabled:     enabled,
		TargetScope: input.TargetScope,
		Direction:   input.Direction,
	}

	oldPeers, err := h.Compiler.GetAffectedPeersByPolicy(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to get old affected peers for policy", "policy_id", id, "error", err)
		oldPeers = nil
	}

	// Take snapshot outside the transaction — snapshots are idempotent (INSERT OR IGNORE)
	// and don't need to be atomically consistent with the update. Keeping them
	// outside the tx reduces write lock hold time and avoids "database is locked"
	// conflicts with background workers.
	if err := h.Store.Snapshot(r.Context(), h.DB, "update", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	err = store.RunInTx(r.Context(), h.DB, func(tx *sql.Tx) error {
		if err := h.Store.UpdatePolicy(r.Context(), tx, &p); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "policy not found")
			}
			return fmt.Errorf("failed to update policy: %w", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		log.ErrorContext(r.Context(), "failed to update policy", "error", err)
		common.InternalError(w)
		return
	}

	newPeers, err := h.Compiler.GetAffectedPeersByPolicy(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to get new affected peers for policy", "policy_id", id, "error", err)
		newPeers = nil
	}

	peerSet := make(map[int]bool)
	for _, pid := range oldPeers {
		peerSet[pid] = true
	}
	for _, pid := range newPeers {
		peerSet[pid] = true
	}
	var allPeers []int
	for pid := range peerSet {
		allPeers = append(allPeers, pid)
	}

	if h.ChangeWorker != nil {
		h.ChangeWorker.QueuePeerChange(r.Context(), h.DB, allPeers, "policy", "update", id, fmt.Sprintf("Policy '%s' updated", input.Name))
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	oldPeers, err := h.Compiler.GetAffectedPeersByPolicy(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to get old affected peers for policy", "policy_id", id, "error", err)
		oldPeers = nil
	}

	policyName, err := h.Store.GetPolicyName(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "policy not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query policy name", "error", err)
			common.InternalError(w)
		}
		return
	}

	// Take snapshot outside the transaction — snapshots are idempotent (INSERT OR IGNORE)
	// and don't need to be atomically consistent with the delete. Keeping them
	// outside the tx reduces write lock hold time.
	if err := h.Store.Snapshot(r.Context(), h.DB, "delete", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	err = store.RunInTx(r.Context(), h.DB, func(tx *sql.Tx) error {
		if err := h.Store.SoftDeletePolicy(r.Context(), tx, id); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "policy not found")
			}
			return fmt.Errorf("failed to soft delete: %w", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		log.ErrorContext(r.Context(), "failed to delete policy", "error", err)
		common.InternalError(w)
		return
	}

	if h.ChangeWorker != nil {
		h.ChangeWorker.QueuePeerChange(r.Context(), h.DB, oldPeers, "policy", "delete", id, fmt.Sprintf("Policy '%s' deleted", policyName))
	}

	w.WriteHeader(http.StatusNoContent)
}

type PolicyPreviewRequest struct {
	SourceID    int    `json:"source_id"`
	SourceType  string `json:"source_type"`
	SourceIP    string `json:"source_ip"`
	TargetID    int    `json:"target_id"`
	TargetType  string `json:"target_type"`
	TargetIP    string `json:"target_ip"`
	ServiceID   int    `json:"service_id"`
	PeerID      int    `json:"peer_id"`
	Direction   string `json:"direction"`
	TargetScope string `json:"target_scope"`
}

func (h *Handler) PolicyPreview(w http.ResponseWriter, r *http.Request) {
	var req PolicyPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Direction == "" {
		req.Direction = "both"
	}
	if req.TargetScope == "" {
		req.TargetScope = "both"
	}

	if req.PeerID == 0 {
		if req.SourceType == "peer" {
			req.PeerID = req.SourceID
		} else if req.TargetType == "peer" {
			req.PeerID = req.TargetID
		}
	}

	rules, err := h.Compiler.PreviewCompile(r.Context(), req.PeerID, req.SourceID, req.SourceType, req.SourceIP, req.TargetID, req.TargetType, req.TargetIP, req.ServiceID, req.Direction, req.TargetScope)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to generate preview", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"rules": ic.EnsureSlice(rules),
		},
	})
}

func (h *Handler) PatchPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}
	var input struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.Enabled == nil {
		common.RespondError(w, http.StatusBadRequest, "enabled field is required")
		return
	}

	policyName, err := h.Store.GetPolicyName(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "policy not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query policy name", "error", err)
			common.InternalError(w)
		}
		return
	}

	// Take snapshot outside the transaction — snapshots are idempotent (INSERT OR IGNORE)
	// and don't need to be atomically consistent with the patch. Keeping them
	// outside the tx reduces write lock hold time.
	if err := h.Store.Snapshot(r.Context(), h.DB, "update", id); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot", "error", err)
	}

	err = store.RunInTx(r.Context(), h.DB, func(tx *sql.Tx) error {
		if err := h.Store.PatchPolicyEnabled(r.Context(), tx, id, *input.Enabled); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return common.NewHTTPError(http.StatusNotFound, "policy not found")
			}
			return fmt.Errorf("failed to patch policy: %w", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		log.ErrorContext(r.Context(), "failed to patch policy", "error", err)
		common.InternalError(w)
		return
	}

	affectedPeers, err := h.Compiler.GetAffectedPeersByPolicy(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to get affected peers", "policy_id", id, "error", err)
	}
	enabledStr := "enabled"
	if !*input.Enabled {
		enabledStr = "disabled"
	}
	if h.ChangeWorker != nil {
		h.ChangeWorker.QueuePeerChange(r.Context(), h.DB, affectedPeers, "policy", "update", id, fmt.Sprintf("Policy '%s' %s", policyName, enabledStr))
	}
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) ListSpecialTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := h.Store.ListSpecialTargets(r.Context())
	if err != nil {
		log.ErrorContext(r.Context(), "failed to query special targets", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query special targets")
		return
	}

	type specialTargetResp struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
		Address     string `json:"address"`
	}

	var resp []specialTargetResp
	for _, t := range targets {
		resp = append(resp, specialTargetResp{
			ID:          t.ID,
			Name:        t.Name,
			DisplayName: t.DisplayName,
			Description: t.Description,
			Address:     t.Address,
		})
	}

	common.RespondJSON(w, http.StatusOK, ic.EnsureSlice(resp))
}

// RegisterRoutes adds policy routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListPolicies).Methods("GET")
	r.HandleFunc("", h.CreatePolicy).Methods("POST")
	r.HandleFunc("/preview", h.PolicyPreview).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}", h.GetPolicy).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdatePolicy).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.PatchPolicy).Methods("PATCH")
	r.HandleFunc("/{id:[0-9]+}", h.DeletePolicy).Methods("DELETE")
	r.HandleFunc("/special-targets", h.ListSpecialTargets).Methods("GET")
}
