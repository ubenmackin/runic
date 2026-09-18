// Package policies provides API policy handlers.
package policies

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	UpdatePolicy(ctx context.Context, p *models.PolicyRow) error
	UpdatePolicyTx(ctx context.Context, tx *sql.Tx, p *models.PolicyRow) error
	PatchPolicyEnabled(ctx context.Context, id int, enabled bool) error
	PatchPolicyEnabledTx(ctx context.Context, tx *sql.Tx, id int, enabled bool) error
	SoftDeletePolicy(ctx context.Context, id int) error
	SoftDeletePolicyTx(ctx context.Context, tx *sql.Tx, id int) error
	Snapshot(ctx context.Context, action string, policyID int) error
	SnapshotTx(ctx context.Context, tx *sql.Tx, action string, policyID int) error
	ListSpecialTargets(ctx context.Context) ([]models.SpecialTargetRow, error)
	CheckDeleteConstraints(ctx context.Context, policyID int) error
	QueuePeerChange(ctx context.Context, changeWorker *common.ChangeWorker, peerIDs []int, changeType, changeAction string, changeID int, summary string) error
}

type Handler struct {
	beginner     db.Beginner
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
	Store        PolicyStore
}

func NewHandler(beginner db.Beginner, compiler *engine.Compiler, changeWorker *common.ChangeWorker, policyStore PolicyStore) *Handler {
	return &Handler{beginner: beginner, Compiler: compiler, ChangeWorker: changeWorker, Store: policyStore}
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

	if !isUpdate {
		if input.Name == "" || input.SourceID == 0 || input.SourceType == "" || input.ServiceID == 0 || input.TargetID == 0 || input.TargetType == "" {
			return common.NewHTTPError(http.StatusBadRequest, "name, source_id, source_type, service_id, target_id, and target_type are required")
		}
	} else {
		if input.Name == "" {
			return common.NewHTTPError(http.StatusBadRequest, "name is required")
		}
	}

	if input.SourceType != "" && !common.IsValidEntityType(input.SourceType) {
		return common.NewHTTPError(http.StatusBadRequest, "source_type must be one of: peer, group, special")
	}
	if input.TargetType != "" && !common.IsValidEntityType(input.TargetType) {
		return common.NewHTTPError(http.StatusBadRequest, "target_type must be one of: peer, group, special")
	}
	var sourceIP, targetIP string
	if input.SourceIP != nil {
		sourceIP = *input.SourceIP
	}
	if input.TargetIP != nil {
		targetIP = *input.TargetIP
	}
	if err := common.ValidatePeerOverrideIPs(sourceIP, targetIP, input.SourceType, input.TargetType); err != nil {
		return common.NewHTTPError(http.StatusBadRequest, err.Error())
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
	if !common.IsValidTargetScope(input.TargetScope) {
		return common.NewHTTPError(http.StatusBadRequest, "target_scope must be one of: both, host, docker")
	}
	if input.Action == "" {
		input.Action = "ACCEPT"
	}
	if !common.IsValidAction(input.Action) {
		return common.NewHTTPError(http.StatusBadRequest, "action must be one of: ACCEPT, DROP, LOG_DROP")
	}
	return nil
}

func toPolicyResponse(p *models.PolicyRow) policyResponse {
	return policyResponse{
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
		data = append(data, toPolicyResponse(p))
	}

	common.RespondJSON(w, http.StatusOK, ic.EnsureSlice(data))
}

func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input policyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
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

	// Fail closed on snapshot failure: without a snapshot there is no
	// rollback path, so do not ack success with a lost snapshot.
	if err := common.SnapshotOrLog(r.Context(), "policy", int(id), "create", func() error {
		return h.Store.Snapshot(r.Context(), "create", int(id))
	}); err != nil {
		log.ErrorContext(r.Context(), "failed to create snapshot for policy", "policy_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy created but snapshot incomplete; manual recompile required")
		return
	}

	var affectedPeers []int
	if h.Compiler == nil {
		// Fail closed: without a compiler no affected-peer resolution is
		// possible, and queueing an empty fan-out would ack 201 with zero
		// pending_changes rows, losing the DB pending signal.
		log.ErrorContext(r.Context(), "compiler not available; failing policy create to preserve pending signal", "policy_id", id)
		common.RespondError(w, http.StatusInternalServerError, "policy created but pending signal incomplete; manual recompile required")
		return
	}
	// Detach from the request context so a client disconnect cannot
	// cancel the resolution and lose pending rows. Fail the request on
	// resolution error: the mutation already succeeded, so acking
	// success with zero fan-out would lose the DB pending signal.
	resolveErr := func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		var err error
		affectedPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, int(id))
		return err
	}()
	if resolveErr != nil {
		// The policy row above is already persisted, so even
		// sql.ErrNoRows (a concurrent delete of a referenced entity
		// between Create and resolve) must not surface as 404: the
		// row exists and a 404 would invite a duplicate-create retry.
		// Fail-closed pending fan-out contract (unified across groups,
		// services, and policies; see docs/api/openapi.yaml): fail the
		// request with 500 so clients uniformly detect the lost pending
		// signal instead of receiving 201 with zero pending_changes rows.
		// For POST, list policies before retrying to avoid creating a
		// duplicate. There are no resolved peers to enqueue as a retry, so
		// log the lost signal explicitly for operator recompile.
		log.ErrorContext(r.Context(), "failed to get affected peers", "policy_id", id, "error", resolveErr)
		log.ErrorContext(r.Context(), "policy created but pending signal lost; manual recompile required", "policy_id", id)
		common.RespondError(w, http.StatusInternalServerError, "policy created but pending signal incomplete; manual recompile required")
		return
	}
	if err := h.Store.QueuePeerChange(r.Context(), h.ChangeWorker, affectedPeers, "policy", "create", int(id), fmt.Sprintf("Policy '%s' created", input.Name)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue peer change", "policy_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy created but pending signal incomplete; manual recompile required")
		return
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

	resp := toPolicyResponse(&p)

	common.RespondJSON(w, http.StatusOK, resp)
}

func (h *Handler) buildAndPersistPolicyUpdate(ctx context.Context, id int, p *models.PolicyRow) ([]int, error) {
	// Check policy existence first so a missing policy returns 404 before
	// affected-peer resolution can surface sql.ErrNoRows as a 500.
	if _, err := h.Store.GetPolicy(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, common.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return nil, fmt.Errorf("failed to query policy: %w", err)
	}
	var oldPeers []int
	// Fail closed when the compiler is unavailable: skipping resolution
	// would persist a change with zero fan-out and lose the DB pending
	// signal. Resolve before the mutation so a resolution failure fails
	// fast without persisting a change that would have no fan-out.
	if h.Compiler == nil {
		return nil, fmt.Errorf("resolve old affected peers for policy %d: compiler not available", id)
	}
	// Detach from the request context so a client disconnect cannot
	// cancel the resolution and lose pending rows. Resolve before the
	// mutation so a resolution failure fails fast without persisting a
	// change that would have no fan-out.
	resolveErr := func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var err error
		oldPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, id)
		return err
	}()
	if resolveErr != nil {
		return nil, fmt.Errorf("resolve old affected peers for policy %d: %w", id, resolveErr)
	}

	// Snapshot inside the transaction (groups pattern): the snapshot and the
	// update commit atomically, so a failed update cannot leave an orphan
	// snapshot that blocks the true first-change snapshot (INSERT OR IGNORE
	// first-wins). A snapshot failure rolls back the whole tx (fail closed).
	err := db.RunInTx(ctx, h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.Store.SnapshotTx(ctx, tx, "update", id); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := h.Store.UpdatePolicyTx(ctx, tx, p); err != nil {
			if errors.Is(err, store.ErrPolicyNotFound) {
				return common.NewHTTPError(http.StatusNotFound, "policy not found")
			}
			return fmt.Errorf("failed to update policy: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var newPeers []int
	// Fail closed when the compiler is unavailable: the mutation above
	// already succeeded, so skipping resolution would ack success with zero
	// fan-out and lose the DB pending signal. The failure propagates as an
	// error (the caller fails the request) rather than acking success. It
	// must never surface as 404: the policy exists. Queue the pre-mutation
	// peers as a fallback so the persisted change keeps at least a partial
	// pending signal.
	if h.Compiler == nil {
		log.ErrorContext(ctx, "compiler not available for new affected peers, falling back to old peers", "policy_id", id)
		var fallbackQueueErr error
		if len(oldPeers) > 0 {
			if qerr := h.Store.QueuePeerChange(ctx, h.ChangeWorker, oldPeers, "policy", "update", id, fmt.Sprintf("Policy %d updated (fallback fan-out)", id)); qerr != nil {
				log.ErrorContext(ctx, "failed to queue fallback peer change", "policy_id", id, "error", qerr)
				fallbackQueueErr = qerr
			}
		}
		return nil, errors.Join(fallbackQueueErr, fmt.Errorf("resolve new affected peers for policy %d: compiler not available", id))
	}
	// The mutation above already succeeded, so a resolution failure must
	// propagate as an error (the caller fails the request) rather than
	// acking success with zero fan-out. It must never surface as 404:
	// the policy exists. Queue the pre-mutation peers as a fallback so
	// the persisted change keeps at least a partial pending signal.
	resolveErr = func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var err error
		newPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, id)
		return err
	}()
	if resolveErr != nil {
		log.ErrorContext(ctx, "failed to resolve new affected peers, falling back to old peers", "policy_id", id, "error", resolveErr)
		var fallbackQueueErr error
		if len(oldPeers) > 0 {
			if qerr := h.Store.QueuePeerChange(ctx, h.ChangeWorker, oldPeers, "policy", "update", id, fmt.Sprintf("Policy %d updated (fallback fan-out)", id)); qerr != nil {
				log.ErrorContext(ctx, "failed to queue fallback peer change", "policy_id", id, "error", qerr)
				fallbackQueueErr = qerr
			}
		}
		return nil, errors.Join(fallbackQueueErr, fmt.Errorf("resolve new affected peers for policy %d: %w", id, resolveErr))
	}

	allPeers := ic.MergePeerIDs(oldPeers, newPeers)
	return allPeers, nil
}

func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input policyInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate the name upfront so a missing name maps to 400 even when the
	// policy does not exist (preserves existing 400-before-404 ordering).
	if input.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "name is required")
		return
	}

	// First-pass validation on a copy (without mutating the original) so
	// malformed explicit fields (bad direction, bad types, etc.) still map
	// to 400 before the existence check below maps to 404. The copy is
	// needed because validate mutates defaults (ACCEPT/both) which would
	// otherwise mask omitted fields before the merge.
	tmp := input
	if err := validatePolicyInput(&tmp, true); err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Read-modify-write merge: PUT is a full-object replace in principle,
	// but existing clients send partial objects (e.g. only name/action).
	// Plain int/string zero values cannot distinguish "omitted" from
	// "explicit zero", and persisting zeros corrupts FKs (service_id=0).
	// Merge omitted (zero) fields from the existing row so a partial PUT
	// like {"name":"x"} preserves IDs/types instead of persisting zeros.
	existing, err := h.Store.GetPolicy(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "policy not found")
		} else {
			log.ErrorContext(r.Context(), "failed to query policy", "error", err)
			common.InternalError(w)
		}
		return
	}
	if input.SourceID == 0 {
		input.SourceID = existing.SourceID
	}
	if input.SourceType == "" {
		input.SourceType = existing.SourceType
	}
	if input.ServiceID == 0 {
		input.ServiceID = existing.ServiceID
	}
	if input.TargetID == 0 {
		input.TargetID = existing.TargetID
	}
	if input.TargetType == "" {
		input.TargetType = existing.TargetType
	}
	if input.Description == "" {
		input.Description = existing.Description
	}
	if input.Action == "" {
		input.Action = existing.Action
	}
	if input.Priority == 0 {
		input.Priority = existing.Priority
	}
	if input.TargetScope == "" {
		input.TargetScope = existing.TargetScope
	}
	if input.Direction == "" {
		input.Direction = existing.Direction
	}
	if input.SourceIP == nil {
		input.SourceIP = existing.SourceIP
	}
	if input.TargetIP == nil {
		input.TargetIP = existing.TargetIP
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

	enabled := existing.Enabled
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

	allPeers, err := h.buildAndPersistPolicyUpdate(r.Context(), id, &p)
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		// Post-mutation resolution failures must never map to 404: the
		// mutation already succeeded so the resource exists. All
		// pre-mutation 404s arrive as *common.HTTPError above.
		log.ErrorContext(r.Context(), "failed to update policy", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy updated but pending signal incomplete; manual recompile required")
		return
	}

	// Fail closed on synchronous queue failures: acking 200 after the
	// fallback dropped the change would lose the DB pending signal.
	if err := h.Store.QueuePeerChange(r.Context(), h.ChangeWorker, allPeers, "policy", "update", id, fmt.Sprintf("Policy '%s' updated", input.Name)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue peer change", "policy_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy updated but pending signal incomplete; manual recompile required")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	// Check policy existence first so a missing policy returns 404 before
	// affected-peer resolution can surface sql.ErrNoRows as a 500.
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

	var oldPeers []int
	// Fail closed when the compiler is unavailable: skipping resolution
	// would delete a policy with zero fan-out and lose the DB pending
	// signal. Resolve before the mutation so a resolution failure fails
	// fast without deleting a policy that would then have no fan-out.
	if h.Compiler == nil {
		log.ErrorContext(r.Context(), "compiler not available; failing policy delete to preserve pending signal", "policy_id", id)
		common.RespondError(w, http.StatusInternalServerError, "failed to resolve affected peers; manual recompile required")
		return
	}
	// Detach from the request context so a client disconnect cannot
	// cancel the resolution and lose pending rows. Resolve before the
	// mutation so a resolution failure fails fast without deleting a
	// policy that would then have no fan-out.
	resolveErr := func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		var err error
		oldPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, id)
		return err
	}()
	if resolveErr != nil {
		log.ErrorContext(r.Context(), "failed to get old affected peers for policy", "policy_id", id, "error", resolveErr)
		common.RespondError(w, http.StatusInternalServerError, "failed to resolve affected peers; manual recompile required")
		return
	}

	// Snapshot inside the transaction (groups pattern): the snapshot and the
	// delete commit atomically, so a failed delete cannot leave an orphan
	// snapshot that blocks the true first-change snapshot (INSERT OR IGNORE
	// first-wins). A snapshot failure rolls back the whole tx (fail closed).
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.Store.SnapshotTx(ctx, tx, "delete", id); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := h.Store.SoftDeletePolicyTx(ctx, tx, id); err != nil {
			if errors.Is(err, store.ErrPolicyNotFound) {
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

	// Fail closed on synchronous queue failures: acking 204 after the
	// fallback dropped the change would lose the DB pending signal.
	if err := h.Store.QueuePeerChange(r.Context(), h.ChangeWorker, oldPeers, "policy", "delete", id, fmt.Sprintf("Policy '%s' deleted", policyName)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue peer change", "policy_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy deleted but pending signal incomplete; manual recompile required")
		return
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
	Action      string `json:"action"`
	Direction   string `json:"direction"`
	TargetScope string `json:"target_scope"`
}

// isPreviewValidationError reports whether a PreviewCompile error reflects
// user-controlled input or fail-closed policy semantics (400) rather than an
// internal failure (500). Validation and fail-closed failures carry the
// engine.ErrPreviewValidation / engine.ErrPreviewFailClosed sentinels via
// %w wrapping; unknown peer IDs surface as sql.ErrNoRows (wrapped with
// engine.ErrPreviewValidation) through the peer loader or the resolver
// chain. Anything else (DB outages, ipset wiring mistakes) stays
// an internal error.
func isPreviewValidationError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, sql.ErrNoRows) {
		return true
	}
	if errors.Is(err, engine.ErrPreviewValidation) {
		return true
	}
	if errors.Is(err, engine.ErrPreviewFailClosed) {
		return true
	}
	return false
}

// sanitizePreviewError returns a user-facing message for PreviewCompile
// validation/fail-closed failures. The full error (with sentinels) is logged
// server-side; the client sees only the human cause without sentinel text
// ("preview validation error", "preview fail-closed"), residual fail-closed
// markers, or internal policy names. Callers must only invoke it after
// isPreviewValidationError returns true so internal failures keep the generic
// 500 message and the errors.Is mapping stays intact.
func sanitizePreviewError(err error) string {
	if errors.Is(err, engine.ErrPreviewFailClosed) {
		lowered := strings.ToLower(err.Error())
		if strings.Contains(lowered, "ingress") {
			return "invalid preview request: ingress from internet cannot be previewed"
		}
		if strings.Contains(lowered, "ipv6") {
			return "invalid preview request: internet target not supported for IPv6 peers"
		}
		return "invalid preview request: internet target requires ipset support"
	}
	if errors.Is(err, sql.ErrNoRows) {
		return "invalid preview request: referenced peer, group, service, or target does not exist"
	}
	msg := err.Error()
	msg = strings.ReplaceAll(msg, engine.ErrPreviewValidation.Error(), "")
	msg = strings.ReplaceAll(msg, engine.ErrPreviewFailClosed.Error(), "")
	msg = strings.ReplaceAll(msg, ": fail-closed", "")
	msg = strings.ReplaceAll(msg, "fail-closed", "")
	msg = strings.TrimSpace(msg)
	msg = strings.TrimSuffix(msg, ":")
	msg = strings.TrimSpace(msg)
	// Collapse spaced-colon artifacts left by sentinel removal (e.g.
	// "foo: : bar" -> "foo: bar") without touching IPv6 "::" literals,
	// which never contain spaces.
	for strings.Contains(msg, ": :") {
		msg = strings.ReplaceAll(msg, ": :", ":")
	}
	// Trim a single leading/trailing colon left by sentinel removal. Use
	// prefix/suffix trimming (not a ": " cutset) so IPv6 literals like
	// "::1" or "2001:db8::/32" are preserved.
	msg = strings.TrimSpace(msg)
	if strings.HasPrefix(msg, ":") && !strings.HasPrefix(msg, "::") {
		msg = strings.TrimSpace(strings.TrimPrefix(msg, ":"))
	}
	msg = strings.TrimSpace(msg)
	if strings.HasSuffix(msg, ":") && !strings.HasSuffix(msg, "::") {
		msg = strings.TrimSpace(strings.TrimSuffix(msg, ":"))
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "invalid preview request"
	}
	msg = strings.Join(strings.Fields(msg), " ")
	if strings.HasPrefix(strings.ToLower(msg), "invalid preview request:") {
		return msg
	}
	return "invalid preview request: " + msg
}

func (h *Handler) PolicyPreview(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req PolicyPreviewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Direction == "" {
		req.Direction = "both"
	}
	if req.TargetScope == "" {
		req.TargetScope = "both"
	}
	if req.Action == "" {
		req.Action = "ACCEPT"
	}

	if !common.IsValidEntityType(req.SourceType) {
		common.RespondError(w, http.StatusBadRequest, "source_type must be one of: peer, group, special")
		return
	}
	if !common.IsValidEntityType(req.TargetType) {
		common.RespondError(w, http.StatusBadRequest, "target_type must be one of: peer, group, special")
		return
	}
	if !common.IsValidDirection(req.Direction) {
		common.RespondError(w, http.StatusBadRequest, "direction must be one of: both, forward, backward")
		return
	}
	if !common.IsValidTargetScope(req.TargetScope) {
		common.RespondError(w, http.StatusBadRequest, "target_scope must be one of: both, host, docker")
		return
	}
	if !common.IsValidAction(req.Action) {
		common.RespondError(w, http.StatusBadRequest, "action must be one of: ACCEPT, DROP, LOG_DROP")
		return
	}

	if req.PeerID == 0 {
		if req.SourceType == "peer" {
			req.PeerID = req.SourceID
		} else if req.TargetType == "peer" {
			req.PeerID = req.TargetID
		}
	}

	if err := common.ValidatePeerOverrideIPs(req.SourceIP, req.TargetIP, req.SourceType, req.TargetType); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if h.Compiler == nil {
		common.RespondError(w, http.StatusInternalServerError, "compiler not available")
		return
	}

	rules, err := h.Compiler.PreviewCompile(r.Context(), req.PeerID, req.SourceID, req.SourceType, req.SourceIP, req.TargetID, req.TargetType, req.TargetIP, req.ServiceID, req.Action, req.Direction, req.TargetScope)
	if err != nil {
		if isPreviewValidationError(err) {
			log.ErrorContext(r.Context(), "preview validation failed", "error", err)
			common.RespondError(w, http.StatusBadRequest, sanitizePreviewError(err))
			return
		}
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Enabled *bool `json:"enabled"`
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

	// Resolve pre-mutation peers before the patch so a post-mutation
	// resolution failure can fall back to them (mirrors UpdatePolicy via
	// buildAndPersistPolicyUpdate). Detach from the request context so a
	// client disconnect cannot cancel the resolution and lose pending rows.
	// Fail closed when the compiler is unavailable: skipping resolution
	// would patch a policy with zero fan-out and lose the DB pending signal.
	var oldPeers []int
	if h.Compiler == nil {
		log.ErrorContext(r.Context(), "compiler not available; failing policy patch to preserve pending signal", "policy_id", id)
		common.RespondError(w, http.StatusInternalServerError, "failed to resolve affected peers; manual recompile required")
		return
	}
	resolveErr := func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		var err error
		oldPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, id)
		return err
	}()
	if resolveErr != nil {
		log.ErrorContext(r.Context(), "failed to get old affected peers for policy", "policy_id", id, "error", resolveErr)
		common.RespondError(w, http.StatusInternalServerError, "failed to resolve affected peers; manual recompile required")
		return
	}

	// Snapshot inside the transaction (groups pattern): the snapshot and the
	// patch commit atomically, so a failed patch cannot leave an orphan
	// snapshot that blocks the true first-change snapshot (INSERT OR IGNORE
	// first-wins). A snapshot failure rolls back the whole tx (fail closed).
	err = db.RunInTx(r.Context(), h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.Store.SnapshotTx(ctx, tx, "update", id); err != nil {
			return fmt.Errorf("snapshot: %w", err)
		}
		if err := h.Store.PatchPolicyEnabledTx(ctx, tx, id, *input.Enabled); err != nil {
			if errors.Is(err, store.ErrPolicyNotFound) {
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

	var newPeers []int
	enabledStr := "enabled"
	if !*input.Enabled {
		enabledStr = "disabled"
	}
	// Detach from the request context so a client disconnect cannot
	// cancel the resolution and lose pending rows. The patch above
	// already succeeded, so a resolution failure must fail the request
	// rather than ack success with zero fan-out. It must never surface
	// as 404: the policy exists. Queue the pre-mutation peers as a
	// fallback so the persisted change keeps at least a partial
	// pending signal (mirrors buildAndPersistPolicyUpdate).
	resolveErr = func() error {
		resolveCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		var err error
		newPeers, err = h.Compiler.GetAffectedPeersByPolicy(resolveCtx, id)
		return err
	}()
	if resolveErr != nil {
		log.ErrorContext(r.Context(), "failed to resolve new affected peers, falling back to old peers", "policy_id", id, "error", resolveErr)
		var fallbackQueueErr error
		if len(oldPeers) > 0 {
			if qerr := h.Store.QueuePeerChange(r.Context(), h.ChangeWorker, oldPeers, "policy", "update", id, fmt.Sprintf("Policy '%s' %s (fallback fan-out)", policyName, enabledStr)); qerr != nil {
				log.ErrorContext(r.Context(), "failed to queue fallback peer change", "policy_id", id, "error", qerr)
				fallbackQueueErr = qerr
			}
		}
		if joined := errors.Join(fallbackQueueErr, resolveErr); joined != nil {
			log.ErrorContext(r.Context(), "policy patch fan-out failed", "policy_id", id, "error", joined)
		}
		common.RespondError(w, http.StatusInternalServerError, "policy updated but pending signal incomplete; manual recompile required")
		return
	}
	affectedPeers := ic.MergePeerIDs(oldPeers, newPeers)
	// Fail closed on synchronous queue failures: acking 200 after the
	// fallback dropped the change would lose the DB pending signal.
	if err := h.Store.QueuePeerChange(r.Context(), h.ChangeWorker, affectedPeers, "policy", "update", id, fmt.Sprintf("Policy '%s' %s", policyName, enabledStr)); err != nil {
		log.ErrorContext(r.Context(), "failed to queue peer change", "policy_id", id, "error", err)
		common.RespondError(w, http.StatusInternalServerError, "policy updated but pending signal incomplete; manual recompile required")
		return
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

// RegisterReadRoutes registers read-only (GET) routes for the viewer role.
func (h *Handler) RegisterReadRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListPolicies).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPolicy).Methods("GET")
	r.HandleFunc("/special-targets", h.ListSpecialTargets).Methods("GET")
}

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
