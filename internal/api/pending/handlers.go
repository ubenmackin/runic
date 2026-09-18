// Package pending provides API pending handlers.
//
// Manual-peer pending visibility: pending changes are tracked and surfaced for
// every affected peer, including manual peers. Policy edits that target manual
// servers remain visible via ListPendingChanges, GetPeerPendingChanges, and the
// Peers list pending counts. Push delivery stays agent-only: PushAllRules (via
// ListAgentBasedPeers) and PushCurrentRules keep the is_manual=0 filter because
// manual peers have no agent to receive a push.
//
// Push versus Apply lifecycle (read before modifying either path):
//
//   - Apply (Approve) = CompileAndStore + clear pending_changes + delete
//     preview + CleanupIfComplete + SSE notify. ApplyPeerPendingBundle,
//     ApplyEntityPendingChanges, and applyBundleForPeer (used by
//     ApplyAllPendingBundles) all follow compile-then-clear: the bundle is
//     stored first (advancing rule_bundles.version_number), then pending rows
//     and the preview are deleted, then CleanupIfComplete runs. Only Apply
//     clears the pending signal.
//   - Push = CompileAndStore + Enqueue + SSE notify, never clear. PushAllRules
//     and PushCurrentRules only create a push job and Enqueue it; the
//     PushWorker's processJob compiles/stores (advancing version_number) and
//     sends SSE. Neither the handler nor the worker deletes pending_changes,
//     previews, or snapshots, and neither updates peers.bundle_version or
//     rule_bundles.applied_at.
//   - Notified versus confirmed: a push-job "succeeded"/"notified" count and
//     the terminal "complete"/"completed_with_errors" status mean SSE
//     delivered (agent notified). "Confirmed" (agent applied) happens only via
//     ConfirmBundleApplied, which updates peers.bundle_version and
//     rule_bundles.applied_at. UI copy must render notified distinctly from
//     confirmed.
//   - ListPeers sync_status explains Approve-then-Push-still-pending:
//     sync_status is "pending" when pending_changes > 0, else "pending_sync"
//     when the latest rule_bundles version differs from peers.bundle_version
//     (or applied_at IS NULL), else "synced". Push never clears pending, so a
//     peer with pending rows stays "pending" after Push. Apply clears pending
//     but stores a new bundle the agent has not confirmed yet, so the peer
//     moves to "pending_sync" until ConfirmBundleApplied flips it to "synced".
package pending

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/auth"
	commonutil "runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/models"
	"runic/internal/store"

	"github.com/gorilla/mux"
)

type Handler struct {
	PeerStore    *store.PeerStore
	GroupStore   *store.GroupStore
	PolicyStore  *store.PolicyStore
	ServiceStore *store.ServiceStore
	PendingStore *store.PendingStore
	beginner     db.Beginner
	Compiler     *engine.Compiler
	SSEHub       *events.SSEHub
	// PushWorker is a concrete type rather than an interface because all callers
	// (PushAllRules, PushCurrentRules) depend on its Enqueue method directly.
	// A future refactor could extract an interface for testability.
	PushWorker *common.PushWorker
}

func NewHandler(peerStore *store.PeerStore, groupStore *store.GroupStore, policyStore *store.PolicyStore, serviceStore *store.ServiceStore, pendingStore *store.PendingStore, beginner db.Beginner, compiler *engine.Compiler, sseHub *events.SSEHub, pushWorker *common.PushWorker) *Handler {
	return &Handler{
		PeerStore:    peerStore,
		GroupStore:   groupStore,
		PolicyStore:  policyStore,
		ServiceStore: serviceStore,
		PendingStore: pendingStore,
		beginner:     beginner,
		Compiler:     compiler,
		SSEHub:       sseHub,
		PushWorker:   pushWorker,
	}
}

// setupSSEHeaders configures the response writer for Server-Sent Events.
// Returns an http.Flusher if the writer supports flushing, or nil otherwise.
func setupSSEHeaders(w http.ResponseWriter) http.Flusher {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return flusher
}

// buildPendingChangeDetails converts store-level pending changes into API response details.
func (h *Handler) buildPendingChangeDetails(ctx context.Context, changes []models.PendingChange) []pendingChangeDetail {
	details := make([]pendingChangeDetail, len(changes))
	for i, c := range changes {
		details[i] = pendingChangeDetail{
			ID:            c.ID,
			ChangeType:    c.ChangeType,
			ChangeID:      c.ChangeID,
			ChangeAction:  c.ChangeAction,
			ChangeSummary: c.ChangeSummary,
			CreatedAt:     commonutil.FormatSQLiteDatetime(c.CreatedAt),
		}
		entityName, _ := h.lookupEntityName(ctx, c.ChangeType, c.ChangeID)
		details[i].EntityName = entityName
	}
	return details
}

// Returns ("Unknown", nil) for unrecognized change types.
func (h *Handler) lookupEntityName(ctx context.Context, changeType string, changeID int) (string, error) {
	switch changeType {
	case "group":
		return h.GroupStore.GetNameByID(ctx, changeID)
	case "policy":
		return h.PolicyStore.GetNameByID(ctx, changeID)
	case "service":
		return h.ServiceStore.GetNameByID(ctx, changeID)
	case "peer":
		return h.PeerStore.GetPeerHostname(ctx, changeID)
	default:
		return "Unknown", nil
	}
}

type peerChangeGroup struct {
	PeerID       int                   `json:"peer_id"`
	Hostname     string                `json:"hostname"`
	IPAddress    string                `json:"ip_address"`
	ChangesCount int                   `json:"changes_count"`
	Changes      []pendingChangeDetail `json:"changes"`
}

type pendingChangeDetail struct {
	ID            int    `json:"id"`
	ChangeType    string `json:"change_type"`
	ChangeID      int    `json:"change_id"`
	ChangeAction  string `json:"change_action"`
	ChangeSummary string `json:"change_summary"`
	EntityName    string `json:"entity_name"`
	CreatedAt     string `json:"created_at"`
}

func (h *Handler) ListPendingChanges(w http.ResponseWriter, r *http.Request) {
	// Includes manual peers by design: GetPeersWithPendingChanges has no
	// is_manual filter so policy edits targeting manual servers stay visible.
	// Push paths remain agent-only (see PushAllRules/PushCurrentRules).
	ctx := r.Context()

	if h.PendingStore == nil || h.PeerStore == nil {
		log.ErrorContext(ctx, "pending or peer store not available")
		common.InternalError(w)
		return
	}

	peerIDs, err := h.PendingStore.GetPeersWithPendingChanges(ctx)
	if err != nil {
		log.ErrorContext(ctx, "failed to get peers with pending changes", "error", err)
		common.InternalError(w)
		return
	}

	if len(peerIDs) == 0 {
		common.RespondJSON(w, http.StatusOK, []peerChangeGroup{})
		return
	}

	var groups []peerChangeGroup
	for _, peerID := range peerIDs {
		hostname, ipAddress, err := h.PeerStore.GetPeerWithIP(ctx, peerID)
		if err != nil {
			log.WarnContext(ctx, "failed to get peer with IP, skipping peer", "peer_id", peerID, "error", err)
			continue // skip peers that no longer exist
		}

		changes, err := h.PendingStore.GetPendingChangesForPeer(ctx, peerID)
		if err != nil {
			log.ErrorContext(ctx, "failed to get pending changes for peer", "peer_id", peerID, "error", err)
			continue
		}

		details := h.buildPendingChangeDetails(ctx, changes)

		groups = append(groups, peerChangeGroup{
			PeerID:       peerID,
			Hostname:     hostname,
			IPAddress:    ipAddress,
			ChangesCount: len(details),
			Changes:      details,
		})
	}

	common.RespondJSON(w, http.StatusOK, commonutil.EnsureSlice(groups))
}

type RollbackRequest struct {
	EntityType string `json:"entity_type"` // Optional: empty = bulk rollback
	EntityID   int    `json:"entity_id"`   // Optional: 0 = bulk rollback
}

type ApplyEntityRequest struct {
	EntityType string `json:"entity_type"` // "group", "policy", "service", or "peer"
	EntityID   int    `json:"entity_id"`
}

// RollbackPendingChanges rolls back pending changes for peers.
// Supports both bulk rollback (empty body) and single-entity rollback (with entity_type and entity_id).
func (h *Handler) RollbackPendingChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	var req RollbackRequest
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid request body")
			return
		}
	}

	if req.EntityType != "" && req.EntityID != 0 {
		err := h.PendingStore.RollbackEntitySnapshot(ctx, req.EntityType, req.EntityID)
		if err != nil {
			if errors.Is(err, store.ErrConstraintViolation) {
				common.RespondError(w, http.StatusConflict, "operation conflict")
				return
			}
			log.ErrorContext(ctx, "failed to rollback entity", "entity_type", req.EntityType, "entity_id", req.EntityID, "error", err)
			common.InternalError(w)
			return
		}

		if err := h.PendingStore.DeleteAllPendingBundlePreviews(ctx); err != nil {
			log.WarnContext(ctx, "failed to delete old previews", "error", err)
		}

		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
		return
	}

	if err := h.PendingStore.RollbackSnapshots(ctx); err != nil {
		log.ErrorContext(ctx, "failed to rollback snapshots", "error", err)
		common.InternalError(w)
		return
	}

	if err := h.PendingStore.DeleteAllPendingBundlePreviews(ctx); err != nil {
		log.WarnContext(ctx, "failed to delete old previews", "error", err)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}

func (h *Handler) GetPeerPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()

	hostname, ipAddress, err := h.PeerStore.GetPeerWithIP(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	changes, err := h.PendingStore.GetPendingChangesForPeer(ctx, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to get pending changes", "error", err)
		common.InternalError(w)
		return
	}

	details := h.buildPendingChangeDetails(ctx, changes)

	common.RespondJSON(w, http.StatusOK, map[string]any{
		"peer_id":    peerID,
		"hostname":   hostname,
		"ip_address": ipAddress,
		"changes":    commonutil.EnsureSlice(details),
	})
}

// PreviewPeerPendingBundle compiles a bundle for a peer, generates a diff against the current bundle, and stores the preview.
func (h *Handler) PreviewPeerPendingBundle(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()

	_, err = h.PeerStore.GetPeerHostname(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	if h.Compiler == nil {
		common.RespondError(w, http.StatusInternalServerError, "compiler not available")
		return
	}

	// Detach from the request context so a client disconnect cannot cancel
	// the compile and leave half-cleared pending state. Bounded so a
	// stalled compile cannot hold the handler indefinitely.
	compileCtx, compileCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	content, err := h.Compiler.Compile(compileCtx, peerID)
	compileCancel()
	if err != nil {
		log.ErrorContext(ctx, "failed to compile bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	version := engine.Version(content)

	// All post-compile DB reads/writes run on a detached timeout so a client
	// disconnect cannot cancel the diff or preview-write tx after the compile
	// already succeeded.
	dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer dbCancel()

	var currentContent string
	var currentVersion string
	var currentVersionNumber int
	currentContent, currentVersion, currentVersionNumber, err = h.PeerStore.GetLatestBundleForPeer(dbCtx, peerID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.WarnContext(ctx, "failed to get current bundle for diff", "error", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		currentContent = ""
		currentVersion = ""
		currentVersionNumber = 0
	}

	// Compute new version number (same logic as compiler)
	versionNumber, err := h.PeerStore.GetNextBundleVersionNumber(dbCtx, peerID)
	if err != nil {
		log.WarnContext(ctx, "failed to compute version number", "error", err)
		versionNumber = 0
	}

	diffContent := generateDiff(currentContent, content)

	err = h.PendingStore.SavePendingBundlePreview(dbCtx, peerID, content, diffContent, version)
	if err != nil {
		log.ErrorContext(ctx, "failed to save bundle preview", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]any{
		"version":                version,
		"current_version":        currentVersion,
		"new_version":            version,
		"current_version_number": currentVersionNumber,
		"new_version_number":     versionNumber,
		"is_different":           version != currentVersion,
		"diff_content":           diffContent,
		"rules_content":          content,
	})
}

// ApplyPeerPendingBundle is the Apply (Approve) path for a single peer.
//
// Lifecycle: CompileAndStore (advances rule_bundles.version_number) THEN, in a
// detached tx, ClearPendingChangesForPeerTx + DeletePendingBundlePreviewTx,
// then best-effort CleanupIfComplete, then best-effort SSE notify. Only Apply
// clears the pending signal. The SSE notify means notified, not confirmed:
// confirmed happens only via ConfirmBundleApplied (peers.bundle_version +
// rule_bundles.applied_at). After Apply the peer is pending_sync in ListPeers
// (pending cleared, latest version != bundle_version) until the agent confirms.
func (h *Handler) ApplyPeerPendingBundle(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()

	hostname, err := h.PeerStore.GetPeerHostname(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	if h.Compiler == nil {
		common.RespondError(w, http.StatusInternalServerError, "compiler not available")
		return
	}

	// Detach from the request context so a client disconnect cannot cancel
	// the compile and leave half-cleared pending state. Bounded so a
	// stalled compile cannot hold the handler indefinitely.
	compileCtx, compileCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	bundle, err := h.Compiler.CompileAndStore(compileCtx, peerID)
	compileCancel()
	if err != nil {
		log.ErrorContext(ctx, "failed to compile and store bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	// Clear pending state in a short transaction. CompileAndStore performs
	// independent DB work in its own transaction, so it must not run while
	// this transaction is held open. The tx runs on a detached timeout so a
	// client disconnect cannot cancel the clear after the bundle was stored.
	dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer dbCancel()
	if err := db.RunInTx(dbCtx, h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.PendingStore.ClearPendingChangesForPeerTx(ctx, tx, peerID); err != nil {
			return fmt.Errorf("failed to clear pending changes: %w", err)
		}
		if err := h.PendingStore.DeletePendingBundlePreviewTx(ctx, tx, peerID); err != nil {
			return fmt.Errorf("failed to delete pending bundle preview: %w", err)
		}
		return nil
	}); err != nil {
		log.ErrorContext(ctx, "failed to clear pending state for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	// Best-effort cleanup (outside transaction)
	_ = h.PendingStore.CleanupIfComplete(dbCtx) // best-effort cleanup

	// Notify via SSE (use hostname as the host_id for SSE).
	// ChannelFull (retryable backpressure) is distinct from NotConnected.
	if h.SSEHub != nil {
		switch h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		case events.UpdateAgentSent:
		case events.UpdateAgentChannelFull:
			log.WarnContext(ctx, "notifyBundleUpdated failed: agent channel full (backpressure, retryable) after applying pending bundle", "host_id", "host-"+hostname)
		default:
			log.WarnContext(ctx, "notifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
		}
	} else {
		log.WarnContext(ctx, "notifyBundleUpdated skipped: SSE hub not available (agent not connected)", "host_id", "host-"+hostname)
	}

	common.RespondJSON(w, http.StatusOK, map[string]any{
		"status":  "applied",
		"version": bundle.Version,
	})
}

func (h *Handler) ApplyAllPendingBundles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	peerIDs, err := h.PendingStore.GetPeersWithPendingChanges(ctx)
	if err != nil {
		log.ErrorContext(ctx, "failed to get peers with pending changes", "error", err)
		common.InternalError(w)
		return
	}

	if len(peerIDs) == 0 {
		common.RespondJSON(w, http.StatusOK, map[string]any{
			"status":  "no_pending_changes",
			"applied": 0,
		})
		return
	}

	// Partial-apply contract (see applyBundleForPeer): each peer is applied
	// independently on a detached context, so a client disconnect or a
	// single-peer failure cannot cancel the remaining peers. The 200
	// response reports applied/total plus per-peer errors; a non-empty
	// errors list means partial success and the caller must retry the
	// failed peers.
	applied := 0
	var applyErrors []string
	for _, peerID := range peerIDs {
		if err := h.applyBundleForPeer(ctx, peerID); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("peer %d: %v", peerID, err))
		} else {
			applied++
		}
	}

	// Detached cleanup so a client disconnect after the fan-out cannot
	// cancel the snapshot cleanup.
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	if err := h.PendingStore.CleanupIfComplete(cleanupCtx); err != nil {
		log.WarnContext(ctx, "failed to cleanup after apply all", "error", err)
	}
	cleanupCancel()

	resp := map[string]any{
		"status":  "completed",
		"applied": applied,
		"total":   len(peerIDs),
	}
	if len(applyErrors) > 0 {
		resp["errors"] = applyErrors
	}

	common.RespondJSON(w, http.StatusOK, resp)
}

// ApplyEntityPendingChanges applies all pending changes for a specific entity type on a peer.
//
// Apply (Approve) lifecycle (compile-then-clear, mirroring
// ApplyPeerPendingBundle): CompileAndStore first (advancing
// rule_bundles.version_number), then in a single tx delete the snapshot +
// pending row, count remaining, and regenerate or delete the preview, then
// best-effort SSE notify (notified, not confirmed), then CleanupIfComplete when
// no rows remain for the peer. A compile failure fails the request with the
// DB-driven pending signal intact instead of 500ing after the signal is gone.
//
// Compile-then-clear (mirroring ApplyPeerPendingBundle): the bundle is stored
// BEFORE the pending row + snapshot are deleted, so a compile failure fails
// the request with the DB-driven pending signal intact instead of returning
// 500 after the signal is already gone.
func (h *Handler) ApplyEntityPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var req ApplyEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.EntityType != "group" && req.EntityType != "policy" && req.EntityType != "service" && req.EntityType != "peer" {
		common.RespondError(w, http.StatusBadRequest, "invalid entity_type: must be 'group', 'policy', 'service', or 'peer'")
		return
	}

	if req.EntityID <= 0 {
		common.RespondError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx := r.Context()

	// Verify the pending change exists for this peer
	exists, err := h.PeerStore.CheckPendingChangeExists(ctx, peerID, req.EntityType, req.EntityID)
	if err != nil {
		log.ErrorContext(ctx, "failed to verify pending change", "error", err)
		common.InternalError(w)
		return
	}
	if !exists {
		common.RespondError(w, http.StatusNotFound, "pending change not found for this peer and entity")
		return
	}

	// Fail closed when the compiler is unavailable: proceeding would delete
	// the snapshot and pending row, clear the preview, and return applied
	// with no bundle, losing the pending signal.
	if h.Compiler == nil {
		log.ErrorContext(ctx, "compiler not available; failing entity apply to preserve pending signal", "peer_id", peerID, "entity_type", req.EntityType, "entity_id", req.EntityID)
		common.RespondError(w, http.StatusInternalServerError, "compiler not available")
		return
	}

	// Read the current (pre-apply) bundle outside the write transaction so
	// the post-apply preview diff can be derived from the stored bundle
	// without a second compile. The tx below only does
	// delete/snapshot/count/preview-write. Detached from the request context
	// so a client disconnect cannot cancel the read after the detach point.
	// A missing bundle (sql.ErrNoRows) means empty current content; any
	// other error fails the request so a transient DB failure cannot
	// silently generate a wrong diff. The cancel is explicit (not deferred)
	// so the timer is released before the compile+tx below instead of being
	// held until handler return.
	var currentContent string
	bundleCtx, bundleCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	content, _, _, bundleErr := h.PeerStore.GetLatestBundleForPeer(bundleCtx, peerID)
	bundleCancel()
	if bundleErr != nil {
		if errors.Is(bundleErr, sql.ErrNoRows) {
			currentContent = ""
		} else {
			log.ErrorContext(ctx, "failed to read current bundle for diff", "peer_id", peerID, "error", bundleErr)
			common.RespondError(w, http.StatusInternalServerError, "failed to read current bundle")
			return
		}
	} else {
		currentContent = content
	}

	// Compile-then-clear: store the bundle BEFORE deleting the pending row +
	// snapshot, so a compile failure fails the request with the DB-driven
	// pending signal intact instead of 500ing after the signal is gone.
	// Detached from the request context so a client disconnect cannot cancel
	// the compile and leave half-cleared pending state. Bounded so a
	// stalled compile cannot hold the handler indefinitely. A single
	// CompileAndStore serves both the apply and the remaining-changes
	// preview below: the preview content, diff, and version are derived
	// from the stored bundle instead of running a second Compile, which
	// would observe the same pre-delete state and waste a full compile.
	compileCtx, compileCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	bundle, compErr := h.Compiler.CompileAndStore(compileCtx, peerID)
	compileCancel()
	if compErr != nil {
		log.ErrorContext(ctx, "failed to compile and store bundle", "peer_id", peerID, "error", compErr)
		common.RespondError(w, http.StatusInternalServerError, "failed to compile bundle")
		return
	}
	previewContent := bundle.RulesContent
	previewVersion := bundle.Version
	previewDiff := generateDiff(currentContent, bundle.RulesContent)

	// All post-compile DB work (delete/count/preview-write tx plus the
	// hostname read and cleanup below) runs on a detached timeout so a
	// client disconnect cannot cancel the tx after the bundle was stored.
	dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer dbCancel()

	// Run all transactional operations within a single transaction
	var remainingCount int
	err = db.RunInTx(dbCtx, h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.PendingStore.DeleteSnapshotTx(ctx, tx, req.EntityType, req.EntityID); err != nil {
			return fmt.Errorf("delete snapshot: %w", err)
		}

		if err := h.PendingStore.DeletePendingChangeForEntityTx(ctx, tx, int64(peerID), req.EntityType, req.EntityID); err != nil {
			return fmt.Errorf("delete pending changes: %w", err)
		}

		count, err := h.PendingStore.CountPendingChangesForPeerTx(ctx, tx, int64(peerID))
		if err != nil {
			return fmt.Errorf("count remaining pending changes: %w", err)
		}
		remainingCount = count

		// If other changes remain, regenerate the bundle preview using the
		// precompiled content above. No compile or preview reads run here.
		if remainingCount > 0 {
			if err := h.PendingStore.SavePendingBundlePreviewTx(ctx, tx, peerID, previewContent, previewDiff, previewVersion); err != nil {
				log.WarnContext(ctx, "failed to save bundle preview", "error", err)
			}
		} else {
			// No more pending changes, delete the preview
			if err := h.PendingStore.DeletePendingBundlePreviewTx(ctx, tx, peerID); err != nil {
				log.WarnContext(ctx, "failed to delete pending bundle preview", "error", err)
			}
		}

		return nil
	})
	if err != nil {
		log.ErrorContext(ctx, "failed to apply entity pending changes in transaction", "error", err)
		common.InternalError(w)
		return
	}

	bundleVersion := bundle.Version
	hostname, hostnameErr := h.PeerStore.GetPeerHostname(dbCtx, peerID)
	if hostnameErr == nil && hostname != "" {
		if h.SSEHub != nil {
			switch h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
			case events.UpdateAgentSent:
			case events.UpdateAgentChannelFull:
				log.WarnContext(ctx, "notifyBundleUpdated failed: agent channel full (backpressure, retryable) after applying pending bundle", "host_id", "host-"+hostname)
			default:
				log.WarnContext(ctx, "notifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
			}
		} else {
			log.WarnContext(ctx, "notifyBundleUpdated skipped: SSE hub not available (agent not connected)", "host_id", "host-"+hostname)
		}
	}

	// If no pending changes remain for this peer, clean up snapshots
	if remainingCount == 0 {
		_ = h.PendingStore.CleanupIfComplete(dbCtx)
	}

	response := map[string]any{
		"status":            "applied",
		"peer_id":           peerID,
		"entity_type":       req.EntityType,
		"entity_id":         req.EntityID,
		"remaining_changes": remainingCount,
	}
	if bundleVersion != "" {
		response["version"] = bundleVersion
	}

	common.RespondJSON(w, http.StatusOK, response)
}

// PushAllRules is the Push path for all agent-based peers (Approve-then-Push
// still pending is expected — see below).
//
// Manual peers are excluded by design (via ListAgentBasedPeers): pending
// visibility includes manual peers, but push delivery is agent-only.
// The PushWorker processes the job in the background.
//
// Push lifecycle (never clears): this handler only creates the push job rows
// and Enqueues the job. The worker runs CompileAndStore (advancing
// rule_bundles.version_number) + SSE notify per peer. Neither this handler nor
// the worker deletes pending_changes, previews, or snapshots, and neither
// updates peers.bundle_version or rule_bundles.applied_at — only
// ConfirmBundleApplied confirms. A peer with pending rows therefore stays
// ListPeers sync_status "pending" (pending_changes > 0) after Push; a peer
// with no pending rows but an unconfirmed bundle stays "pending_sync"
// (latest version != bundle_version) until the agent confirms.
func (h *Handler) PushAllRules(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := commonutil.WithHandlerTimeout(r.Context())
	defer cancel()

	allPeers, err := h.PeerStore.ListAgentBasedPeers(ctx)
	if err != nil {
		log.ErrorContext(ctx, "failed to query agent-based peers", "error", err)
		common.InternalError(w)
		return
	}

	if len(allPeers) == 0 {
		common.RespondJSON(w, http.StatusOK, map[string]any{
			"status": "no_peers",
			"pushed": 0,
		})
		return
	}

	jobID, err := common.GeneratePushJobID()
	if err != nil {
		log.ErrorContext(ctx, "failed to generate push job ID", "error", err)
		common.InternalError(w)
		return
	}

	initiatedBy := auth.UsernameFromContext(ctx)
	if err := h.PendingStore.CreatePushJob(ctx, jobID, initiatedBy, len(allPeers)); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	peers := make([]struct {
		ID       int
		Hostname string
	}, len(allPeers))
	for i := range allPeers {
		peers[i] = struct {
			ID       int
			Hostname string
		}{ID: allPeers[i].ID, Hostname: allPeers[i].Hostname}
	}
	if err := h.PendingStore.CreatePushJobPeers(ctx, jobID, peers); err != nil {
		log.ErrorContext(ctx, "failed to create push job peers", "error", err)
		if ferr := h.PendingStore.FinalizePushJobWithCounts(ctx, jobID, 0, len(allPeers)); ferr != nil {
			log.WarnContext(ctx, "failed to finalize orphaned push job", "error", ferr, "job_id", jobID)
		}
		common.InternalError(w)
		return
	}

	if err := h.PushWorker.Enqueue(jobID); err != nil {
		log.ErrorContext(ctx, "push worker queue full", "error", err, "job_id", jobID)
		if ferr := h.PendingStore.FinalizePushJobWithCounts(ctx, jobID, 0, len(allPeers)); ferr != nil {
			log.WarnContext(ctx, "failed to finalize orphaned push job", "error", ferr, "job_id", jobID)
		}
		common.RespondError(w, http.StatusServiceUnavailable, "push worker queue full, retry later")
		return
	}

	log.InfoContext(ctx, "push job created", "job_id", jobID, "total_peers", len(allPeers))

	common.RespondJSON(w, http.StatusAccepted, map[string]any{
		"job_id":      jobID,
		"status":      "queued",
		"total_peers": len(allPeers),
	})
}

// PushCurrentRules is the Push path for a single peer (never clears pending).
//
// Manual peers are rejected by design: pending visibility includes manual
// peers, but push delivery is agent-only since manual peers have no agent.
// The peer must be agent-based (is_manual = false).
//
// Push lifecycle (never clears): this handler only creates the push job rows
// and Enqueues the job. The worker runs CompileAndStore (advancing
// rule_bundles.version_number) + SSE notify. Neither this handler nor the
// worker deletes pending_changes, previews, or snapshots, and neither updates
// peers.bundle_version or rule_bundles.applied_at — only ConfirmBundleApplied
// confirms. ListPeers stays "pending" while pending_changes > 0, and
// "pending_sync" while the latest version != bundle_version, so a Push without
// a prior Apply leaves the peer "pending" by design.
func (h *Handler) PushCurrentRules(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx, cancel := commonutil.WithHandlerTimeout(r.Context())
	defer cancel()

	hostname, _, isManual, err := h.PeerStore.GetPeerWithAgentVersion(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	// Push delivery is agent-only: reject manual peers outright. A manual
	// peer with a non-NULL empty agent_version ('') must not pass, and
	// requiring a non-empty agent_version would wrongly exclude non-manual
	// peers that have not yet reported a version, so gate on isManual to
	// stay consistent with ListAgentBasedPeers (is_manual=0).
	if isManual {
		common.RespondError(w, http.StatusBadRequest, "peer is not agent-based (manual peer)")
		return
	}

	jobID, err := common.GeneratePushJobID()
	if err != nil {
		log.ErrorContext(ctx, "failed to generate push job ID", "error", err)
		common.InternalError(w)
		return
	}

	initiatedBy := auth.UsernameFromContext(ctx)
	if err := h.PendingStore.CreatePushJob(ctx, jobID, initiatedBy, 1); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	peers := []struct {
		ID       int
		Hostname string
	}{{ID: peerID, Hostname: hostname}}
	if err := h.PendingStore.CreatePushJobPeers(ctx, jobID, peers); err != nil {
		log.ErrorContext(ctx, "failed to create push job peers", "error", err)
		if ferr := h.PendingStore.FinalizePushJobWithCounts(ctx, jobID, 0, 1); ferr != nil {
			log.WarnContext(ctx, "failed to finalize orphaned push job", "error", ferr, "job_id", jobID)
		}
		common.InternalError(w)
		return
	}

	if err := h.PushWorker.Enqueue(jobID); err != nil {
		log.ErrorContext(ctx, "push worker queue full", "error", err, "job_id", jobID)
		if ferr := h.PendingStore.FinalizePushJobWithCounts(ctx, jobID, 0, 1); ferr != nil {
			log.WarnContext(ctx, "failed to finalize orphaned push job", "error", ferr, "job_id", jobID)
		}
		common.RespondError(w, http.StatusServiceUnavailable, "push worker queue full, retry later")
		return
	}

	log.InfoContext(ctx, "push current rules job created", "job_id", jobID, "peer_id", peerID, "hostname", hostname)

	common.RespondJSON(w, http.StatusAccepted, map[string]any{
		"job_id":      jobID,
		"status":      "queued",
		"peer_id":     peerID,
		"hostname":    hostname,
		"total_peers": 1,
	})
}

func (h *Handler) HandlePushJobSSE(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]
	if jobID == "" {
		common.RespondError(w, http.StatusBadRequest, "missing job_id")
		return
	}

	_, err := h.PendingStore.GetPushJob(r.Context(), jobID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get push job", "error", err)
		common.InternalError(w)
		return
	}

	flusher := setupSSEHeaders(w)
	if flusher == nil {
		common.InternalError(w)
		return
	}

	// Register for push job events
	ch := h.SSEHub.RegisterPushJob(jobID)
	defer h.SSEHub.UnregisterPushJob(jobID, ch)

	// Send initial state
	job, peers, err := h.PendingStore.GetPushJobWithPeers(r.Context(), jobID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get push job with peers", "job_id", jobID, "error", err)
	} else {
		// total_peers is canonical; total is a deprecated alias kept for
		// backward compatibility. notified is canonical (SSE delivered, not
		// agent-confirmed); succeeded and success are deprecated aliases for
		// notified kept for backward compatibility so existing SSE consumers
		// keep working. Terminal status stays complete/completed_with_errors
		// (notified counts); confirmed is only via ConfirmBundleApplied
		// (peers.bundle_version + rule_bundles.applied_at).
		initialData := map[string]any{
			"job_id":      job.ID,
			"status":      job.Status,
			"total_peers": job.TotalPeers,
			"total":       job.TotalPeers,
			"notified":    job.Succeeded,
			"succeeded":   job.Succeeded,
			"success":     job.Succeeded,
			"failed":      job.Failed,
			"peers":       peers,
		}
		data, err := json.Marshal(initialData)
		if err != nil {
			log.ErrorContext(r.Context(), "failed to marshal initial push job state", "error", err)
			return
		}
		if _, err := fmt.Fprintf(w, "event: init\ndata: %s\n\n", data); err != nil {
			log.WarnContext(r.Context(), "failed to write SSE init", "error", err)
		}
		flusher.Flush()
	}

	// Stream events until client disconnects or job completes
	streamSSEEvents(r.Context(), w, flusher, ch, true)
}

// streamSSEEvents reads from an SSE channel and writes each event to the
// ResponseWriter, flushing after every write. It returns when the context is
// canceled, the channel is closed, or (if stopOnComplete is true) a complete
// event is received.
func streamSSEEvents(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, ch <-chan string, stopOnComplete bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, event); err != nil {
				log.WarnContext(ctx, "failed to write SSE event", "error", err)
				return
			}
			flusher.Flush()
			if stopOnComplete {
				eventType := parseSSEEventType(event)
				if eventType == "complete" {
					return
				}
			}
		}
	}
}

// Returns empty string if not found.
func parseSSEEventType(event string) string {
	for _, line := range strings.Split(event, "\n") {
		if strings.HasPrefix(line, "event:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
	}
	return ""
}

// applyBundleForPeer is the Apply (Approve) helper for ApplyAllPendingBundles.
//
// Apply lifecycle: CompileAndStore (advancing rule_bundles.version_number)
// THEN ClearPendingChangesForPeerTx + DeletePendingBundlePreviewTx, then
// best-effort SSE notify (notified, not confirmed). CleanupIfComplete runs once
// in ApplyAllPendingBundles after the fan-out, not per peer. Push paths
// (PushAllRules/PushCurrentRules + PushWorker.processJob) must never call this
// helper and must never clear pending state.
//
// Partial-apply contract: every stage (hostname lookup, compile, tx clear)
// runs on a detached timeout derived from WithoutCancel, so a client
// disconnect cannot cancel the per-peer work mid-flight and leave a
// half-cleared peer. ApplyAllPendingBundles aggregates per-peer results and
// returns 200 with applied/total plus an errors list when some peers fail;
// callers must treat a 200 with non-empty errors as partial success and
// retry the failed peers.
func (h *Handler) applyBundleForPeer(ctx context.Context, peerID int) error {
	// Detached hostname lookup: the outer request context may be canceled
	// by a client disconnect, which must not turn a healthy peer into
	// "peer not found" after the compile below already ran.
	hostnameCtx, hostnameCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	hostname, err := h.PeerStore.GetPeerHostname(hostnameCtx, peerID)
	hostnameCancel()
	if err != nil {
		return fmt.Errorf("peer not found: %w", err)
	}

	if h.Compiler == nil {
		return fmt.Errorf("compiler not available")
	}

	// Detach from the request context so a client disconnect cannot cancel
	// the compile and leave half-cleared pending state. Bounded so a
	// stalled compile cannot hold the apply-all fan-out indefinitely.
	compileCtx, compileCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	bundle, err := h.Compiler.CompileAndStore(compileCtx, peerID)
	compileCancel()
	if err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	// Clear pending state in a short transaction. CompileAndStore performs
	// independent DB work in its own transaction, so it must not run while
	// this transaction is held open. The tx runs on a detached timeout so a
	// client disconnect cannot cancel the clear after the bundle was stored.
	dbCtx, dbCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer dbCancel()
	err = db.RunInTx(dbCtx, h.beginner, func(ctx context.Context, tx *sql.Tx) error {
		if err := h.PendingStore.ClearPendingChangesForPeerTx(ctx, tx, peerID); err != nil {
			return fmt.Errorf("failed to clear pending changes: %w", err)
		}

		if err := h.PendingStore.DeletePendingBundlePreviewTx(ctx, tx, peerID); err != nil {
			return fmt.Errorf("failed to delete pending bundle preview: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Notify via SSE. ChannelFull (retryable backpressure) is distinct
	// from NotConnected and must not be reported as not connected.
	if h.SSEHub != nil {
		switch h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		case events.UpdateAgentSent:
		case events.UpdateAgentChannelFull:
			log.WarnContext(ctx, "notifyBundleUpdated failed: agent channel full (backpressure, retryable) after applying pending bundle", "host_id", "host-"+hostname)
		default:
			log.WarnContext(ctx, "notifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
		}
	} else {
		log.WarnContext(ctx, "notifyBundleUpdated skipped: SSE hub not available (agent not connected)", "host_id", "host-"+hostname)
	}

	return nil
}

// HandleFrontendSSE handles Server-Sent Events for frontend clients. This endpoint is used for notifications like pending_change_added events.
func (h *Handler) HandleFrontendSSE(w http.ResponseWriter, r *http.Request) {
	// Unpredictable, collision-resistant client ID: 8 random bytes (hex) plus
	// nanosecond timestamp. UnixNano alone is predictable and can collide
	// under concurrent connects.
	var randBytes [8]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		log.ErrorContext(r.Context(), "failed to generate random client ID suffix", "error", err)
		common.InternalError(w)
		return
	}
	clientID := fmt.Sprintf("frontend-%d-%s", time.Now().UnixNano(), hex.EncodeToString(randBytes[:]))

	flusher := setupSSEHeaders(w)
	if flusher == nil {
		common.InternalError(w)
		return
	}

	// Register for frontend events
	ch := h.SSEHub.RegisterFrontend(clientID)
	defer h.SSEHub.UnregisterFrontend(clientID)

	// Send initial connection event
	if _, err := fmt.Fprint(w, "event: connected\ndata: {\"status\":\"connected\"}\n\n"); err != nil {
		log.WarnContext(r.Context(), "failed to write SSE connected event", "error", err)
		return
	}
	flusher.Flush()

	// Stream events until client disconnects
	streamSSEEvents(r.Context(), w, flusher, ch, false)
}
