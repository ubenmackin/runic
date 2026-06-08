// Package pending provides API pending handlers.
package pending

import (
	"bytes"
	"context"
	"database/sql"
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
	ctx := r.Context()

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
			log.WarnContext(ctx, "Failed to delete old previews", "error", err)
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
		log.WarnContext(ctx, "Failed to delete old previews", "error", err)
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

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
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

	content, err := h.Compiler.Compile(ctx, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to compile bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	version := engine.Version(content)

	var currentContent string
	var currentVersion string
	var currentVersionNumber int
	currentContent, currentVersion, currentVersionNumber, err = h.PeerStore.GetLatestBundleForPeer(ctx, peerID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		log.WarnContext(ctx, "failed to get current bundle for diff", "error", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		currentContent = ""
		currentVersion = ""
		currentVersionNumber = 0
	}

	// Compute new version number (same logic as compiler)
	versionNumber, err := h.PeerStore.GetNextBundleVersionNumber(ctx, peerID)
	if err != nil {
		log.WarnContext(ctx, "failed to compute version number", "error", err)
		versionNumber = 0
	}

	diffContent := generateDiff(currentContent, content)

	err = h.PendingStore.SavePendingBundlePreview(ctx, peerID, content, diffContent, version)
	if err != nil {
		log.ErrorContext(ctx, "failed to save bundle preview", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
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

// ApplyPeerPendingBundle compiles and stores a bundle for a peer, clears pending changes, and triggers SSE notification.
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

	// Begin transaction for atomic operations
	tx, err := h.beginner.BeginTx(ctx, nil)
	if err != nil {
		log.ErrorContext(ctx, "failed to begin transaction", "error", err)
		common.InternalError(w)
		return
	}
	defer func() { _ = tx.Rollback() }()

	bundle, err := h.Compiler.CompileAndStore(ctx, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to compile and store bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	// Clear pending changes for this peer (MUST succeed)
	if err := h.PendingStore.ClearPendingChangesForPeerTx(ctx, tx, peerID); err != nil {
		log.ErrorContext(ctx, "failed to clear pending changes for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	if err := h.PendingStore.DeletePendingBundlePreviewTx(ctx, tx, peerID); err != nil {
		log.ErrorContext(ctx, "failed to delete pending bundle preview", "error", err)
		common.InternalError(w)
		return
	}

	if err := tx.Commit(); err != nil {
		log.ErrorContext(ctx, "failed to commit transaction", "error", err)
		common.InternalError(w)
		return
	}

	// Best-effort cleanup (outside transaction)
	_ = h.PendingStore.CleanupIfComplete(ctx) // best-effort cleanup

	// Notify via SSE (use hostname as the host_id for SSE)
	if !h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
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
		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "no_pending_changes",
			"applied": 0,
		})
		return
	}

	applied := 0
	var applyErrors []string
	for _, peerID := range peerIDs {
		if err := h.applyBundleForPeer(ctx, peerID); err != nil {
			applyErrors = append(applyErrors, fmt.Sprintf("peer %d: %v", peerID, err))
		} else {
			applied++
		}
	}

	if err := h.PendingStore.CleanupIfComplete(ctx); err != nil {
		log.WarnContext(ctx, "Failed to cleanup after apply all", "error", err)
	}

	resp := map[string]interface{}{
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
// It:
// 1. Deletes the pending change record and snapshot
// 2. Commits the transaction
// 3. Compiles and stores the new bundle with current state
// 4. Notifies via SSE that bundle is updated
// 5. If other pending changes remain, regenerates the bundle preview
func (h *Handler) ApplyEntityPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	var req ApplyEntityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	// Run all transactional operations within a single transaction
	var remainingCount int
	err = store.RunInTx(ctx, h.beginner, func(tx *sql.Tx) error {
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

		// If other changes remain, regenerate the bundle preview
		if remainingCount > 0 && h.Compiler != nil {
			content, compileErr := h.Compiler.Compile(ctx, peerID)
			if compileErr != nil {
				log.WarnContext(ctx, "failed to compile bundle preview for remaining changes", "error", compileErr)
				// Don't fail - just skip preview generation
			} else {
				version := engine.Version(content)

				var currentContent string
				currentContent, _, _, bundleErr := h.PeerStore.GetLatestBundleForPeer(ctx, peerID)
				if bundleErr != nil {
					// No existing bundle or error — use empty values
					currentContent = ""
				}

				diffContent := generateDiff(currentContent, content)
				if err := h.PendingStore.SavePendingBundlePreviewTx(ctx, tx, peerID, content, diffContent, version); err != nil {
					log.WarnContext(ctx, "failed to save bundle preview", "error", err)
				}
			}
		} else {
			// No more pending changes, delete the preview
			_ = h.PendingStore.DeletePendingBundlePreviewTx(ctx, tx, peerID)
		}

		return nil
	})
	if err != nil {
		log.ErrorContext(ctx, "failed to apply entity pending changes in transaction", "error", err)
		common.InternalError(w)
		return
	}

	var bundleVersion string
	if h.Compiler != nil {
		bundle, compErr := h.Compiler.CompileAndStore(ctx, peerID)
		if compErr != nil {
			log.WarnContext(ctx, "failed to compile and store bundle", "error", compErr)
			// Don't fail - the pending change is still cleared
		} else {
			bundleVersion = bundle.Version
			hostname, hostnameErr := h.PeerStore.GetPeerHostname(ctx, peerID)
			if hostnameErr == nil && hostname != "" {
				if !h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
					log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
				}
			}
		}
	}

	// If no pending changes remain for this peer, clean up snapshots
	if remainingCount == 0 {
		_ = h.PendingStore.CleanupIfComplete(ctx)
	}

	response := map[string]interface{}{
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

// PushAllRules pushes compiled rules to all agent-based peers.
// The PushWorker processes the job in the background.
func (h *Handler) PushAllRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	allPeers, err := h.PeerStore.ListAgentBasedPeers(ctx)
	if err != nil {
		log.ErrorContext(ctx, "failed to query agent-based peers", "error", err)
		common.InternalError(w)
		return
	}

	if len(allPeers) == 0 {
		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"status": "no_peers",
			"pushed": 0,
		})
		return
	}

	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	initiatedBy := auth.UsernameFromContext(r.Context())
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
		common.InternalError(w)
		return
	}

	h.PushWorker.Enqueue(jobID)

	log.InfoContext(ctx, "push job created", "job_id", jobID, "total_peers", len(allPeers))

	common.RespondJSON(w, http.StatusAccepted, map[string]interface{}{
		"job_id":      jobID,
		"status":      "queued",
		"total_peers": len(allPeers),
	})
}

// PushCurrentRules pushes the current compiled rules to a specific peer.
// The peer must be agent-based (has agent_version or is_manual = false).
func (h *Handler) PushCurrentRules(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()

	hostname, agentVersion, isManual, err := h.PeerStore.GetPeerWithAgentVersion(ctx, peerID)
	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	isAgentBased := agentVersion.Valid || !isManual
	if !isAgentBased {
		common.RespondError(w, http.StatusBadRequest, "peer is not agent-based (manual peer)")
		return
	}

	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	initiatedBy := auth.UsernameFromContext(r.Context())
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
		common.InternalError(w)
		return
	}

	h.PushWorker.Enqueue(jobID)

	log.InfoContext(ctx, "push current rules job created", "job_id", jobID, "peer_id", peerID, "hostname", hostname)

	common.RespondJSON(w, http.StatusAccepted, map[string]interface{}{
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
	if err == nil {
		initialData := map[string]interface{}{
			"job_id":    job.ID,
			"status":    job.Status,
			"total":     job.TotalPeers,
			"succeeded": job.Succeeded,
			"failed":    job.Failed,
			"peers":     peers,
		}
		data, err := json.Marshal(initialData)
		if err != nil {
			log.ErrorContext(r.Context(), "failed to marshal initial push job state", "error", err)
			return
		}
		if _, err := fmt.Fprintf(w, "event: init\ndata: %s\n\n", data); err != nil {
			log.WarnContext(r.Context(), "Failed to write SSE init", "error", err)
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
				log.WarnContext(ctx, "Failed to write SSE event", "error", err)
				if stopOnComplete {
					return
				}
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

// applyBundleForPeer compiles and stores a bundle for a peer, clears pending changes, and notifies via SSE.
func (h *Handler) applyBundleForPeer(ctx context.Context, peerID int) error {
	hostname, err := h.PeerStore.GetPeerHostname(ctx, peerID)
	if err != nil {
		return fmt.Errorf("peer not found: %w", err)
	}

	if h.Compiler == nil {
		return fmt.Errorf("compiler not available")
	}

	var bundle models.RuleBundleRow
	err = store.RunInTx(ctx, h.beginner, func(tx *sql.Tx) error {
		// Compile and store
		b, compileErr := h.Compiler.CompileAndStore(ctx, peerID)
		if compileErr != nil {
			return fmt.Errorf("compile failed: %w", compileErr)
		}
		bundle = b

		// Clear pending changes (MUST succeed)
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

	// Notify via SSE
	if !h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
	}

	return nil
}

// HandleFrontendSSE handles Server-Sent Events for frontend clients. This endpoint is used for notifications like pending_change_added events.
func (h *Handler) HandleFrontendSSE(w http.ResponseWriter, r *http.Request) {
	clientID := fmt.Sprintf("frontend-%d", time.Now().UnixNano())

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
		log.WarnContext(r.Context(), "Failed to write SSE connected event", "error", err)
		return
	}
	flusher.Flush()

	// Stream events until client disconnects
	streamSSEEvents(r.Context(), w, flusher, ch, false)
}
