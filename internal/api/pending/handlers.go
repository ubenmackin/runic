// Package pending provides API pending handlers.
package pending

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/auth"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"

	"github.com/gorilla/mux"
)

// Handler holds dependencies for pending change handlers.
type Handler struct {
	DB         db.Querier // For queries
	DBBeginner db.DB      // For transactions and queries
	Compiler   *engine.Compiler
	SSEHub     *events.SSEHub
	PushWorker *common.PushWorker
}

// NewHandler creates a new Handler with the given dependencies.
func NewHandler(database *sql.DB, compiler *engine.Compiler, sseHub *events.SSEHub, pushWorker *common.PushWorker) *Handler {
	return &Handler{DB: database, DBBeginner: database, Compiler: compiler, SSEHub: sseHub, PushWorker: pushWorker}
}

// peerChangeGroup represents a peer with its pending changes and hostname.
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

// ListPendingChanges returns all pending changes grouped by peer with hostnames.
func (h *Handler) ListPendingChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	peerIDs, err := db.GetPeersWithPendingChanges(ctx, database)
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
		var hostname, ipAddress string
		err := database.QueryRowContext(ctx, "SELECT hostname, ip_address FROM peers WHERE id = ?", peerID).Scan(&hostname, &ipAddress)
		if err != nil {
			continue // skip peers that no longer exist
		}

		changes, err := db.GetPendingChangesForPeer(ctx, database, peerID)
		if err != nil {
			log.ErrorContext(ctx, "failed to get pending changes for peer", "peer_id", peerID, "error", err)
			continue
		}

		details := make([]pendingChangeDetail, len(changes))
		for i, c := range changes {
			details[i] = pendingChangeDetail{
				ID:            c.ID,
				ChangeType:    c.ChangeType,
				ChangeID:      c.ChangeID,
				ChangeAction:  c.ChangeAction,
				ChangeSummary: c.ChangeSummary,
				CreatedAt:     c.CreatedAt,
			}
			// Lookup entity name based on change_type
			var entityName string
			switch c.ChangeType {
			case "group":
				_ = database.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ?", c.ChangeID).Scan(&entityName)
			case "policy":
				_ = database.QueryRowContext(ctx, "SELECT name FROM policies WHERE id = ?", c.ChangeID).Scan(&entityName)
			case "service":
				_ = database.QueryRowContext(ctx, "SELECT name FROM services WHERE id = ?", c.ChangeID).Scan(&entityName)
			}
			details[i].EntityName = entityName
		}

		groups = append(groups, peerChangeGroup{
			PeerID:       peerID,
			Hostname:     hostname,
			IPAddress:    ipAddress,
			ChangesCount: len(details),
			Changes:      details,
		})
	}

	common.RespondJSON(w, http.StatusOK, common.EnsureSlice(groups))
}

// RollbackRequest represents the request body for rollback operations.
type RollbackRequest struct {
	EntityType string `json:"entity_type"` // Optional: empty = bulk rollback
	EntityID   int    `json:"entity_id"`   // Optional: 0 = bulk rollback
}

// ApplyEntityRequest represents the request body for applying a single entity's pending changes.
type ApplyEntityRequest struct {
	EntityType string `json:"entity_type"` // "group", "policy", or "service"
	EntityID   int    `json:"entity_id"`
}

// RollbackPendingChanges restores groups, services, and policies to their state before any pending changes.
// Supports both bulk rollback (empty body) and single-entity rollback (with entity_type and entity_id).
func (h *Handler) RollbackPendingChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req RollbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Legacy bulk rollback (no body or invalid JSON)
		if err := db.RollbackSnapshots(ctx, h.DBBeginner); err != nil {
			log.ErrorContext(ctx, "failed to rollback snapshots", "error", err)
			common.InternalError(w)
			return
		}

		if err := db.DeleteAllPendingBundlePreviews(ctx, h.DB); err != nil {
			log.WarnContext(ctx, "Failed to delete old previews", "error", err)
		}

		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
		return
	}

	if req.EntityType != "" && req.EntityID != 0 {
		err := db.RollbackEntitySnapshot(ctx, h.DBBeginner, req.EntityType, req.EntityID)
		if err != nil {
			if errors.Is(err, db.ErrConstraintViolation) {
				common.RespondJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
				return
			}
			log.ErrorContext(ctx, "failed to rollback entity", "entity_type", req.EntityType, "entity_id", req.EntityID, "error", err)
			common.InternalError(w)
			return
		}

		// Delete affected bundle previews for peers
		if err := db.DeleteAllPendingBundlePreviews(ctx, h.DB); err != nil {
			log.WarnContext(ctx, "Failed to delete old previews", "error", err)
		}

		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
		return
	}

	if err := db.RollbackSnapshots(ctx, h.DBBeginner); err != nil {
		log.ErrorContext(ctx, "failed to rollback snapshots", "error", err)
		common.InternalError(w)
		return
	}

	if err := db.DeleteAllPendingBundlePreviews(ctx, h.DB); err != nil {
		log.WarnContext(ctx, "Failed to delete old previews", "error", err)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "rolled_back"})
}

// GetPeerPendingChanges returns pending changes for a specific peer.
func (h *Handler) GetPeerPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()
	database := h.DB

	var hostname, ipAddress string
	err = database.QueryRowContext(ctx, "SELECT hostname, ip_address FROM peers WHERE id = ?", peerID).Scan(&hostname, &ipAddress)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	changes, err := db.GetPendingChangesForPeer(ctx, database, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to get pending changes", "error", err)
		common.InternalError(w)
		return
	}

	details := make([]pendingChangeDetail, len(changes))
	for i, c := range changes {
		details[i] = pendingChangeDetail{
			ID:            c.ID,
			ChangeType:    c.ChangeType,
			ChangeID:      c.ChangeID,
			ChangeAction:  c.ChangeAction,
			ChangeSummary: c.ChangeSummary,
			CreatedAt:     c.CreatedAt,
		}
		// Lookup entity name based on change_type
		var entityName string
		switch c.ChangeType {
		case "group":
			_ = database.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ?", c.ChangeID).Scan(&entityName)
		case "policy":
			_ = database.QueryRowContext(ctx, "SELECT name FROM policies WHERE id = ?", c.ChangeID).Scan(&entityName)
		case "service":
			_ = database.QueryRowContext(ctx, "SELECT name FROM services WHERE id = ?", c.ChangeID).Scan(&entityName)
		}
		details[i].EntityName = entityName
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"peer_id":    peerID,
		"hostname":   hostname,
		"ip_address": ipAddress,
		"changes":    common.EnsureSlice(details),
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
	database := h.DB

	var hostname string
	err = database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	content, err := h.Compiler.Compile(ctx, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to compile bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	version := engine.Version(content)

	// Get current bundle for diff
	var currentContent string
	var currentVersion string
	var currentVersionNumber int
	err = database.QueryRowContext(ctx, `
		SELECT rules_content, version, version_number FROM rule_bundles
		WHERE peer_id = ?
		ORDER BY id DESC LIMIT 1
	`, peerID).Scan(&currentContent, &currentVersion, &currentVersionNumber)
	if err != nil && err != sql.ErrNoRows {
		log.WarnContext(ctx, "failed to get current bundle for diff", "error", err)
	}

	// Compute new version number (same logic as compiler)
	var versionNumber int
	err = database.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(version_number), 0) + 1 FROM rule_bundles WHERE peer_id = ?
	`, peerID).Scan(&versionNumber)
	if err != nil {
		log.WarnContext(ctx, "failed to compute version number", "error", err)
		versionNumber = 0
	}

	diffContent := generateDiff(currentContent, content)

	err = db.SavePendingBundlePreview(ctx, database, peerID, content, diffContent, version)
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
	database := h.DB

	var hostname string
	err = database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to query peer", "error", err)
		common.InternalError(w)
		return
	}

	// Begin transaction for atomic operations
	tx, err := h.DBBeginner.BeginTx(ctx, nil)
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
	if err := db.ClearPendingChangesForPeer(ctx, tx, peerID); err != nil {
		log.ErrorContext(ctx, "failed to clear pending changes for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	if err := db.DeletePendingBundlePreview(ctx, tx, peerID); err != nil {
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
	_ = db.CleanupIfComplete(ctx, h.DBBeginner) // best-effort cleanup

	// Notify via SSE (use hostname as the host_id for SSE)
	if !h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "applied",
		"version": bundle.Version,
	})
}

// ApplyAllPendingBundles applies pending bundles for all peers with pending changes.
func (h *Handler) ApplyAllPendingBundles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	peerIDs, err := db.GetPeersWithPendingChanges(ctx, database)
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
	var errors []string
	for _, peerID := range peerIDs {
		if err := applyBundleForPeer(ctx, h.DBBeginner, h.Compiler, h.SSEHub, peerID); err != nil {
			errors = append(errors, fmt.Sprintf("peer %d: %v", peerID, err))
		} else {
			applied++
		}
	}

	if err := db.CleanupIfComplete(ctx, h.DBBeginner); err != nil {
		log.WarnContext(ctx, "Failed to cleanup after apply all", "error", err)
	}

	resp := map[string]interface{}{
		"status":  "completed",
		"applied": applied,
		"total":   len(peerIDs),
	}
	if len(errors) > 0 {
		resp["errors"] = errors
	}

	common.RespondJSON(w, http.StatusOK, resp)
}

// ApplyEntityPendingChanges applies pending changes for a single entity for a specific peer.
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

	if req.EntityType != "group" && req.EntityType != "policy" && req.EntityType != "service" {
		common.RespondError(w, http.StatusBadRequest, "invalid entity_type: must be 'group', 'policy', or 'service'")
		return
	}

	if req.EntityID <= 0 {
		common.RespondError(w, http.StatusBadRequest, "invalid entity_id")
		return
	}

	ctx := r.Context()
	database := h.DB

	// Verify the pending change exists for this peer
	var exists int
	err = database.QueryRowContext(ctx,
		"SELECT 1 FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?",
		peerID, req.EntityType, req.EntityID,
	).Scan(&exists)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "pending change not found for this peer and entity")
		return
	}
	if err != nil {
		log.ErrorContext(ctx, "failed to verify pending change", "error", err)
		common.InternalError(w)
		return
	}

	// Begin transaction for atomic operations
	tx, err := h.DBBeginner.BeginTx(ctx, nil)
	if err != nil {
		log.ErrorContext(ctx, "failed to begin transaction", "error", err)
		common.InternalError(w)
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := db.DeleteSnapshot(ctx, tx, req.EntityType, req.EntityID); err != nil {
		log.ErrorContext(ctx, "failed to delete snapshot", "error", err)
		common.InternalError(w)
		return
	}

	_, err = tx.ExecContext(ctx,
		"DELETE FROM pending_changes WHERE peer_id = ? AND change_type = ? AND change_id = ?",
		peerID, req.EntityType, req.EntityID,
	)
	if err != nil {
		log.ErrorContext(ctx, "failed to delete pending changes", "error", err)
		common.InternalError(w)
		return
	}

	var remainingCount int
	err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM pending_changes WHERE peer_id = ?", peerID).Scan(&remainingCount)
	if err != nil {
		log.ErrorContext(ctx, "failed to count remaining pending changes", "error", err)
		common.InternalError(w)
		return
	}

	// If other changes remain, regenerate the bundle preview
	if remainingCount > 0 {
		content, err := h.Compiler.Compile(ctx, peerID)
		if err != nil {
			log.WarnContext(ctx, "failed to compile bundle preview for remaining changes", "error", err)
			// Don't fail - just skip preview generation
		} else {
			version := engine.Version(content)

			var currentContent, currentVersion string
			_ = tx.QueryRowContext(ctx, `
SELECT rules_content, version FROM rule_bundles
WHERE peer_id = ?
ORDER BY id DESC LIMIT 1
`, peerID).Scan(&currentContent, &currentVersion)

			diffContent := generateDiff(currentContent, content)
			if err := db.SavePendingBundlePreview(ctx, tx, peerID, content, diffContent, version); err != nil {
				log.WarnContext(ctx, "failed to save bundle preview", "error", err)
			}
		}
	} else {
		// No more pending changes, delete the preview
		_ = db.DeletePendingBundlePreview(ctx, tx, peerID)
	}

	if err := tx.Commit(); err != nil {
		log.ErrorContext(ctx, "failed to commit transaction", "error", err)
		common.InternalError(w)
		return
	}

	var bundleVersion string
	bundle, err := h.Compiler.CompileAndStore(ctx, peerID)
	if err != nil {
		log.WarnContext(ctx, "failed to compile and store bundle", "error", err)
		// Don't fail - the pending change is still cleared
	} else {
		bundleVersion = bundle.Version
		var hostname string
		_ = database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
		if hostname != "" {
			if !h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
				log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
			}
		}
	}

	// If no pending changes remain for this peer, clean up snapshots
	if remainingCount == 0 {
		_ = db.CleanupIfComplete(ctx, h.DBBeginner)
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

// PushAllRules creates an async push job and returns immediately with a job_id.
// The PushWorker processes the job in the background.
func (h *Handler) PushAllRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	// Get all agent-based peers from the database (excluding manual peers)
	rows, err := database.QueryContext(ctx, "SELECT id, hostname FROM peers WHERE is_manual = 0 ORDER BY hostname")
	if err != nil {
		log.ErrorContext(ctx, "failed to query agent-based peers", "error", err)
		common.InternalError(w)
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Failed to close rows", "error", cErr)
		}
	}()

	type peerInfo struct {
		id       int
		hostname string
	}

	var allPeers []peerInfo
	for rows.Next() {
		var p peerInfo
		if err := rows.Scan(&p.id, &p.hostname); err != nil {
			log.WarnContext(ctx, "failed to scan peer", "error", err)
			continue
		}
		allPeers = append(allPeers, p)
	}
	if err := rows.Err(); err != nil {
		log.ErrorContext(ctx, "error iterating peers", "error", err)
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
	if err := db.CreatePushJob(ctx, database, jobID, initiatedBy, len(allPeers)); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	peers := make([]struct {
		ID       int
		Hostname string
	}, len(allPeers))
	for i, p := range allPeers {
		peers[i] = struct {
			ID       int
			Hostname string
		}{ID: p.id, Hostname: p.hostname}
	}
	if err := db.CreatePushJobPeersT(ctx, h.DBBeginner, jobID, peers); err != nil {
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

// PushCurrentRules pushes the current rules to a specific peer.
// The peer must be agent-based (has agent_version or is_manual = false).
func (h *Handler) PushCurrentRules(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()
	database := h.DB

	var hostname string
	var agentVersion sql.NullString
	var isManual bool
	err = database.QueryRowContext(ctx, `
		SELECT hostname, agent_version, is_manual FROM peers WHERE id = ?
	`, peerID).Scan(&hostname, &agentVersion, &isManual)
	if err == sql.ErrNoRows {
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

	// Create a single-peer job for consistency with push-all flow
	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	initiatedBy := auth.UsernameFromContext(r.Context())
	if err := db.CreatePushJob(ctx, database, jobID, initiatedBy, 1); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	peers := []struct {
		ID       int
		Hostname string
	}{{ID: peerID, Hostname: hostname}}
	if err := db.CreatePushJobPeersT(ctx, h.DBBeginner, jobID, peers); err != nil {
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

// HandlePushJobSSE streams real-time progress events for a push job via Server-Sent Events.
func (h *Handler) HandlePushJobSSE(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	jobID := vars["job_id"]
	if jobID == "" {
		common.RespondError(w, http.StatusBadRequest, "missing job_id")
		return
	}

	_, err := db.GetPushJob(r.Context(), h.DB, jobID)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "job not found")
		return
	}
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get push job", "error", err)
		common.InternalError(w)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		common.InternalError(w)
		return
	}

	// Register for push job events
	ch := h.SSEHub.RegisterPushJob(jobID)
	defer h.SSEHub.UnregisterPushJob(jobID)

	// Send initial state
	job, peers, err := db.GetPushJobWithPeers(r.Context(), h.DB, jobID)
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
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, event); err != nil {
				log.WarnContext(r.Context(), "Failed to write SSE event", "error", err)
			}
			flusher.Flush()

			// Check if this was a completion event by parsing the event type explicitly
			// SSE format: "event: {eventType}\ndata: {jsonPayload}\n\n"
			eventType := parseSSEEventType(event)
			if eventType == "complete" {
				return
			}
		}
	}
}

// parseSSEEventType extracts the event type from an SSE message.
// Returns empty string if not found.
func parseSSEEventType(event string) string {
	for _, line := range strings.Split(event, "\n") {
		if strings.HasPrefix(line, "event:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
	}
	return ""
}

// applyBundleForPeer compiles, stores, and clears pending for a single peer.
func applyBundleForPeer(ctx context.Context, database db.DB, compiler *engine.Compiler, sseHub *events.SSEHub, peerID int) error {
	// Get hostname for SSE
	var hostname string
	err := database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
	if err != nil {
		return fmt.Errorf("peer not found: %w", err)
	}

	// Begin transaction for atomic operations
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Compile and store
	bundle, err := compiler.CompileAndStore(ctx, peerID)
	if err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	// Clear pending changes (MUST succeed)
	if err := db.ClearPendingChangesForPeer(ctx, tx, peerID); err != nil {
		return fmt.Errorf("failed to clear pending changes: %w", err)
	}

	// Delete pending preview (MUST succeed)
	if err := db.DeletePendingBundlePreview(ctx, tx, peerID); err != nil {
		return fmt.Errorf("failed to delete pending bundle preview: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Notify via SSE
	if !sseHub.NotifyBundleUpdated("host-"+hostname, bundle.Version) {
		log.Warn("NotifyBundleUpdated failed: agent not connected after applying pending bundle", "host_id", "host-"+hostname)
	}

	return nil
}

// generateDiff produces a text diff between two strings using LCS.
func generateDiff(oldContent, newContent string) string {
	if oldContent == newContent {
		return "No changes detected."
	}

	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	// Compute LCS using DP table
	m, n := len(oldLines), len(newLines)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if oldLines[i-1] == newLines[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] > dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}

	// Backtrack to produce diff output
	type diffEntry struct {
		prefix string
		line   string
	}
	var entries []diffEntry
	i, j := m, n
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && oldLines[i-1] == newLines[j-1]:
			entries = append(entries, diffEntry{"  ", oldLines[i-1]})
			i--
			j--
		case j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]):
			entries = append(entries, diffEntry{"+ ", newLines[j-1]})
			j--
		default:
			entries = append(entries, diffEntry{"- ", oldLines[i-1]})
			i--
		}
	}

	// Reverse entries (backtrack produced them in reverse order)
	for l, r := 0, len(entries)-1; l < r; l, r = l+1, r-1 {
		entries[l], entries[r] = entries[r], entries[l]
	}

	var diff string
	for _, e := range entries {
		diff += fmt.Sprintf("%s%s\n", e.prefix, e.line)
	}

	return diff
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	// Use json.Unmarshal trick or simple split
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// HandleFrontendSSE streams real-time events to frontend clients via Server-Sent Events.
// This endpoint is used for notifications like pending_change_added events.
func (h *Handler) HandleFrontendSSE(w http.ResponseWriter, r *http.Request) {
	// Generate a unique client ID for this connection
	clientID := fmt.Sprintf("frontend-%d", time.Now().UnixNano())

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
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
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			if _, err := fmt.Fprint(w, event); err != nil {
				log.WarnContext(r.Context(), "Failed to write SSE event", "error", err)
				return
			}
			flusher.Flush()
		}
	}
}
