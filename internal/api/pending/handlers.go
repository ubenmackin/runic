// Package pending provides API pending handlers.
package pending

import (
	"context"
	"database/sql"
	"encoding/json"
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
	CreatedAt     string `json:"created_at"`
}

// ListPendingChanges returns all pending changes grouped by peer with hostnames.
func (h *Handler) ListPendingChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	// Get all peers with pending changes
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
		// Get peer info
		var hostname, ipAddress string
		err := database.QueryRowContext(ctx, "SELECT hostname, ip_address FROM peers WHERE id = ?", peerID).Scan(&hostname, &ipAddress)
		if err != nil {
			continue // skip peers that no longer exist
		}

		// Get pending changes for this peer
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

// GetPeerPendingChanges returns pending changes for a specific peer.
func (h *Handler) GetPeerPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()
	database := h.DB

	// Verify peer exists
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

	// Verify peer exists
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

	// Compile fresh bundle
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

	// Generate diff
	diffContent := generateDiff(currentContent, content, currentVersion, version)

	// Save preview
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
		"diff":                   diffContent,
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

	// Verify peer exists and get hostname
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

	// Compile and store the bundle
	bundle, err := h.Compiler.CompileAndStore(ctx, peerID)
	if err != nil {
		log.ErrorContext(ctx, "failed to compile and store bundle for peer", "peer_id", peerID, "error", err)
		common.InternalError(w)
		return
	}

	// Clear pending changes for this peer
	err = db.ClearPendingChangesForPeer(ctx, database, peerID)
	if err != nil {
		log.WarnContext(ctx, "failed to clear pending changes for peer", "peer_id", peerID, "error", err)
		// Don't fail the request — bundle was applied successfully
	}

	// Delete any pending preview
	if err := db.DeletePendingBundlePreview(ctx, database, peerID); err != nil {
		log.WarnContext(ctx, "Failed to delete pending bundle preview", "error", err)
	}

	// Notify via SSE (use hostname as the host_id for SSE)
	h.SSEHub.NotifyBundleUpdated("host-"+hostname, bundle.Version)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":  "applied",
		"version": bundle.Version,
	})
}

// ApplyAllPendingBundles applies pending bundles for all peers with pending changes.
func (h *Handler) ApplyAllPendingBundles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	// Get all peers with pending changes
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

// PushAllRules creates an async push job and returns immediately with a job_id.
// The PushWorker processes the job in the background.
func (h *Handler) PushAllRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := h.DB

	// Get ALL peers from the database
	rows, err := database.QueryContext(ctx, "SELECT id, hostname FROM peers ORDER BY hostname")
	if err != nil {
		log.ErrorContext(ctx, "failed to query all peers", "error", err)
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

	// Generate job ID
	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	// Create push job record
	initiatedBy := auth.UsernameFromContext(r.Context())
	if err := db.CreatePushJob(ctx, database, jobID, initiatedBy, len(allPeers)); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	// Create push job peer records
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

	// Enqueue to worker
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

	// Verify peer exists and is agent-based
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

	// Check if peer is agent-based: has agent_version OR is_manual = false
	isAgentBased := agentVersion.Valid || !isManual
	if !isAgentBased {
		common.RespondError(w, http.StatusBadRequest, "peer is not agent-based (manual peer)")
		return
	}

	// Use the PushWorker to compile and store bundle, then notify
	// Create a single-peer job for consistency with push-all flow
	jobID := fmt.Sprintf("job_%d", time.Now().UnixNano())

	// Create push job record with single peer
	initiatedBy := auth.UsernameFromContext(r.Context())
	if err := db.CreatePushJob(ctx, database, jobID, initiatedBy, 1); err != nil {
		log.ErrorContext(ctx, "failed to create push job", "error", err)
		common.InternalError(w)
		return
	}

	// Create push job peer record
	peers := []struct {
		ID       int
		Hostname string
	}{{ID: peerID, Hostname: hostname}}
	if err := db.CreatePushJobPeersT(ctx, h.DBBeginner, jobID, peers); err != nil {
		log.ErrorContext(ctx, "failed to create push job peers", "error", err)
		common.InternalError(w)
		return
	}

	// Enqueue to worker for processing
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

	// Verify job exists
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

	// Set SSE headers
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

	// Compile and store
	bundle, err := compiler.CompileAndStore(ctx, peerID)
	if err != nil {
		return fmt.Errorf("compile failed: %w", err)
	}

	// Clear pending
	if err := db.ClearPendingChangesForPeer(ctx, database, peerID); err != nil {
		log.WarnContext(ctx, "failed to clear pending changes for peer", "peer_id", peerID, "error", err)
	}
	if err := db.DeletePendingBundlePreview(ctx, database, peerID); err != nil {
		log.WarnContext(ctx, "Failed to delete pending bundle preview", "error", err)
	}

	// Notify via SSE
	sseHub.NotifyBundleUpdated("host-"+hostname, bundle.Version)

	return nil
}

// generateDiff produces a simple text diff between two bundle versions.
func generateDiff(oldContent, newContent, oldVersion, newVersion string) string {
	if oldContent == "" {
		return fmt.Sprintf("New bundle (version %s)\n%s", newVersion, newContent)
	}
	if oldContent == newContent {
		return "No changes detected."
	}

	// Simple line-by-line diff
	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	var diff string
	diff += fmt.Sprintf("--- version %s\n+++ version %s\n", oldVersion, newVersion)

	maxLen := len(oldLines)
	if len(newLines) > maxLen {
		maxLen = len(newLines)
	}

	for i := 0; i < maxLen; i++ {
		var oldLine, newLine string
		hasOld := i < len(oldLines)
		hasNew := i < len(newLines)
		if hasOld {
			oldLine = oldLines[i]
		}
		if hasNew {
			newLine = newLines[i]
		}

		if hasOld && hasNew && oldLine == newLine {
			continue // skip unchanged lines for brevity
		}
		if hasOld && (!hasNew || oldLine != newLine) {
			diff += fmt.Sprintf("- %s\n", oldLine)
		}
		if hasNew && (!hasOld || oldLine != newLine) {
			diff += fmt.Sprintf("+ %s\n", newLine)
		}
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
