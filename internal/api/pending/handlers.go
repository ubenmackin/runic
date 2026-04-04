package pending

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/db"
	"runic/internal/engine"
)

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
func ListPendingChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	database := db.DB.DB

	// Get all peers with pending changes
	peerIDs, err := db.GetPeersWithPendingChanges(ctx, database)
	if err != nil {
		log.Printf("ERROR: failed to get peers with pending changes: %v", err)
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
			log.Printf("ERROR: failed to get pending changes for peer %d: %v", peerID, err)
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
func GetPeerPendingChanges(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "peerId")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ctx := r.Context()
	database := db.DB.DB

	// Verify peer exists
	var hostname, ipAddress string
	err = database.QueryRowContext(ctx, "SELECT hostname, ip_address FROM peers WHERE id = ?", peerID).Scan(&hostname, &ipAddress)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		log.Printf("ERROR: failed to query peer: %v", err)
		common.InternalError(w)
		return
	}

	changes, err := db.GetPendingChangesForPeer(ctx, database, peerID)
	if err != nil {
		log.Printf("ERROR: failed to get pending changes: %v", err)
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

// MakePreviewPeerPendingBundleHandler compiles a bundle for a peer, generates a diff against the current bundle, and stores the preview.
func MakePreviewPeerPendingBundleHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID, err := common.ParseIDParam(r, "peerId")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
			return
		}

		ctx := r.Context()
		database := db.DB.DB

		// Verify peer exists
		var hostname string
		err = database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
		if err == sql.ErrNoRows {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		if err != nil {
			log.Printf("ERROR: failed to query peer: %v", err)
			common.InternalError(w)
			return
		}

		// Compile fresh bundle
		content, err := compiler.Compile(ctx, peerID)
		if err != nil {
			log.Printf("ERROR: failed to compile bundle for peer %d: %v", peerID, err)
			common.InternalError(w)
			return
		}

		version := engine.Version(content)

		// Get current bundle for diff
		var currentContent string
		var currentVersion string
		err = database.QueryRowContext(ctx, `
			SELECT rules_content, version FROM rule_bundles 
			WHERE peer_id = ? 
			ORDER BY id DESC LIMIT 1
		`, peerID).Scan(&currentContent, &currentVersion)
		if err != nil && err != sql.ErrNoRows {
			log.Printf("WARN: failed to get current bundle for diff: %v", err)
		}

		// Generate diff
		diffContent := generateDiff(currentContent, content, currentVersion, version)

		// Save preview
		err = db.SavePendingBundlePreview(ctx, database, peerID, content, diffContent, version)
		if err != nil {
			log.Printf("ERROR: failed to save bundle preview: %v", err)
			common.InternalError(w)
			return
		}

		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"version":         version,
			"current_version": currentVersion,
			"new_version":     version,
			"is_different":    version != currentVersion,
			"diff":            diffContent,
			"rules_content":   content,
		})
	}
}

// MakeApplyPeerPendingBundleHandler compiles and stores a bundle for a peer, clears pending changes, and triggers SSE notification.
func MakeApplyPeerPendingBundleHandler(compiler *engine.Compiler, sseHub *events.SSEHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		peerID, err := common.ParseIDParam(r, "peerId")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
			return
		}

		ctx := r.Context()
		database := db.DB.DB

		// Verify peer exists and get hostname
		var hostname string
		err = database.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", peerID).Scan(&hostname)
		if err == sql.ErrNoRows {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		if err != nil {
			log.Printf("ERROR: failed to query peer: %v", err)
			common.InternalError(w)
			return
		}

		// Compile and store the bundle
		bundle, err := compiler.CompileAndStore(ctx, peerID)
		if err != nil {
			log.Printf("ERROR: failed to compile and store bundle for peer %d: %v", peerID, err)
			common.InternalError(w)
			return
		}

		// Clear pending changes for this peer
		err = db.ClearPendingChangesForPeer(ctx, database, peerID)
		if err != nil {
			log.Printf("WARN: failed to clear pending changes for peer %d: %v", peerID, err)
			// Don't fail the request — bundle was applied successfully
		}

		// Delete any pending preview
		db.DeletePendingBundlePreview(ctx, database, peerID)

		// Notify via SSE (use hostname as the host_id for SSE)
		sseHub.NotifyBundleUpdated("host-"+hostname, bundle.Version)

		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "applied",
			"version": bundle.Version,
		})
	}
}

// MakeApplyAllPendingBundlesHandler applies pending bundles for all peers with pending changes.
func MakeApplyAllPendingBundlesHandler(compiler *engine.Compiler, sseHub *events.SSEHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		database := db.DB.DB

		// Get all peers with pending changes
		peerIDs, err := db.GetPeersWithPendingChanges(ctx, database)
		if err != nil {
			log.Printf("ERROR: failed to get peers with pending changes: %v", err)
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
			if err := applyBundleForPeer(ctx, database, compiler, sseHub, peerID); err != nil {
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
}

// MakePushAllRulesHandler compiles and pushes rules to ALL peers in the database,
// regardless of whether they have pending changes. This is used for the "Push Rules to All"
// dashboard action.
func MakePushAllRulesHandler(compiler *engine.Compiler, sseHub *events.SSEHub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		database := db.DB.DB

		// Get ALL peers from the database (not just those with pending changes)
		rows, err := database.QueryContext(ctx, "SELECT id, hostname FROM peers ORDER BY hostname")
		if err != nil {
			log.Printf("ERROR: failed to query all peers: %v", err)
			common.InternalError(w)
			return
		}
		defer rows.Close()

		type peerInfo struct {
			id       int
			hostname string
		}

		var allPeers []peerInfo
		for rows.Next() {
			var p peerInfo
			if err := rows.Scan(&p.id, &p.hostname); err != nil {
				log.Printf("WARN: failed to scan peer: %v", err)
				continue
			}
			allPeers = append(allPeers, p)
		}

		if err := rows.Err(); err != nil {
			log.Printf("ERROR: error iterating peers: %v", err)
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

		pushed := 0
		var errors []string
		for _, p := range allPeers {
			// Compile and store the bundle (similar to applyBundleForPeer but without clearing pending)
			bundle, err := compiler.CompileAndStore(ctx, p.id)
			if err != nil {
				errors = append(errors, fmt.Sprintf("peer %d (%s): %v", p.id, p.hostname, err))
				continue
			}

			// Notify via SSE
			sseHub.NotifyBundleUpdated("host-"+p.hostname, bundle.Version)
			pushed++
		}

		resp := map[string]interface{}{
			"status": "completed",
			"pushed": pushed,
			"total":  len(allPeers),
		}
		if len(errors) > 0 {
			resp["errors"] = errors
		}

		common.RespondJSON(w, http.StatusOK, resp)
	}
}

// applyBundleForPeer compiles, stores, and clears pending for a single peer.
func applyBundleForPeer(ctx context.Context, database *sql.DB, compiler *engine.Compiler, sseHub *events.SSEHub, peerID int) error {
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
		log.Printf("WARN: failed to clear pending changes for peer %d: %v", peerID, err)
	}
	db.DeletePendingBundlePreview(ctx, database, peerID)

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
