// Package peers provides API peers handlers.
package peers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/gorilla/mux"

	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// Handler holds dependencies for peer handlers.
type Handler struct {
	DB         db.Querier // For queries
	DBBeginner db.DB      // For transactions and queries
	Compiler   *engine.Compiler
	SSEHub     events.NotifyUpdateAgenter
}

// NewHandler creates a new peers handler.
func NewHandler(db *sql.DB, compiler *engine.Compiler, sseHub events.NotifyUpdateAgenter) *Handler {
	return &Handler{DB: db, DBBeginner: db, Compiler: compiler, SSEHub: sseHub}
}

// hostnameRegex validates hostnames: 1-253 chars, alphanumeric with hyphens and dots,
// must start and end with alphanumeric (single-char hostnames allowed).
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

// validOSTypes is the list of allowed OS types for peer creation.
var validOSTypes = []string{
	"debian", "ubuntu", "rhel", "arch", "opensuse", "raspbian", "linux",
	"armbian", "ios", "ipados", "macos", "tvos", "windows", "other",
}

// validArchs is the list of allowed architectures for peer creation.
var validArchs = []string{"amd64", "arm64", "arm", "armv6", "other"}

// PeerIP is the JSON representation of a peer IP for API responses.
type PeerIP struct {
	ID        int    `json:"id"`
	PeerID    int    `json:"peer_id"`
	IPAddress string `json:"ip_address"`
	IsPrimary bool   `json:"is_primary"`
}

// Peer is the JSON representation of a peer for API responses.
type Peer struct {
	ID                   int      `json:"id"`
	Hostname             string   `json:"hostname"`
	IPAddress            string   `json:"ip_address"`
	OSType               string   `json:"os_type"`
	Arch                 string   `json:"arch"`
	HasDocker            bool     `json:"has_docker"`
	IsManual             bool     `json:"is_manual"`
	AgentVersion         string   `json:"agent_version"`
	LastHeartbeat        string   `json:"last_heartbeat"`
	Groups               string   `json:"groups"` // Comma-separated group names
	Status               string   `json:"status"`
	BundleVersion        string   `json:"bundle_version"`
	BundleVersionNumber  int      `json:"bundle_version_number"`
	Description          string   `json:"description"`
	HMACKeyLastRotatedAt string   `json:"hmac_key_last_rotated_at"`
	PendingChangesCount  int      `json:"pending_changes_count"`
	SyncStatus           string   `json:"sync_status"`
	IPs                  []PeerIP `json:"ips"`
}

func (h *Handler) GetPeers(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
SELECT p.id, p.hostname, p.ip_address, p.os_type, p.arch, p.has_docker, p.is_manual,
COALESCE(p.agent_version, '') as agent_version,
COALESCE(p.last_heartbeat, '') as last_heartbeat,
CASE
WHEN p.last_heartbeat IS NULL THEN 'pending'
WHEN p.last_heartbeat < `+fmt.Sprintf("datetime('now', '-%d minutes')", constants.PeerOfflineThresholdMinutes)+` THEN 'offline'
ELSE COALESCE(p.status, 'online')
END as status,
COALESCE(p.bundle_version, '') as bundle_version,
COALESCE((SELECT rb.version_number FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1), 0) as bundle_version_number,
COALESCE(GROUP_CONCAT(g.name, ','), '') as groups,
COALESCE(p.description, '') as description,
COALESCE(p.hmac_key_last_rotated_at, '') as hmac_key_last_rotated_at,
(SELECT COUNT(*) FROM pending_changes pc JOIN peers p2 ON pc.peer_id = p2.id WHERE pc.peer_id = p.id AND p2.is_manual = 0) as pending_changes_count,
CASE
WHEN (SELECT COUNT(*) FROM pending_changes pc JOIN peers p2 ON pc.peer_id = p2.id WHERE pc.peer_id = p.id AND p2.is_manual = 0) > 0 THEN 'pending'
WHEN (SELECT rb.version FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1) IS NOT NULL
     AND (SELECT rb.version FROM rule_bundles rb WHERE rb.peer_id = p.id ORDER BY rb.created_at DESC LIMIT 1) != COALESCE(p.bundle_version, '') THEN 'pending_sync'
ELSE 'synced'
END as sync_status
FROM peers p
LEFT JOIN group_members gm ON p.id = gm.peer_id
LEFT JOIN groups g ON gm.group_id = g.id
GROUP BY p.id
ORDER BY p.hostname ASC
`)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peers")
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Failed to close rows", "error", cErr)
		}
	}()

	var peers []Peer
	for rows.Next() {
		var p Peer
		var agentVersion, lastHeartbeat, description, hmacKeyLastRotatedAt sql.NullString
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker, &p.IsManual, &agentVersion, &lastHeartbeat, &p.Status, &p.BundleVersion, &p.BundleVersionNumber, &p.Groups, &description, &hmacKeyLastRotatedAt, &p.PendingChangesCount, &p.SyncStatus); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan peer")
			return
		}
		if agentVersion.Valid {
			p.AgentVersion = agentVersion.String
		}
		if lastHeartbeat.Valid {
			p.LastHeartbeat = lastHeartbeat.String
		}
		if description.Valid {
			p.Description = description.String
		}
		if hmacKeyLastRotatedAt.Valid {
			p.HMACKeyLastRotatedAt = hmacKeyLastRotatedAt.String
		}
		p.IPs = []PeerIP{} // Initialize to empty slice instead of nil
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []Peer{}
	}

	// Fetch peer IPs for all peers in a single query
	ipRows, err := h.DB.QueryContext(r.Context(), `SELECT peer_id, ip_address, is_primary FROM peer_ips ORDER BY peer_id, is_primary DESC`)
	if err != nil {
		log.WarnContext(r.Context(), "failed to query peer_ips", "error", err)
		// Non-fatal: return peers without IPs
		common.RespondJSON(w, http.StatusOK, peers)
		return
	}
	defer func() {
		if cErr := ipRows.Close(); cErr != nil {
			log.Warn("Failed to close ip rows", "error", cErr)
		}
	}()

	// Build a map of peer_id -> []PeerIP
	ipMap := make(map[int][]PeerIP)
	for ipRows.Next() {
		var peerID int
		var ipAddr string
		var isPrimary int
		if err := ipRows.Scan(&peerID, &ipAddr, &isPrimary); err != nil {
			log.WarnContext(r.Context(), "failed to scan peer_ip", "error", err)
			continue
		}
		ipMap[peerID] = append(ipMap[peerID], PeerIP{
			IPAddress: ipAddr,
			IsPrimary: isPrimary == 1,
		})
	}

	// Attach IPs to each peer
	for i := range peers {
		if ips, ok := ipMap[peers[i].ID]; ok {
			peers[i].IPs = ips
		}
	}

	common.RespondJSON(w, http.StatusOK, peers)
}

func (h *Handler) CreatePeer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		OSType    string `json:"os_type"`
		Arch      string `json:"arch"`
		AgentKey  string `json:"agent_key"`
		HasDocker bool   `json:"has_docker"`
		IsManual  bool   `json:"is_manual"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if input.Hostname == "" || len(input.Hostname) > 253 || !hostnameRegex.MatchString(input.Hostname) {
		common.RespondError(w, http.StatusBadRequest, "hostname must be 1-253 characters, alphanumeric with hyphens and dots only")
		return
	}

	// Validate IP address
	if net.ParseIP(input.IPAddress) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	// Validate os_type if provided
	if input.OSType != "" && !slices.Contains(validOSTypes, input.OSType) {
		common.RespondError(w, http.StatusBadRequest, "os_type must be one of: "+strings.Join(validOSTypes, ", "))
		return
	}

	if input.Arch != "" && !slices.Contains(validArchs, input.Arch) {
		common.RespondError(w, http.StatusBadRequest, "arch must be one of: "+strings.Join(validArchs, ", "))
		return
	}

	// For manual peers, hostname and IP are required but agent_key is optional
	// For agent peers, hostname, IP, and agent_key are all required
	if !input.IsManual && input.AgentKey == "" {
		common.RespondError(w, http.StatusBadRequest, "agent_key is required for agent peers")
		return
	}

	// For manual peers, generate a placeholder agent_key if not provided
	agentKey := input.AgentKey
	if input.IsManual && agentKey == "" {
		agentKey = "manual-" + input.Hostname + "-" + input.IPAddress
	}

	hmacKey, err := agents.GenerateHMACKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO peers (hostname, ip_address, os_type, arch, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		input.Hostname, input.IPAddress, input.OSType, input.Arch, agentKey, hmacKey, input.HasDocker, input.IsManual)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create peer", "error", err)
		common.InternalError(w)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get insert ID", "error", err)
		common.InternalError(w)
		return
	}
	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// UpdatePeer updates a manual peer's hostname, IP, OS type, arch, has_docker, and description.
func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	var input struct {
		Hostname    string `json:"hostname"`
		IPAddress   string `json:"ip_address"`
		OSType      string `json:"os_type"`
		Arch        string `json:"arch"`
		HasDocker   bool   `json:"has_docker"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate hostname
	if input.Hostname != "" {
		if err := common.ValidateHostname(input.Hostname); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Validate IP address
	if input.IPAddress != "" {
		if err := common.ValidateIPAddress(input.IPAddress); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	// Validate this is a manual peer (only manual peers can be edited)
	var isManual bool
	err = h.DB.QueryRowContext(r.Context(), "SELECT is_manual FROM peers WHERE id = ?", id).Scan(&isManual)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}
	if !isManual {
		common.RespondError(w, http.StatusBadRequest, "can only edit manual peers")
		return
	}

	_, err = h.DB.ExecContext(r.Context(), "UPDATE peers SET hostname = ?, ip_address = ?, os_type = ?, arch = ?, has_docker = ?, description = ? WHERE id = ?", input.Hostname, input.IPAddress, input.OSType, input.Arch, input.HasDocker, input.Description, id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to update peer", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "peer updated"})
}

// CompilePeer compiles rules for a peer.
func (h *Handler) CompilePeer(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	bundle, err := h.Compiler.CompileAndStore(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "compilation failed", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"version": bundle.Version,
		"hmac":    bundle.HMAC,
		"size":    len(bundle.RulesContent),
	})
}

// DeletePeer deletes a peer after checking policy constraints.
func (h *Handler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// Check delete constraints (target_peer_id in policies, or in group used by policy)
	err = common.CheckPeerDeleteConstraints(r.Context(), h.DB, peerID)
	if err != nil {
		constraintErr, ok := err.(*common.DeleteConstraintError)
		if ok {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup group_members for peer", "peer_id", peerID, "error", err)
	}

	// Delete any rule bundles (foreign key constraint)
	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM rule_bundles WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup rule_bundles for peer", "peer_id", peerID, "error", err)
	}

	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM firewall_logs WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup firewall_logs for peer", "peer_id", peerID, "error", err)
	}

	result, err := h.DB.ExecContext(r.Context(), "DELETE FROM peers WHERE id = ?", peerID)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete peer")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.ErrorContext(r.Context(), "Failed to check delete result", "error", err)
		common.InternalError(w)
		return
	}
	if rowsAffected == 0 {
		common.RespondError(w, http.StatusNotFound, "Peer not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "Peer deleted"})
}

// GetPeerBundle returns the current effective rules for a peer.
// Supports include_pending query parameter:
// - include_pending=true: Returns the latest bundle (what's been compiled/applied but not necessarily synced)
// - include_pending=false or not provided: Returns the deployed bundle matching peers.bundle_version
func (h *Handler) GetPeerBundle(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	includePending := r.URL.Query().Get("include_pending") == "true"

	var query string
	var args []interface{}

	if includePending {
		query = `SELECT version, version_number, rules_content, hmac FROM rule_bundles WHERE peer_id = ? ORDER BY created_at DESC LIMIT 1`
		args = []interface{}{id}

		var version string
		var versionNumber int
		var rulesContent string
		var hmac string

		err = h.DB.QueryRowContext(r.Context(), query, args...).Scan(&version, &versionNumber, &rulesContent, &hmac)
		if err != nil {
			if err == sql.ErrNoRows {
				log.WarnContext(r.Context(), "no pending bundle found", "peer_id", id)
				common.RespondError(w, http.StatusNotFound, "bundle not found")
				return
			}
			log.ErrorContext(r.Context(), "failed to get pending bundle", "error", err)
			common.InternalError(w)
			return
		}

		var deployedVersion sql.NullString
		err = h.DB.QueryRowContext(r.Context(), "SELECT bundle_version FROM peers WHERE id = ?", id).Scan(&deployedVersion)
		if err != nil && err != sql.ErrNoRows {
			log.ErrorContext(r.Context(), "failed to get deployed version", "error", err)
			common.InternalError(w)
			return
		}

		response := map[string]interface{}{
			"version":        version,
			"version_number": versionNumber,
			"rules":          rulesContent,
			"hmac":           hmac,
		}

		if deployedVersion.Valid && deployedVersion.String != "" {
			var deployedContent sql.NullString
			err = h.DB.QueryRowContext(r.Context(),
				"SELECT rules_content FROM rule_bundles WHERE peer_id = ? AND version = ?",
				id, deployedVersion.String).Scan(&deployedContent)
			if err != nil && err != sql.ErrNoRows {
				log.ErrorContext(r.Context(), "failed to get deployed bundle", "error", err)
				// Don't fail the request, just don't include deployed content
			}
			if deployedContent.Valid {
				response["deployed_rules"] = deployedContent.String
				response["deployed_version"] = deployedVersion.String
			}
		}

		common.RespondJSON(w, http.StatusOK, response)
		return
	}

	query = `SELECT rb.version, rb.version_number, rb.rules_content, rb.hmac
		FROM rule_bundles rb
		JOIN peers p ON p.id = ?
		WHERE rb.version = p.bundle_version AND rb.peer_id = p.id
		ORDER BY rb.created_at DESC LIMIT 1`
	args = []interface{}{id}

	var version string
	var versionNumber int
	var rulesContent string
	var hmac string

	err = h.DB.QueryRowContext(r.Context(), query, args...).Scan(&version, &versionNumber, &rulesContent, &hmac)
	if err != nil {
		if err == sql.ErrNoRows {
			log.WarnContext(r.Context(), "no bundle found", "peer_id", id, "include_pending", includePending)
			common.RespondError(w, http.StatusNotFound, "bundle not found")
			return
		}
		log.ErrorContext(r.Context(), "failed to get bundle", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"version":        version,
		"version_number": versionNumber,
		"rules":          rulesContent,
		"hmac":           hmac,
	})
}

// GetPeerByIP looks up a peer by exact IP address.
// GET /api/v1/peers/by-ip?ip=<ip_address>
func (h *Handler) GetPeerByIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		common.RespondError(w, http.StatusBadRequest, "ip parameter required")
		return
	}

	// First, query for peer with exact IP match on primary ip_address
	var p Peer
	err := h.DB.QueryRowContext(r.Context(), "SELECT id, hostname, ip_address, is_manual FROM peers WHERE ip_address = ?", ip).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.IsManual)
	if err == nil {
		common.RespondJSON(w, http.StatusOK, p)
		return
	}
	if err != sql.ErrNoRows {
		common.InternalError(w)
		return
	}

	// Fallback: check peer_ips table for secondary IPs
	err = h.DB.QueryRowContext(r.Context(), "SELECT p.id, p.hostname, p.ip_address, p.is_manual FROM peers p JOIN peer_ips pi ON p.id = pi.peer_id WHERE pi.ip_address = ?", ip).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.IsManual)
	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusOK, nil) // No peer found
		return
	}
	if err != nil {
		common.InternalError(w)
		return
	}
	common.RespondJSON(w, http.StatusOK, p)
}

// GetPeerByHostname looks up a peer by exact hostname.
// GET /api/v1/peers/by-hostname?hostname=<hostname>
func (h *Handler) GetPeerByHostname(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		common.RespondError(w, http.StatusBadRequest, "hostname parameter required")
		return
	}

	// Query for peer with exact hostname match (case-sensitive)
	var p Peer
	err := h.DB.QueryRowContext(r.Context(), "SELECT id, hostname, ip_address, is_manual FROM peers WHERE hostname = ?", hostname).Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.IsManual)
	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusOK, nil) // No peer found
		return
	}
	if err != nil {
		common.InternalError(w)
		return
	}
	common.RespondJSON(w, http.StatusOK, p)
}

// GetPeerIPs returns all IPs for a given peer.
// GET /api/v1/peers/{id}/ips
func (h *Handler) GetPeerIPs(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// Check if peer exists
	var exists int
	err = h.DB.QueryRowContext(r.Context(), "SELECT 1 FROM peers WHERE id = ?", id).Scan(&exists)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	rows, err := h.DB.QueryContext(r.Context(), "SELECT id, peer_id, ip_address, is_primary FROM peer_ips WHERE peer_id = ? ORDER BY is_primary DESC, id ASC", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IPs")
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Failed to close rows", "error", cErr)
		}
	}()

	var peerIPs []PeerIP
	for rows.Next() {
		var pip PeerIP
		var isPrimary int
		if err := rows.Scan(&pip.ID, &pip.PeerID, &pip.IPAddress, &isPrimary); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan peer IP")
			return
		}
		pip.IsPrimary = isPrimary == 1
		peerIPs = append(peerIPs, pip)
	}
	if peerIPs == nil {
		peerIPs = []PeerIP{}
	}
	common.RespondJSON(w, http.StatusOK, peerIPs)
}

// AddPeerIP adds a secondary IP to a peer.
// POST /api/v1/peers/{id}/ips
func (h *Handler) AddPeerIP(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	var input struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate IP address
	if net.ParseIP(input.IPAddress) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	// Check if peer exists
	var exists int
	err = h.DB.QueryRowContext(r.Context(), "SELECT 1 FROM peers WHERE id = ?", id).Scan(&exists)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	// Check for duplicate IP for same peer
	var duplicateCount int
	err = h.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM peer_ips WHERE peer_id = ? AND ip_address = ?", id, input.IPAddress).Scan(&duplicateCount)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check duplicate IP")
		return
	}
	if duplicateCount > 0 {
		common.RespondError(w, http.StatusConflict, "IP address already exists for this peer")
		return
	}

	result, err := h.DB.ExecContext(r.Context(), "INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 0)", id, input.IPAddress)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to add peer IP", "error", err)
		common.InternalError(w)
		return
	}

	ipID, err := result.LastInsertId()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get insert ID", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusCreated, PeerIP{
		ID:        int(ipID),
		PeerID:    id,
		IPAddress: input.IPAddress,
		IsPrimary: false,
	})
}

// DeletePeerIP removes a secondary IP from a peer.
// DELETE /api/v1/peers/{id}/ips/{ip_id}
func (h *Handler) DeletePeerIP(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ipID, err := common.ParseIDParam(r, "ip_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP ID")
		return
	}

	// Check if peer exists
	var peerExists int
	err = h.DB.QueryRowContext(r.Context(), "SELECT 1 FROM peers WHERE id = ?", peerID).Scan(&peerExists)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	// Check if the peer_ip entry exists and belongs to this peer
	var isPrimary int
	err = h.DB.QueryRowContext(r.Context(), "SELECT is_primary FROM peer_ips WHERE id = ? AND peer_id = ?", ipID, peerID).Scan(&isPrimary)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer IP not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IP")
		return
	}

	// Cannot delete primary IP
	if isPrimary == 1 {
		common.RespondError(w, http.StatusBadRequest, "cannot delete primary IP address")
		return
	}

	// Get the IP address for this peer_ip entry (needed for policy check)
	var ipAddress string
	err = h.DB.QueryRowContext(r.Context(), "SELECT ip_address FROM peer_ips WHERE id = ? AND peer_id = ?", ipID, peerID).Scan(&ipAddress)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IP address")
		return
	}

	// Check if this IP is referenced by any policies
	var policyCount int
	err = h.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM policies WHERE (source_id = ? AND source_ip = ?) OR (target_id = ? AND target_ip = ?)", peerID, ipAddress, peerID, ipAddress).Scan(&policyCount)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check policy references")
		return
	}
	if policyCount > 0 {
		common.RespondError(w, http.StatusConflict, fmt.Sprintf("cannot delete IP: referenced by %d policy/policies", policyCount))
		return
	}

	result, err := h.DB.ExecContext(r.Context(), "DELETE FROM peer_ips WHERE id = ? AND peer_id = ?", ipID, peerID)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to delete peer IP")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to check delete result", "error", err)
		common.InternalError(w)
		return
	}
	if rowsAffected == 0 {
		common.RespondError(w, http.StatusNotFound, "peer IP not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateAgent sends an update_agent SSE event to the agent peer.
// POST /api/v1/peers/{id}/update-agent
func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}
	ctx := r.Context()

	// Look up the peer
	var hostname string
	var isManual bool
	err = h.DB.QueryRowContext(ctx, "SELECT hostname, is_manual FROM peers WHERE id = ?", peerID).Scan(&hostname, &isManual)
	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if isManual {
		common.RespondError(w, http.StatusBadRequest, "cannot update a manual peer")
		return
	}

	// Get instance URL from system_config for the control plane URL
	var instanceURL string
	err = h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'instance_url'").Scan(&instanceURL)
	if err != nil || instanceURL == "" {
		common.RespondError(w, http.StatusBadRequest, "instance URL not configured — set it in Settings to enable agent updates")
		return
	}

	// Get the SSE hub
	if h.SSEHub == nil {
		common.RespondError(w, http.StatusInternalServerError, "SSE hub not available")
		return
	}
	hostID := fmt.Sprintf("host-%s", hostname)
	h.SSEHub.NotifyUpdateAgent(hostID, instanceURL)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "update_sent"})
}

// RegisterRoutes adds peer routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("", h.CreatePeer).Methods("POST")
	r.HandleFunc("/by-ip", h.GetPeerByIP).Methods("GET")
	r.HandleFunc("/by-hostname", h.GetPeerByHostname).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeletePeer).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/compile", h.CompilePeer).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/rotate-key", h.RotatePeerKey).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips", h.GetPeerIPs).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/ips", h.AddPeerIP).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips/{ip_id:[0-9]+}", h.DeletePeerIP).Methods("DELETE")
}
