package peers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"slices"

	"github.com/gorilla/mux"

	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/engine"
)

// Handler holds dependencies for peer handlers.
type Handler struct {
	DB       *sql.DB
	Compiler *engine.Compiler
}

// NewHandler creates a new peers handler.
func NewHandler(db *sql.DB, compiler *engine.Compiler) *Handler {
	return &Handler{DB: db, Compiler: compiler}
}

// hostnameRegex validates hostnames: 1-253 chars, alphanumeric with hyphens and dots,
// must start and end with alphanumeric (single-char hostnames allowed).
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

// validOSTypes is the list of allowed OS types for peer creation.
var validOSTypes = []string{"debian", "ubuntu", "rhel", "arch", "opensuse", "raspbian", "linux"}

// validArchs is the list of allowed architectures for peer creation.
var validArchs = []string{"amd64", "arm64", "arm", "armv6"}

// Peer is the JSON representation of a peer for API responses.
type Peer struct {
	ID                   int    `json:"id"`
	Hostname             string `json:"hostname"`
	IPAddress            string `json:"ip_address"`
	OSType               string `json:"os_type"`
	Arch                 string `json:"arch"`
	HasDocker            bool   `json:"has_docker"`
	IsManual             bool   `json:"is_manual"`
	AgentVersion         string `json:"agent_version"`
	LastHeartbeat        string `json:"last_heartbeat"`
	Groups               string `json:"groups"` // Comma-separated group names
	Status               string `json:"status"`
	BundleVersion        string `json:"bundle_version"`
	BundleVersionNumber  int    `json:"bundle_version_number"`
	Description          string `json:"description"`
	HMACKeyLastRotatedAt string `json:"hmac_key_last_rotated_at"`
	PendingChangesCount  int    `json:"pending_changes_count"`
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
		(SELECT COUNT(*) FROM pending_changes WHERE peer_id = p.id) as pending_changes_count
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
	defer rows.Close()

	var peers []Peer
	for rows.Next() {
		var p Peer
		var agentVersion, lastHeartbeat, description, hmacKeyLastRotatedAt sql.NullString
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.Arch, &p.HasDocker, &p.IsManual, &agentVersion, &lastHeartbeat, &p.Status, &p.BundleVersion, &p.BundleVersionNumber, &p.Groups, &description, &hmacKeyLastRotatedAt, &p.PendingChangesCount); err != nil {
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
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []Peer{}
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

	// Validate hostname: 1-253 chars, alphanumeric with hyphens and dots only
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
		common.RespondError(w, http.StatusBadRequest, "os_type must be one of: debian, ubuntu, rhel, arch, opensuse, raspbian, linux")
		return
	}

	// Validate arch if provided
	if input.Arch != "" && !slices.Contains(validArchs, input.Arch) {
		common.RespondError(w, http.StatusBadRequest, "arch must be one of: amd64, arm64, arm, armv6")
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

	// Generate HMAC key for the peer
	hmacKey, err := agents.GenerateHMACKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	result, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO peers (hostname, ip_address, os_type, agent_key, hmac_key, has_docker, is_manual) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		input.Hostname, input.IPAddress, input.OSType, agentKey, hmacKey, input.HasDocker, input.IsManual)
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

	// Update the peer (hostname, ip_address, os_type, arch, has_docker, and description are all editable)
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
		common.RespondError(w, http.StatusConflict, err.Error())
		return
	}

	// Delete from group_members first
	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup group_members for peer", "peer_id", peerID, "error", err)
	}

	// Delete any rule bundles (foreign key constraint)
	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM rule_bundles WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup rule_bundles for peer", "peer_id", peerID, "error", err)
	}

	// Delete any firewall logs for this peer
	if _, err := h.DB.ExecContext(r.Context(), "DELETE FROM firewall_logs WHERE peer_id = ?", peerID); err != nil {
		log.WarnContext(r.Context(), "failed to cleanup firewall_logs for peer", "peer_id", peerID, "error", err)
	}

	// Delete the peer
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
// This handler compiles fresh rules on each request to ensure no stale data is returned.
func (h *Handler) GetPeerBundle(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// Compile fresh rules for the peer to ensure current effective rules
	bundle, err := h.Compiler.CompileAndStore(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to compile rules", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"content":        bundle.RulesContent,
		"version_number": bundle.VersionNumber,
	})
}

// RegisterRoutes adds peer routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("", h.CreatePeer).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeletePeer).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/compile", h.CompilePeer).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/rotate-key", h.RotatePeerKey).Methods("POST")
}
