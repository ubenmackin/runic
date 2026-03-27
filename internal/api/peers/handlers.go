package peers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"

	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/db"
	"runic/internal/engine"
)

// Peer is the JSON representation of a peer for API responses.
type Peer struct {
	ID            int    `json:"id"`
	Hostname      string `json:"hostname"`
	IPAddress     string `json:"ip_address"`
	OSType        string `json:"os_type"`
	IsManual      bool   `json:"is_manual"`
	AgentVersion  string `json:"agent_version"`
	LastHeartbeat string `json:"last_heartbeat"`
	Groups        string `json:"groups"` // Comma-separated group names
}

func GetPeers(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}
	rows, err := db.DB.QueryContext(r.Context(), `
		SELECT id, hostname, ip_address, os_type, is_manual, 
		       COALESCE(agent_version, '') as agent_version,
		       COALESCE(last_heartbeat, '') as last_heartbeat
		FROM peers
		ORDER BY hostname ASC
	`)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peers")
		return
	}
	defer rows.Close()

	var peers []Peer
	for rows.Next() {
		var p Peer
		var agentVersion, lastHeartbeat sql.NullString
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.IsManual, &agentVersion, &lastHeartbeat); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan peer")
			return
		}
		if agentVersion.Valid {
			p.AgentVersion = agentVersion.String
		}
		if lastHeartbeat.Valid {
			p.LastHeartbeat = lastHeartbeat.String
		}
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []Peer{}
	}
	common.RespondJSON(w, http.StatusOK, peers)
}

func CreatePeer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		AgentKey  string `json:"agent_key"`
		HasDocker bool   `json:"has_docker"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.Hostname == "" || input.IPAddress == "" || input.AgentKey == "" {
		common.RespondError(w, http.StatusBadRequest, "hostname, ip_address, and agent_key are required")
		return
	}

	// Generate HMAC key for the peer
	hmacKey := agents.GenerateHMACKey()

	result, err := db.DB.ExecContext(r.Context(),
		`INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		input.Hostname, input.IPAddress, input.AgentKey, hmacKey, input.HasDocker)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create peer: %v", err))
		return
	}

	id, _ := result.LastInsertId()
	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// MakeCompilePeerHandler injects the Compiler dependency for peer rule compilation.
func MakeCompilePeerHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
			return
		}

		bundle, err := compiler.CompileAndStore(r.Context(), id)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("compilation failed: %v", err))
			return
		}

		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"version": bundle.Version,
			"hmac":    bundle.HMAC,
			"size":    len(bundle.RulesContent),
		})
	}
}

// DeletePeer deletes a peer after checking policy constraints.
func DeletePeer(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// CONSTRAINT CHECK 1: Is peer referenced as target_peer_id in any policy?
	var policyName string
	err = db.DB.QueryRowContext(r.Context(),
		`SELECT name FROM policies WHERE target_peer_id = ? LIMIT 1`, peerID,
	).Scan(&policyName)
	if err == nil {
		// Peer is used in a policy - block deletion
		common.RespondError(w, http.StatusConflict,
			fmt.Sprintf("Cannot delete peer — it is used in policy '%s'", policyName))
		return
	}

	// Safe to delete - delete any rule bundles first (foreign key constraint)
	db.DB.ExecContext(r.Context(), "DELETE FROM rule_bundles WHERE peer_id = ?", peerID)

	// Delete any firewall logs for this peer
	db.DB.ExecContext(r.Context(), "DELETE FROM firewall_logs WHERE peer_id = ?", peerID)

	// Delete the peer
	result, err := db.DB.ExecContext(r.Context(), "DELETE FROM peers WHERE id = ?", peerID)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete peer")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		common.RespondError(w, http.StatusNotFound, "Peer not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "Peer deleted"})
}

// GetPeerGroups returns all groups that reference this peer via group_members.
// Note: This is for future use when groups contain peer references.
// Currently, groups contain IP/CIDR values, not peer IDs.
func GetPeerGroups(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// Get the peer's IP address to find matching groups
	var ipAddress string
	err = db.DB.QueryRowContext(r.Context(), "SELECT ip_address FROM peers WHERE id = ?", peerID).Scan(&ipAddress)
	if err != nil {
		if err == sql.ErrNoRows {
			common.RespondError(w, http.StatusNotFound, "Peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to fetch peer")
		return
	}

	// Find groups where this peer's IP is a member (as an IP or CIDR match)
	// This is a simplified version - in production, you'd do proper CIDR matching
	rows, err := db.DB.QueryContext(r.Context(), `
		SELECT DISTINCT g.id, g.name
		FROM groups g
		JOIN group_members gm ON g.id = gm.group_id
		WHERE gm.value = ? OR gm.type = 'group_ref'
		ORDER BY g.name
	`, ipAddress)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to fetch peer groups")
		return
	}
	defer rows.Close()

	var groups []map[string]interface{}
	for rows.Next() {
		var id int
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "Failed to scan group")
			return
		}
		groups = append(groups, map[string]interface{}{
			"id":   id,
			"name": name,
		})
	}
	if groups == nil {
		groups = []map[string]interface{}{}
	}

	common.RespondJSON(w, http.StatusOK, groups)
}
