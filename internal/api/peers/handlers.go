package peers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
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

	// Check delete constraints (target_peer_id in policies, or in group used by policy)
	err = common.CheckPeerDeleteConstraints(r.Context(), db.DB.DB, peerID)
	if err != nil {
		common.RespondError(w, http.StatusConflict, err.Error())
		return
	}

	// Delete from group_members first
	if _, err := db.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE peer_id = ?", peerID); err != nil {
		log.Printf("WARN: Failed to cleanup group_members for peer %d: %v", peerID, err)
	}

	// Delete any rule bundles (foreign key constraint)
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
