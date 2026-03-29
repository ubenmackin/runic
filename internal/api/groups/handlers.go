package groups

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"runic/internal/api/common"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// --- Groups ---

// GroupWithCounts represents a group with peer and policy counts
type GroupWithCounts struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsSystem    bool   `json:"is_system"`
	PeerCount   int    `json:"peer_count"`
	PolicyCount int    `json:"policy_count"`
}

func ListGroups(w http.ResponseWriter, r *http.Request) {
	query := `
	SELECT g.id, g.name, COALESCE(g.description, ''), COALESCE(g.is_system, 0),
	COALESCE(p.peer_count, 0), COALESCE(pol.policy_count, 0)
	FROM groups g
	LEFT JOIN (SELECT group_id, COUNT(*) as peer_count FROM group_members GROUP BY group_id) p ON g.id = p.group_id
	LEFT JOIN (
		SELECT group_id, SUM(count) as policy_count FROM (
			SELECT source_id as group_id, COUNT(*) as count FROM policies WHERE source_type='group' GROUP BY source_id
			UNION ALL
			SELECT target_id as group_id, COUNT(*) as count FROM policies WHERE target_type='group' GROUP BY target_id
		) GROUP BY group_id
	) pol ON g.id = pol.group_id
	ORDER BY g.name ASC`

	rows, err := db.DB.QueryContext(r.Context(), query)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query groups")
		return
	}
	defer rows.Close()

	var groupsData []GroupWithCounts
	for rows.Next() {
		var g GroupWithCounts
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem, &g.PeerCount, &g.PolicyCount); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan group")
			return
		}
		groupsData = append(groupsData, g)
	}
	if groupsData == nil {
		groupsData = []GroupWithCounts{}
	}
	common.RespondJSON(w, http.StatusOK, groupsData)
}

func CreateGroup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "name is required")
		return
	}

	result, err := db.DB.ExecContext(r.Context(),
		"INSERT INTO groups (name, description) VALUES (?, ?)", input.Name, input.Description)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create group: %v", err))
		return
	}

	id, _ := result.LastInsertId()
	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func GetGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	g, err := db.GetGroup(r.Context(), db.DB.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "group not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, g)
}

func UpdateGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	_, err = db.DB.ExecContext(r.Context(),
		"UPDATE groups SET name = ?, description = ? WHERE id = ?", input.Name, input.Description, id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update group: %v", err))
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	// Query the group to get its is_system flag
	var isSystem bool
	err = db.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM groups WHERE id = ?", id).Scan(&isSystem)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "group not found")
		return
	}

	// Block deletion of system groups
	if isSystem {
		common.RespondError(w, http.StatusForbidden, "Cannot delete system group")
		return
	}

	// Check if group is used by any policy
	if err := common.CheckGroupDeleteConstraints(r.Context(), db.DB.DB, id); err != nil {
		common.RespondError(w, http.StatusConflict, err.Error())
		return
	}

	// Delete group_members first (due to foreign key)
	_, err = db.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE group_id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete group members: %v", err))
		return
	}

	// Delete the group
	_, err = db.DB.ExecContext(r.Context(), "DELETE FROM groups WHERE id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete group: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Group Members ---

// PeerInGroup represents a peer that belongs to a group
type PeerInGroup struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	OSType    string `json:"os_type"`
	IsManual  bool   `json:"is_manual"`
}

func ListGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	query := `
		SELECT p.id, p.hostname, p.ip_address, p.os_type, p.is_manual
		FROM peers p
		JOIN group_members gm ON p.id = gm.peer_id
		WHERE gm.group_id = ?
		ORDER BY p.hostname ASC`

	rows, err := db.DB.QueryContext(r.Context(), query, id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query group members")
		return
	}
	defer rows.Close()

	var peers []PeerInGroup
	for rows.Next() {
		var p PeerInGroup
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.IsManual); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan peer")
			return
		}
		peers = append(peers, p)
	}
	if peers == nil {
		peers = []PeerInGroup{}
	}

	common.RespondJSON(w, http.StatusOK, peers)
}

func MakeAddGroupMemberHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid group ID")
			return
		}

		var input struct {
			PeerID int `json:"peer_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if input.PeerID == 0 {
			common.RespondError(w, http.StatusBadRequest, "peer_id is required")
			return
		}

		result, err := db.DB.ExecContext(r.Context(),
			"INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)",
			groupID, input.PeerID)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to add member: %v", err))
			return
		}

		id, _ := result.LastInsertId()

		// Trigger async recompilation for affected peers with timeout (if compiler is available)
		if compiler != nil {
			go func() {
				// Use background context so goroutine survives handler return
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := compiler.RecompileAffectedPeers(ctx, groupID); err != nil {
					runiclog.ErrorContext(ctx, "async recompile affected peers failed",
						"group_id", groupID,
						"error", err)
				}
			}()
		}

		common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
	}
}

func MakeDeleteGroupMemberHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID, err := common.ParseIDParam(r, "groupId")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid group ID")
			return
		}

		peerID, err := common.ParseIDParam(r, "peerId")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
			return
		}

		_, err = db.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE group_id = ? AND peer_id = ?", groupID, peerID)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove peer from group: %v", err))
			return
		}

		// Trigger async recompilation with timeout (if compiler is available)
		if compiler != nil {
			go func() {
				// Use background context so goroutine survives handler return
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				if err := compiler.RecompileAffectedPeers(ctx, groupID); err != nil {
					runiclog.ErrorContext(ctx, "async recompile affected peers failed",
						"group_id", groupID,
						"error", err)
				}
			}()
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
