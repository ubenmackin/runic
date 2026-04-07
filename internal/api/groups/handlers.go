// Package groups provides group management handlers.
package groups

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
)

// Handler provides HTTP handlers for group operations with dependency injection
type Handler struct {
	DB           db.Querier
	Compiler     *engine.Compiler
	ChangeWorker *common.ChangeWorker
}

// NewHandler creates a new groups handler with the given dependencies
func NewHandler(db db.Querier, compiler *engine.Compiler, changeWorker *common.ChangeWorker) *Handler {
	return &Handler{DB: db, Compiler: compiler, ChangeWorker: changeWorker}
}

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

func (h *Handler) ListGroups(w http.ResponseWriter, r *http.Request) {
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

	rows, err := h.DB.QueryContext(r.Context(), query)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query groups")
		return
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.ErrorContext(r.Context(), "failed to close rows", "error", cerr)
		}
	}()

	var groupsData []GroupWithCounts
	for rows.Next() {
		var g GroupWithCounts
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.IsSystem, &g.PeerCount, &g.PolicyCount); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan group")
			return
		}
		groupsData = append(groupsData, g)
	}
	groupsData = common.EnsureSlice(groupsData)
	common.RespondJSON(w, http.StatusOK, groupsData)
}

func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate name
	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}
	if input.Name == "" {
		common.RespondError(w, http.StatusBadRequest, "name is required")
		return
	}

	result, err := h.DB.ExecContext(r.Context(),
		"INSERT INTO groups (name, description) VALUES (?, ?)", input.Name, input.Description)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create group", "error", err)
		common.InternalError(w)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get insert ID", "error", err)
		common.InternalError(w)
		return
	}

	// Trigger async recompilation for affected peers (if ChangeWorker is available)
	if h.ChangeWorker != nil {
		// Fetch group details for summary
		group, groupErr := db.GetGroup(r.Context(), h.DB, int(id))

		var summary string
		if groupErr == nil {
			summary = fmt.Sprintf("Group '%s' created", group.Name)
		} else {
			summary = "Group created"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, int(id), "create", summary)
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) GetGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	g, err := db.GetGroup(r.Context(), h.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "group not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, g)
}

func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
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

	// Validate name
	if input.Name != "" {
		if err := common.ValidateName(input.Name); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	_, err = h.DB.ExecContext(r.Context(),
		"UPDATE groups SET name = ?, description = ? WHERE id = ?", input.Name, input.Description, id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to update group", "error", err)
		common.InternalError(w)
		return
	}

	// Trigger async recompilation for affected peers (if ChangeWorker is available)
	if h.ChangeWorker != nil {
		// Fetch group details for summary
		group, groupErr := db.GetGroup(r.Context(), h.DB, id)

		var summary string
		if groupErr == nil {
			summary = fmt.Sprintf("Group '%s' updated", group.Name)
		} else {
			summary = "Group updated"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, id, "update", summary)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (h *Handler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	// Query the group to get its is_system flag
	var isSystem bool
	err = h.DB.QueryRowContext(r.Context(), "SELECT COALESCE(is_system, 0) FROM groups WHERE id = ?", id).Scan(&isSystem)
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
	constraintErr, ok := common.CheckGroupDeleteConstraints(r.Context(), h.DB, id).(*common.DeleteConstraintError)
	if ok && constraintErr != nil {
		common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
		return
	}

	// Delete group_members first (due to foreign key)
	_, err = h.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE group_id = ?", id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to delete group members", "error", err)
		common.InternalError(w)
		return
	}

	// Delete the group
	_, err = h.DB.ExecContext(r.Context(), "DELETE FROM groups WHERE id = ?", id)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to delete group", "error", err)
		common.InternalError(w)
		return
	}

	// Trigger async recompilation for affected peers (if ChangeWorker is available)
	if h.ChangeWorker != nil {
		summary := "Group deleted"
		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, id, "delete", summary)
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

func (h *Handler) ListGroupMembers(w http.ResponseWriter, r *http.Request) {
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

	rows, err := h.DB.QueryContext(r.Context(), query, id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query group members")
		return
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.ErrorContext(r.Context(), "failed to close rows", "error", cerr)
		}
	}()

	var peers []PeerInGroup
	for rows.Next() {
		var p PeerInGroup
		if err := rows.Scan(&p.ID, &p.Hostname, &p.IPAddress, &p.OSType, &p.IsManual); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan peer")
			return
		}
		peers = append(peers, p)
	}
	peers = common.EnsureSlice(peers)

	common.RespondJSON(w, http.StatusOK, peers)
}

func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
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

	result, err := h.DB.ExecContext(r.Context(), "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)", groupID, input.PeerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to add member", "error", err)
		common.InternalError(w)
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		log.ErrorContext(r.Context(), "failed to get insert ID", "error", err)
		common.InternalError(w)
		return
	}

	// Trigger async recompilation for affected peers (if ChangeWorker is available)
	if h.ChangeWorker != nil {
		// Fetch peer and group details for enhanced summary
		peer, peerErr := db.GetPeer(r.Context(), h.DB, input.PeerID)
		group, groupErr := db.GetGroup(r.Context(), h.DB, groupID)

		var summary string
		if peerErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' added to group '%s'", peer.Hostname, group.Name)
		} else {
			summary = "Peer added to group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, groupID, "update", summary)
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) DeleteGroupMember(w http.ResponseWriter, r *http.Request) {
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

	_, err = h.DB.ExecContext(r.Context(), "DELETE FROM group_members WHERE group_id = ? AND peer_id = ?", groupID, peerID)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to remove peer from group", "error", err)
		common.InternalError(w)
		return
	}

	// Trigger async recompilation (if ChangeWorker is available)
	if h.ChangeWorker != nil {
		// Fetch peer and group details for enhanced summary
		peer, peerErr := db.GetPeer(r.Context(), h.DB, peerID)
		group, groupErr := db.GetGroup(r.Context(), h.DB, groupID)

		var summary string
		if peerErr == nil && groupErr == nil {
			summary = fmt.Sprintf("Peer '%s' removed from group '%s'", peer.Hostname, group.Name)
		} else {
			summary = "Peer removed from group"
		}

		h.ChangeWorker.QueueGroupChange(r.Context(), h.DB, h.Compiler, groupID, "update", summary)
	}

	w.WriteHeader(http.StatusNoContent)
}

// RegisterRoutes adds group routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.ListGroups).Methods("GET")
	r.HandleFunc("", h.CreateGroup).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}", h.GetGroup).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdateGroup).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeleteGroup).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/members", h.ListGroupMembers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/members", h.AddGroupMember).Methods("POST")
	r.HandleFunc("/{groupId:[0-9]+}/members/{peerId:[0-9]+}", h.DeleteGroupMember).Methods("DELETE")
}
