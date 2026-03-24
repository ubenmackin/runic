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

func ListGroups(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(),
		"SELECT id, name, COALESCE(description, '') FROM groups")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query groups")
		return
	}
	defer rows.Close()

	type groupResp struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}

	var groupsData []groupResp
	for rows.Next() {
		var g groupResp
		if err := rows.Scan(&g.ID, &g.Name, &g.Description); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan group")
			return
		}
		groupsData = append(groupsData, g)
	}
	if groupsData == nil {
		groupsData = []groupResp{}
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

	_, err = db.DB.ExecContext(r.Context(), "DELETE FROM groups WHERE id = ?", id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete group: %v", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Group Members ---

func ListGroupMembers(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid group ID")
		return
	}

	members, err := db.ListGroupMembers(r.Context(), db.DB.DB, id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query group members")
		return
	}

	common.RespondJSON(w, http.StatusOK, members)
}

func MakeAddGroupMemberHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid group ID")
			return
		}

		var input struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if input.Value == "" || input.Type == "" {
			common.RespondError(w, http.StatusBadRequest, "value and type are required")
			return
		}

		result, err := db.DB.ExecContext(r.Context(),
			"INSERT INTO group_members (group_id, value, type) VALUES (?, ?, ?)",
			groupID, input.Value, input.Type)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to add member: %v", err))
			return
		}

		id, _ := result.LastInsertId()

		// Trigger async recompilation for affected servers with timeout
		go func() {
			// Use background context so goroutine survives handler return
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := compiler.RecompileAffectedServers(ctx, groupID); err != nil {
				runiclog.ErrorContext(ctx, "async recompile affected servers failed",
					"group_id", groupID,
					"error", err)
			}
		}()

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

		memberID, err := common.ParseIDParam(r, "memberId")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid member ID")
			return
		}

		_, err = db.DB.ExecContext(r.Context(),
			"DELETE FROM group_members WHERE id = ? AND group_id = ?", memberID, groupID)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete member: %v", err))
			return
		}

		// Trigger async recompilation with timeout
		go func() {
			// Use background context so goroutine survives handler return
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if err := compiler.RecompileAffectedServers(ctx, groupID); err != nil {
				runiclog.ErrorContext(ctx, "async recompile affected servers failed",
					"group_id", groupID,
					"error", err)
			}
		}()

		w.WriteHeader(http.StatusNoContent)
	}
}
