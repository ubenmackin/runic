package policies

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

func ListPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(),
		`SELECT id, name, COALESCE(description, ''), source_group_id, service_id,
		target_server_id, action, priority, enabled, created_at, updated_at
		FROM policies ORDER BY priority ASC`)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query policies")
		return
	}
	defer rows.Close()

	type policyResp struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		Description    string `json:"description"`
		SourceGroupID  int    `json:"source_group_id"`
		ServiceID      int    `json:"service_id"`
		TargetServerID int    `json:"target_server_id"`
		Action         string `json:"action"`
		Priority       int    `json:"priority"`
		Enabled        bool   `json:"enabled"`
		CreatedAt      string `json:"created_at"`
		UpdatedAt      string `json:"updated_at"`
	}

	var policiesData []policyResp
	for rows.Next() {
		var p policyResp
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceGroupID, &p.ServiceID,
			&p.TargetServerID, &p.Action, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan policy")
			return
		}
		policiesData = append(policiesData, p)
	}
	if policiesData == nil {
		policiesData = []policyResp{}
	}
	common.RespondJSON(w, http.StatusOK, policiesData)
}

func MakeCreatePolicyHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name           string `json:"name"`
			Description    string `json:"description"`
			SourceGroupID  int    `json:"source_group_id"`
			ServiceID      int    `json:"service_id"`
			TargetServerID int    `json:"target_server_id"`
			Action         string `json:"action"`
			Priority       int    `json:"priority"`
			Enabled        *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if input.Name == "" || input.SourceGroupID == 0 || input.ServiceID == 0 || input.TargetServerID == 0 {
			common.RespondError(w, http.StatusBadRequest, "name, source_group_id, service_id, and target_server_id are required")
			return
		}
		if input.Action == "" {
			input.Action = "ACCEPT"
		}
		if input.Priority == 0 {
			input.Priority = 100
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		result, err := db.DB.ExecContext(r.Context(),
			`INSERT INTO policies (name, description, source_group_id, service_id, target_server_id, action, priority, enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			input.Name, input.Description, input.SourceGroupID, input.ServiceID,
			input.TargetServerID, input.Action, input.Priority, enabled)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create policy: %v", err))
			return
		}

		id, _ := result.LastInsertId()

		// Trigger async recompilation for the target server with timeout
		go func() {
			// Use background context so goroutine survives handler return
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if _, err := compiler.CompileAndStore(ctx, input.TargetServerID); err != nil {
				runiclog.ErrorContext(ctx, "async compile and store failed",
					"server_id", input.TargetServerID,
					"error", err)
			}
		}()

		common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
	}
}

func GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
		return
	}

	var p struct {
		ID             int    `json:"id"`
		Name           string `json:"name"`
		Description    string `json:"description"`
		SourceGroupID  int    `json:"source_group_id"`
		ServiceID      int    `json:"service_id"`
		TargetServerID int    `json:"target_server_id"`
		Action         string `json:"action"`
		Priority       int    `json:"priority"`
		Enabled        bool   `json:"enabled"`
		CreatedAt      string `json:"created_at"`
		UpdatedAt      string `json:"updated_at"`
	}

	err = db.DB.QueryRowContext(r.Context(),
		`SELECT id, name, COALESCE(description, ''), source_group_id, service_id,
		target_server_id, action, priority, enabled, created_at, updated_at
		FROM policies WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.SourceGroupID, &p.ServiceID,
		&p.TargetServerID, &p.Action, &p.Priority, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		common.RespondError(w, http.StatusNotFound, "policy not found")
		return
	}

	common.RespondJSON(w, http.StatusOK, p)
}

func MakeUpdatePolicyHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
			return
		}

		var input struct {
			Name           string `json:"name"`
			Description    string `json:"description"`
			SourceGroupID  int    `json:"source_group_id"`
			ServiceID      int    `json:"service_id"`
			TargetServerID int    `json:"target_server_id"`
			Action         string `json:"action"`
			Priority       int    `json:"priority"`
			Enabled        *bool  `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}

		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		result, err := db.DB.ExecContext(r.Context(),
			`UPDATE policies SET name = ?, description = ?, source_group_id = ?, service_id = ?,
		target_server_id = ?, action = ?, priority = ?, enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?`,
			input.Name, input.Description, input.SourceGroupID, input.ServiceID,
			input.TargetServerID, input.Action, input.Priority, enabled, id)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update policy: %v", err))
			return
		}

		// Check if any rows were updated
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to check update result: %v", err))
			return
		}
		if rowsAffected == 0 {
			common.RespondError(w, http.StatusNotFound, "policy not found")
			return
		}

		// Trigger async recompilation for the target server with timeout
		go func() {
			if input.TargetServerID <= 0 {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if _, err := compiler.CompileAndStore(ctx, input.TargetServerID); err != nil {
				runiclog.ErrorContext(ctx, "async compile and store failed",
					"server_id", input.TargetServerID,
					"error", err)
			}
		}()

		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func MakeDeletePolicyHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
			return
		}

		// Get the target server ID before deleting so we can recompile
		var targetServerID int
		err = db.DB.QueryRowContext(r.Context(),
			"SELECT target_server_id FROM policies WHERE id = ?", id).Scan(&targetServerID)
		if err != nil {
			common.RespondError(w, http.StatusNotFound, "policy not found")
			return
		}

		_, err = db.DB.ExecContext(r.Context(), "DELETE FROM policies WHERE id = ?", id)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete policy: %v", err))
			return
		}

		// Trigger async recompilation for the target server with timeout
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			if _, err := compiler.CompileAndStore(ctx, targetServerID); err != nil {
				runiclog.ErrorContext(ctx, "async compile and store failed",
					"server_id", targetServerID,
					"error", err)
			}
		}()

		w.WriteHeader(http.StatusNoContent)
	}
}

type PolicyPreviewRequest struct {
	SourceGroupID  int `json:"source_group_id"`
	ServiceID      int `json:"service_id"`
	TargetServerID int `json:"target_server_id"`
}

func MakePolicyPreviewHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PolicyPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Generate rules using the engine's preview function
		rules, err := compiler.PreviewCompile(r.Context(), req.TargetServerID, req.SourceGroupID, req.ServiceID)
		if err != nil {
			http.Error(w, "Failed to generate preview: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"rules": rules}})
	}
}
