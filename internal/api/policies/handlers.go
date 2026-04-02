package policies

import (
	"encoding/json"
	"log"
	"net/http"

	"runic/internal/api/common"
	"runic/internal/db"
	"runic/internal/engine"
)

// isValidSourceType validates that the source type is one of the allowed values.
func isValidSourceType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

// isValidTargetType validates that the target type is one of the allowed values.
func isValidTargetType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

// isValidDirection validates that the direction is one of the allowed values.
func isValidDirection(value string) bool {
	return value == "both" || value == "forward" || value == "backward"
}

func ListPolicies(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(),
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id,
		target_id, target_type, action, priority, enabled, target_scope, COALESCE(direction, 'both'), created_at, updated_at
		FROM policies ORDER BY priority ASC`)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query policies")
		return
	}
	defer rows.Close()

	type policyResp struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		SourceID    int    `json:"source_id"`
		SourceType  string `json:"source_type"`
		ServiceID   int    `json:"service_id"`
		TargetID    int    `json:"target_id"`
		TargetType  string `json:"target_type"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
		TargetScope string `json:"target_scope"`
		Direction   string `json:"direction"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	}

	var policiesData []policyResp
	for rows.Next() {
		var p policyResp
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
			&p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.Enabled, &p.TargetScope, &p.Direction, &p.CreatedAt, &p.UpdatedAt); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan policy")
			return
		}
		policiesData = append(policiesData, p)
	}
	policiesData = common.EnsureSlice(policiesData)
	common.RespondJSON(w, http.StatusOK, policiesData)
}

func MakeCreatePolicyHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			SourceID    int    `json:"source_id"`
			SourceType  string `json:"source_type"`
			ServiceID   int    `json:"service_id"`
			TargetID    int    `json:"target_id"`
			TargetType  string `json:"target_type"`
			Action      string `json:"action"`
			Priority    int    `json:"priority"`
			Enabled     *bool  `json:"enabled"`
			TargetScope string `json:"target_scope"`
			Direction   string `json:"direction"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if len(input.Name) > 255 {
			common.RespondError(w, http.StatusBadRequest, "policy name must not exceed 255 characters")
			return
		}
		if input.Name == "" || input.SourceID == 0 || input.SourceType == "" || input.ServiceID == 0 || input.TargetID == 0 || input.TargetType == "" {
			common.RespondError(w, http.StatusBadRequest, "name, source_id, source_type, service_id, target_id, and target_type are required")
			return
		}
		if !isValidSourceType(input.SourceType) {
			common.RespondError(w, http.StatusBadRequest, "source_type must be one of: peer, group, special")
			return
		}
		if !isValidTargetType(input.TargetType) {
			common.RespondError(w, http.StatusBadRequest, "target_type must be one of: peer, group, special")
			return
		}
		if input.Action == "" {
			input.Action = "ACCEPT"
		}
		if input.Priority == 0 {
			input.Priority = 100
		}
		if input.Direction == "" {
			input.Direction = "both"
		}
		if !isValidDirection(input.Direction) {
			common.RespondError(w, http.StatusBadRequest, "direction must be one of: both, forward, backward")
			return
		}
		if input.TargetScope == "" {
			input.TargetScope = "both"
		}
		if input.TargetScope != "both" && input.TargetScope != "host" && input.TargetScope != "docker" {
			common.RespondError(w, http.StatusBadRequest, "target_scope must be one of: both, host, docker")
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		result, err := db.DB.ExecContext(r.Context(),
			`INSERT INTO policies (name, description, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, target_scope, direction)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			input.Name, input.Description, input.SourceID, input.SourceType, input.ServiceID,
			input.TargetID, input.TargetType, input.Action, input.Priority, enabled, input.TargetScope, input.Direction)
		if err != nil {
			log.Printf("ERROR: failed to create policy: %v", err)
			common.InternalError(w)
			return
		}

		id, _ := result.LastInsertId()

		// Trigger async recompilation for all affected peers
		affectedPeers, _ := compiler.GetAffectedPeersByPolicy(r.Context(), int(id))
		common.AsyncRecompilePeers(compiler, affectedPeers)

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
		ID          int    `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		SourceID    int    `json:"source_id"`
		SourceType  string `json:"source_type"`
		ServiceID   int    `json:"service_id"`
		TargetID    int    `json:"target_id"`
		TargetType  string `json:"target_type"`
		Action      string `json:"action"`
		Priority    int    `json:"priority"`
		Enabled     bool   `json:"enabled"`
		TargetScope string `json:"target_scope"`
		Direction   string `json:"direction"`
		CreatedAt   string `json:"created_at"`
		UpdatedAt   string `json:"updated_at"`
	}

	err = db.DB.QueryRowContext(r.Context(),
		`SELECT id, name, COALESCE(description, ''), source_id, source_type, service_id,
		target_id, target_type, action, priority, enabled, target_scope, COALESCE(direction, 'both'), created_at, updated_at
		FROM policies WHERE id = ?`, id,
	).Scan(&p.ID, &p.Name, &p.Description, &p.SourceID, &p.SourceType, &p.ServiceID,
		&p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.Enabled, &p.TargetScope, &p.Direction, &p.CreatedAt, &p.UpdatedAt)
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
			Name        string `json:"name"`
			Description string `json:"description"`
			SourceID    int    `json:"source_id"`
			SourceType  string `json:"source_type"`
			ServiceID   int    `json:"service_id"`
			TargetID    int    `json:"target_id"`
			TargetType  string `json:"target_type"`
			Action      string `json:"action"`
			Priority    int    `json:"priority"`
			Enabled     *bool  `json:"enabled"`
			TargetScope string `json:"target_scope"`
			Direction   string `json:"direction"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if len(input.Name) > 255 {
			common.RespondError(w, http.StatusBadRequest, "policy name must not exceed 255 characters")
			return
		}
		if input.Name == "" {
			common.RespondError(w, http.StatusBadRequest, "name is required")
			return
		}
		if input.SourceType != "" && !isValidSourceType(input.SourceType) {
			common.RespondError(w, http.StatusBadRequest, "source_type must be one of: peer, group, special")
			return
		}
		if input.TargetType != "" && !isValidTargetType(input.TargetType) {
			common.RespondError(w, http.StatusBadRequest, "target_type must be one of: peer, group, special")
			return
		}
		if input.Direction == "" {
			input.Direction = "both"
		}
		if !isValidDirection(input.Direction) {
			common.RespondError(w, http.StatusBadRequest, "direction must be one of: both, forward, backward")
			return
		}
		if input.TargetScope == "" {
			input.TargetScope = "both"
		}
		if input.TargetScope != "both" && input.TargetScope != "host" && input.TargetScope != "docker" {
			common.RespondError(w, http.StatusBadRequest, "target_scope must be one of: both, host, docker")
			return
		}

		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}

		// Save old affected peers before update
		oldPeers, _ := compiler.GetAffectedPeersByPolicy(r.Context(), id)

		result, err := db.DB.ExecContext(r.Context(),
			`UPDATE policies SET name = ?, description = ?, source_id = ?, source_type = ?, service_id = ?,
			target_id = ?, target_type = ?, action = ?, priority = ?, enabled = ?, target_scope = ?, direction = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?`,
			input.Name, input.Description, input.SourceID, input.SourceType, input.ServiceID,
			input.TargetID, input.TargetType, input.Action, input.Priority, enabled, input.TargetScope, input.Direction, id)
		if err != nil {
			log.Printf("ERROR: failed to update policy: %v", err)
			common.InternalError(w)
			return
		}

		// Check if any rows were updated
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.Printf("ERROR: failed to check update result: %v", err)
			common.InternalError(w)
			return
		}
		if rowsAffected == 0 {
			common.RespondError(w, http.StatusNotFound, "policy not found")
			return
		}

		// Trigger async recompilation for all affected peers (old and new)
		newPeers, _ := compiler.GetAffectedPeersByPolicy(r.Context(), id)
		peerSet := make(map[int]bool)
		for _, pid := range oldPeers {
			peerSet[pid] = true
		}
		for _, pid := range newPeers {
			peerSet[pid] = true
		}
		var allPeers []int
		for pid := range peerSet {
			allPeers = append(allPeers, pid)
		}
		common.AsyncRecompilePeers(compiler, allPeers)

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

		// Save old affected peers before update
		oldPeers, _ := compiler.GetAffectedPeersByPolicy(r.Context(), id)

		// Delete the policy
		res, err := db.DB.ExecContext(r.Context(), "DELETE FROM policies WHERE id = ?", id)
		if err != nil {
			log.Printf("ERROR: failed to delete policy: %v", err)
			common.InternalError(w)
			return
		}

		affected, _ := res.RowsAffected()
		if affected == 0 {
			common.RespondError(w, http.StatusNotFound, "policy not found")
			return
		}

		// Trigger async recompilation for all old affected peers
		common.AsyncRecompilePeers(compiler, oldPeers)

		w.WriteHeader(http.StatusNoContent)
	}
}

type PolicyPreviewRequest struct {
	SourceID    int    `json:"source_id"`
	SourceType  string `json:"source_type"`
	TargetID    int    `json:"target_id"`
	TargetType  string `json:"target_type"`
	ServiceID   int    `json:"service_id"`
	PeerID      int    `json:"peer_id"`      // the peer to base the preview on
	Direction   string `json:"direction"`    // forward, backward, or both
	TargetScope string `json:"target_scope"` // host, docker, or both
}

func MakePolicyPreviewHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req PolicyPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Default direction to both
		if req.Direction == "" {
			req.Direction = "both"
		}

		// Default target_scope to both
		if req.TargetScope == "" {
			req.TargetScope = "both"
		}

		// Derive peer_id if not provided - used for special target resolution
		if req.PeerID == 0 {
			if req.SourceType == "peer" {
				req.PeerID = req.SourceID
			} else if req.TargetType == "peer" {
				req.PeerID = req.TargetID
			}
		}

		// Generate rules using the policy-centric preview function
		rules, err := compiler.PreviewCompile(r.Context(), req.PeerID, req.SourceID, req.SourceType, req.TargetID, req.TargetType, req.ServiceID, req.Direction, req.TargetScope)
		if err != nil {
			log.Printf("ERROR: failed to generate preview: %v", err)
			http.Error(w, `{"error": "failed to generate preview"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"rules": rules}})
	}
}

func MakePatchPolicyHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid policy ID")
			return
		}
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		if input.Enabled == nil {
			common.RespondError(w, http.StatusBadRequest, "enabled field is required")
			return
		}
		result, err := db.DB.ExecContext(r.Context(), "UPDATE policies SET enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", *input.Enabled, id)
		if err != nil {
			log.Printf("ERROR: failed to update policy: %v", err)
			common.InternalError(w)
			return
		}
		rowsAffected, _ := result.RowsAffected()
		if rowsAffected == 0 {
			common.RespondError(w, http.StatusNotFound, "policy not found")
			return
		}
		// Trigger async recompilation
		affectedPeers, _ := compiler.GetAffectedPeersByPolicy(r.Context(), id)
		common.AsyncRecompilePeers(compiler, affectedPeers)
		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "updated"})
	}
}

func ListSpecialTargets(w http.ResponseWriter, r *http.Request) {
	rows, err := db.DB.QueryContext(r.Context(), "SELECT id, name, display_name, COALESCE(description, ''), address FROM special_targets ORDER BY id ASC")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query special targets")
		return
	}
	defer rows.Close()

	type specialTargetResp struct {
		ID          int    `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		Description string `json:"description"`
		Address     string `json:"address"`
	}

	var targets []specialTargetResp
	for rows.Next() {
		var t specialTargetResp
		if err := rows.Scan(&t.ID, &t.Name, &t.DisplayName, &t.Description, &t.Address); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan special target")
			return
		}
		targets = append(targets, t)
	}

	targets = common.EnsureSlice(targets)

	common.RespondJSON(w, http.StatusOK, targets)
}
