package agents

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	runiclog "runic/internal/common/log"
)

// GenerateRegistrationToken generates a new registration token
// POST /api/v1/registration-tokens
func (h *Handler) GenerateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	// Parse optional description from request body
	var input struct {
		Description string `json:"description"`
	}
	// Ignore decode errors — description is optional
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		runiclog.Debug("Failed to decode token description", "error", err)
	}

	// Generate random token (32 bytes = 64 hex chars)
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		runiclog.Error("Failed to generate token", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Insert into database
	_, err := h.DB.Exec(
		"INSERT INTO registration_tokens (token, description) VALUES (?, ?)",
		token, input.Description,
	)
	if err != nil {
		runiclog.Error("Failed to store token", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	common.RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"full_token":  token,
		"description": input.Description,
		"created_at":  time.Now().UTC().Format(time.RFC3339),
	})
}

// ListRegistrationTokens lists all registration tokens
// GET /api/v1/registration-tokens
func (h *Handler) ListRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(
		"SELECT id, token, description, created_at, used_at, used_by_hostname, is_revoked FROM registration_tokens ORDER BY created_at DESC",
	)
	if err != nil {
		runiclog.Error("Failed to list tokens", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			runiclog.Warn("Failed to close rows", "error", cErr)
		}
	}()

	var tokens []map[string]interface{}
	for rows.Next() {
		var id int
		var token, desc string
		var createdAt sql.NullString
		var usedAt, usedByHostname sql.NullString
		var isRevoked int

		if err := rows.Scan(&id, &token, &desc, &createdAt, &usedAt, &usedByHostname, &isRevoked); err != nil {
			runiclog.Error("Failed to scan token row", "error", err)
			http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			return
		}

		status := "active"
		if isRevoked == 1 {
			status = "revoked"
		} else if usedAt.Valid {
			status = "used"
		}

		// Mask token for display (show first 8 and last 4 chars)
		masked := maskToken(token)

		tokens = append(tokens, map[string]interface{}{
			"id":               id,
			"token":            masked,
			"description":      desc,
			"created_at":       createdAt.String,
			"used_at":          usedAt.String,
			"used_by_hostname": usedByHostname.String,
			"status":           status,
			"is_revoked":       isRevoked,
		})
	}

	tokens = common.EnsureSlice(tokens)
	common.RespondJSON(w, http.StatusOK, tokens)
}

// RevokeRegistrationToken revokes a registration token
// DELETE /api/v1/registration-tokens/{id}
func (h *Handler) RevokeRegistrationToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	result, err := h.DB.Exec(
		"UPDATE registration_tokens SET is_revoked = 1 WHERE id = ? AND used_at IS NULL AND is_revoked = 0",
		id,
	)
	if err != nil {
		runiclog.Error("Failed to revoke token", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		runiclog.Error("Failed to get rows affected", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	if rowsAffected == 0 {
		http.Error(w, `{"error": "token not found or already used/revoked"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ConsumeRegistrationToken atomically validates and consumes a registration token.
// Returns (true, nil) if the token was successfully consumed,
// (false, nil) if the token was already used/revoked/not found,
// (false, err) on database error.
func (h *Handler) ConsumeRegistrationToken(token, hostname string) (bool, error) {
	result, err := h.DB.Exec(
		"UPDATE registration_tokens SET used_at = CURRENT_TIMESTAMP, used_by_hostname = ? WHERE token = ? AND used_at IS NULL AND is_revoked = 0",
		hostname, token,
	)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("getting rows affected: %w", err)
	}
	return rowsAffected > 0, nil
}

func maskToken(token string) string {
	if len(token) <= 12 {
		return "****"
	}
	return token[:8] + "..." + token[len(token)-4:]
}
