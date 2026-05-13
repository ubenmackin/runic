package agents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	runiclog "runic/internal/common/log"
)

// GenerateRegistrationToken handles POST /api/v1/registration-tokens
func (h *Handler) GenerateRegistrationToken(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Description string `json:"description"`
	}
	// Ignore decode errors — description is optional
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		runiclog.Debug("Failed to decode token description", "error", err)
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		runiclog.Error("Failed to generate token", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	token := hex.EncodeToString(tokenBytes)

	if err := h.DashboardStore.GenerateRegistrationToken(r.Context(), token, input.Description); err != nil {
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

func (h *Handler) ListRegistrationTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.DashboardStore.ListRegistrationTokens(r.Context())
	if err != nil {
		runiclog.Error("Failed to list tokens", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}

	// Mask token for display (show first 8 and last 4 chars)
	for i := range tokens {
		tokens[i].Token = maskToken(tokens[i].Token)
	}

	common.RespondJSON(w, http.StatusOK, tokens)
}

func (h *Handler) RevokeRegistrationToken(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	revoked, err := h.DashboardStore.RevokeRegistrationToken(r.Context(), id)
	if err != nil {
		runiclog.Error("Failed to revoke token", "error", err)
		http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
		return
	}
	if !revoked {
		http.Error(w, `{"error": "token not found or already used/revoked"}`, http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ConsumeRegistrationToken consumes a registration token. Returns (true, nil) if the token was successfully consumed,
// (false, nil) if the token was already used/revoked/not found,
// (false, err) on database error.
func (h *Handler) ConsumeRegistrationToken(ctx context.Context, token, hostname string) (bool, error) {
	return h.DashboardStore.ConsumeRegistrationToken(ctx, token, hostname)
}

func maskToken(token string) string {
	if len(token) <= 12 {
		return "****"
	}
	return token[:8] + "..." + token[len(token)-4:]
}
