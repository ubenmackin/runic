// Package keys provides API key management handlers.
package keys

import (
	"encoding/json"
	"net/http"

	"runic/internal/api/common"
	runiclog "runic/internal/common/log"
	"runic/internal/store"

	"github.com/gorilla/mux"
)

type Handler struct {
	Keys *store.KeyStore
}

func NewHandler(keys *store.KeyStore) *Handler {
	return &Handler{Keys: keys}
}

var keyTypes = []string{
	"jwt-secret",
	"agent-jwt-secret",
}

var keyTypeToDBKey = map[string]string{
	"jwt-secret":       "jwt_secret",
	"agent-jwt-secret": "agent_jwt_secret",
}

func (h *Handler) ListKeys(w http.ResponseWriter, r *http.Request) {
	result := make([]map[string]interface{}, 0, len(keyTypes))
	for _, kt := range keyTypes {
		dbKey := keyTypeToDBKey[kt]
		exists, _ := h.Keys.KeyExists(r.Context(), dbKey)
		result = append(result, map[string]interface{}{
			"type":   kt,
			"exists": exists,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		runiclog.Error("Failed to encode keys result", "error", err)
	}
}

func (h *Handler) CreateKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	dbKey, ok := keyTypeToDBKey[keyType]
	if !ok {
		common.RespondError(w, http.StatusBadRequest, "Invalid key type")
		return
	}

	newKey, err := h.Keys.GenerateSecureKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to generate key")
		return
	}

	if err := h.Keys.SetSecret(r.Context(), dbKey, newKey); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to store key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": true,
	}); err != nil {
		runiclog.Error("Failed to encode create key result", "error", err)
	}
}

func (h *Handler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	dbKey, ok := keyTypeToDBKey[keyType]
	if !ok {
		common.RespondError(w, http.StatusBadRequest, "Invalid key type")
		return
	}

	if err := h.Keys.DeleteSecret(r.Context(), dbKey); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": false,
	}); err != nil {
		runiclog.Error("Failed to encode delete key result", "error", err)
	}
}
