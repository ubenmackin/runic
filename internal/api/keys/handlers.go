// Package keys provides API key management handlers.
package keys

import (
	"net/http"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
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
	dbKeys := make([]string, 0, len(keyTypes))
	for _, kt := range keyTypes {
		dbKeys = append(dbKeys, keyTypeToDBKey[kt])
	}

	keyStatuses, err := h.Keys.ListKeyStatuses(r.Context(), dbKeys)
	if err != nil {
		runiclog.Error("Failed to list key statuses", "error", err)
		common.RespondError(w, http.StatusBadGateway, "database unavailable")
		return
	}

	result := make([]map[string]interface{}, 0, len(keyTypes))
	for _, kt := range keyTypes {
		dbKey := keyTypeToDBKey[kt]
		result = append(result, map[string]interface{}{
			"type":   kt,
			"exists": keyStatuses[dbKey],
		})
	}

	common.RespondJSON(w, http.StatusOK, result)
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

	// Record the one-time bootstrap marker so deleting this key later can
	// never be undone by re-seeding it from the environment on restart.
	if err := h.Keys.SetSecret(r.Context(), db.JWTSecretsSeedMarker, "1"); err != nil {
		runiclog.Error("Failed to record JWT secrets bootstrap marker", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "Failed to store key")
		return
	}

	if keyType == "jwt-secret" {
		if err := auth.RotateJwtKey(r.Context(), []byte(newKey)); err != nil {
			runiclog.Error("Failed to activate rotated JWT key", "error", err)
			common.RespondError(w, http.StatusInternalServerError, "Failed to activate key")
			return
		}
		// Operator-initiated replacement must log out existing sessions, so
		// drop the previous key instead of honoring the rotation window.
		if err := auth.ClearJwtPrevKey(r.Context()); err != nil {
			runiclog.Error("Failed to clear previous JWT key", "error", err)
			common.RespondError(w, http.StatusInternalServerError, "Failed to activate key")
			return
		}
	}

	common.RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"type":   keyType,
		"exists": true,
	})
}

func (h *Handler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	dbKey, ok := keyTypeToDBKey[keyType]
	if !ok {
		common.RespondError(w, http.StatusBadRequest, "Invalid key type")
		return
	}

	if keyType == "jwt-secret" {
		// Deleting the persisted signing key must invalidate every issued
		// token. Rotate the active key to a fresh value and drop the
		// rotation-window key so old tokens cannot validate while the
		// delete is in flight.
		newKey, err := h.Keys.GenerateSecureKey()
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "Failed to generate key")
			return
		}
		if err := auth.RotateJwtKey(r.Context(), []byte(newKey)); err != nil {
			runiclog.Error("Failed to rotate active JWT key", "error", err)
			common.RespondError(w, http.StatusInternalServerError, "Failed to delete key")
			return
		}
		if err := auth.ClearJwtPrevKey(r.Context()); err != nil {
			runiclog.Error("Failed to clear previous JWT key", "error", err)
			common.RespondError(w, http.StatusInternalServerError, "Failed to delete key")
			return
		}
	}

	// The one-time bootstrap marker must exist before the key disappears and
	// is never deleted with it; otherwise a restart would re-seed the key
	// from the environment and revive tokens signed before the deletion.
	if err := h.Keys.SetSecret(r.Context(), db.JWTSecretsSeedMarker, "1"); err != nil {
		runiclog.Error("Failed to record JWT secrets bootstrap marker", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}

	if err := h.Keys.DeleteSecret(r.Context(), dbKey); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete key")
		return
	}

	if keyType == "jwt-secret" {
		// The persisted key is gone, so clear the in-memory pair as well;
		// keeping a key in memory would diverge from storage and could be
		// replaced by a stale bootstrap value on the next restart.
		auth.JwtKeyMu.Lock()
		auth.JwtKey = nil
		auth.JwtPrevKey = nil
		auth.JwtKeyMu.Unlock()
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"type":   keyType,
		"exists": false,
	})
}
