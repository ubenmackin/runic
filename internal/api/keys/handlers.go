package keys

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"runic/internal/db"
)

var keyTypes = []string{
	"jwt-secret",
	"agent-jwt-secret",
}

var keyTypeToDBKey = map[string]string{
	"jwt-secret":       "jwt_secret",
	"agent-jwt-secret": "agent_jwt_secret",
}

// ListKeys returns the status of all setup keys
func ListKeys(w http.ResponseWriter, r *http.Request) {
	result := make([]map[string]interface{}, 0, len(keyTypes))
	for _, kt := range keyTypes {
		dbKey := keyTypeToDBKey[kt]
		_, err := db.GetSecret(dbKey)
		result = append(result, map[string]interface{}{
			"type":   kt,
			"exists": err == nil,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CreateKey generates a new random key and stores it in the database
func CreateKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	dbKey, ok := keyTypeToDBKey[keyType]
	if !ok {
		http.Error(w, `{"error": "Invalid key type"}`, http.StatusBadRequest)
		return
	}

	newKey, err := db.GenerateSecureKey()
	if err != nil {
		http.Error(w, `{"error": "Failed to generate key"}`, http.StatusInternalServerError)
		return
	}

	if err := db.SetSecret(dbKey, newKey); err != nil {
		http.Error(w, `{"error": "Failed to store key"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": true,
	})
}

// DeleteKey removes a key from the database
func DeleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	dbKey, ok := keyTypeToDBKey[keyType]
	if !ok {
		http.Error(w, `{"error": "Invalid key type"}`, http.StatusBadRequest)
		return
	}

	_, err := db.DB.Exec("DELETE FROM system_config WHERE key = ?", dbKey)
	if err != nil {
		http.Error(w, `{"error": "Failed to delete key"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": false,
	})
}
