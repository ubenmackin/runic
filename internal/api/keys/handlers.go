package keys

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
)

// Key types mapping: frontend type -> .env variable name
var keyTypeToEnv = map[string]string{
	"jwt-secret":       "RUNIC_JWT_SECRET",
	"hmac-key":         "RUNIC_HMAC_KEY",
	"agent-jwt-secret": "RUNIC_AGENT_JWT_SECRET",
}

// All key types in order
var keyTypes = []string{"jwt-secret", "hmac-key", "agent-jwt-secret"}

// getEnvPath returns the .env file path from env var or default
func getEnvPath() string {
	if p := os.Getenv("RUNIC_ENV_PATH"); p != "" {
		return p
	}
	return "/opt/runic/.env"
}

// readEnvFile reads the .env file and returns lines
func readEnvFile() ([]string, error) {
	path := getEnvPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}
	lines := strings.Split(string(data), "\n")
	return lines, nil
}

// writeEnvFile writes lines back to the .env file
func writeEnvFile(lines []string) error {
	path := getEnvPath()
	content := strings.Join(lines, "\n")
	return os.WriteFile(path, []byte(content), 0600)
}

// keyExists checks if a key exists in the .env file
func keyExists(lines []string, envVar string) bool {
	prefix := envVar + "="
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			value := strings.TrimPrefix(trimmed, prefix)
			return value != ""
		}
	}
	return false
}

// setKey sets or updates a key in the .env file lines
func setKey(lines []string, envVar, value string) []string {
	prefix := envVar + "="
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = envVar + "=" + value
			found = true
			break
		}
	}
	if !found {
		lines = append(lines, envVar+"="+value)
	}
	return lines
}

// removeKey removes a key from the .env file lines
func removeKey(lines []string, envVar string) []string {
	prefix := envVar + "="
	result := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			result = append(result, line)
		}
	}
	return result
}

// generateKey generates a random 32-byte hex-encoded key (64 hex chars)
func generateKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// validateKeyType checks if the key type is valid
func validateKeyType(keyType string) (string, bool) {
	envVar, ok := keyTypeToEnv[keyType]
	return envVar, ok
}

// ListKeys returns the status of all setup keys
func ListKeys(w http.ResponseWriter, r *http.Request) {
	lines, err := readEnvFile()
	if err != nil {
		http.Error(w, `{"error": "Failed to read env file"}`, http.StatusInternalServerError)
		return
	}

	result := make([]map[string]interface{}, 0, len(keyTypes))
	for _, kt := range keyTypes {
		envVar := keyTypeToEnv[kt]
		result = append(result, map[string]interface{}{
			"type":   kt,
			"exists": keyExists(lines, envVar),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// CreateKey generates a new random key and writes it to .env
func CreateKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	envVar, ok := validateKeyType(keyType)
	if !ok {
		http.Error(w, `{"error": "Invalid key type"}`, http.StatusBadRequest)
		return
	}

	newKey, err := generateKey()
	if err != nil {
		http.Error(w, `{"error": "Failed to generate key"}`, http.StatusInternalServerError)
		return
	}

	lines, err := readEnvFile()
	if err != nil {
		http.Error(w, `{"error": "Failed to read env file"}`, http.StatusInternalServerError)
		return
	}

	lines = setKey(lines, envVar, newKey)
	if err := writeEnvFile(lines); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to write env file: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": true,
	})
}

// DeleteKey removes a key from the .env file
func DeleteKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyType := vars["type"]

	envVar, ok := validateKeyType(keyType)
	if !ok {
		http.Error(w, `{"error": "Invalid key type"}`, http.StatusBadRequest)
		return
	}

	lines, err := readEnvFile()
	if err != nil {
		http.Error(w, `{"error": "Failed to read env file"}`, http.StatusInternalServerError)
		return
	}

	lines = removeKey(lines, envVar)
	if err := writeEnvFile(lines); err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to write env file: %s"}`, err.Error()), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"type":   keyType,
		"exists": false,
	})
}
