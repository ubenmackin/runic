package agents

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	runiclog "runic/internal/common/log"
	"runic/internal/db"
)

// getEnv gets an environment variable or returns a default.
func getEnv(key, defaultVal string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return defaultVal
}

// requireEnv gets an environment variable or returns an error.
func requireEnv(key string) ([]byte, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return nil, fmt.Errorf("required environment variable %s is not set", key)
	}
	return []byte(val), nil
}

// GenerateHMACKey generates a cryptographically secure random HMAC key.
func GenerateHMACKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		runiclog.Error("Failed to generate HMAC key error", "error", err)
		return "runic-hmac-key-change-me"
	}
	return hex.EncodeToString(b)
}

// generateAgentToken generates a JWT-like token for an agent.
func generateAgentToken(hostname string) (string, error) {
	hMACKey, err := requireEnv("RUNIC_AGENT_JWT_SECRET")
	if err != nil {
		return "", err
	}
	// In production, use proper JWT generation with expiration
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  fmt.Sprintf("host-%s", hostname),
		"type": "agent",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString(hMACKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return tokenStr, nil
}

// generateAgentKey generates a cryptographically secure unique agent key.
func generateAgentKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		runiclog.Error("Failed to generate agent key error", "error", err)
		return fmt.Sprintf("agent-key-%d", time.Now().UnixNano())
	}
	return "agent-key-" + hex.EncodeToString(b)
}

// getHostIDFromContext safely extracts host_id from request context and looks up the server.
// The host_id in context comes from the JWT subject claim, which is in format "host-{hostname}".
func getHostIDFromContext(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	hostIDVal := r.Context().Value(hostIDKey)
	if hostIDVal == nil {
		http.Error(w, `{"error": "host_id not found in context"}`, http.StatusUnauthorized)
		return "", 0, false
	}
	hostID, ok := hostIDVal.(string)
	if !ok {
		http.Error(w, `{"error": "invalid host_id type"}`, http.StatusBadRequest)
		return "", 0, false
	}

	// Extract hostname from host-{hostname} format
	var hostname string
	if _, err := fmt.Sscanf(hostID, "host-%s", &hostname); err != nil {
		http.Error(w, `{"error": "invalid host_id format"}`, http.StatusBadRequest)
		return "", 0, false
	}

	// Look up server by hostname to get the numeric ID
	var serverID int
	err := db.DB.QueryRowContext(r.Context(), "SELECT id FROM servers WHERE hostname = ?", hostname).Scan(&serverID)
	if err != nil {
		http.Error(w, `{"error": "server not found"}`, http.StatusNotFound)
		return "", 0, false
	}

	return hostID, serverID, true
}
