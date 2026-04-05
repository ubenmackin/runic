package agents

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/common"
	"runic/internal/db"
)

// getEnv gets an environment variable or returns a default.
func getEnv(key, defaultVal string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return defaultVal
}

// GenerateHMACKey generates a cryptographically secure random HMAC key.
func GenerateHMACKey() (string, error) {
	key, err := common.GenerateHMACKey()
	if err != nil {
		return "", fmt.Errorf("generate HMAC key: %w", err)
	}
	return key, nil
}

// generateAgentToken generates a JWT-like token for an agent.
func generateAgentToken(ctx context.Context, dbConn *sql.DB, hostname string) (string, error) {
	hMACKey, err := db.GetSecret(ctx, dbConn, "agent_jwt_secret")
	if err != nil {
		return "", fmt.Errorf("agent JWT secret not configured: %w", err)
	}
	// In production, use proper JWT generation with expiration
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  fmt.Sprintf("host-%s", hostname),
		"type": "agent",
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(hMACKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return tokenStr, nil
}

// generateAgentKey generates a cryptographically secure unique agent key.
func generateAgentKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate agent key: %w", err)
	}
	return "agent-key-" + hex.EncodeToString(b), nil
}

// getHostIDFromContext safely extracts host_id from request context and looks up the peer.
// The host_id in context comes from the JWT subject claim, which is in format "host-{hostname}".
func (h *Handler) getHostIDFromContext(w http.ResponseWriter, r *http.Request) (string, int, bool) {
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

	// Look up peer by hostname to get the numeric ID
	var peerID int
	err := h.DB.QueryRowContext(r.Context(), "SELECT id FROM peers WHERE hostname = ?", hostname).Scan(&peerID)
	if err != nil {
		http.Error(w, `{"error": "peer not found"}`, http.StatusNotFound)
		return "", 0, false
	}

	return hostID, peerID, true
}
