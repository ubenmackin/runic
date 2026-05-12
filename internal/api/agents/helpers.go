package agents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	apicommon "runic/internal/api/common"
	"runic/internal/common"
	"runic/internal/store"
)

// generateUniqueID creates a random hex-encoded unique ID for JWT jti claims.
func generateUniqueID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func GenerateHMACKey() (string, error) {
	key, err := common.GenerateHMACKey()
	if err != nil {
		return "", fmt.Errorf("generate HMAC key: %w", err)
	}
	return key, nil
}

func generateAgentToken(ctx context.Context, ds *store.DashboardStore, hostname string) (string, error) {
	hMACKey, err := ds.GetSecret(ctx, "agent_jwt_secret")
	if err != nil {
		return "", fmt.Errorf("agent JWT secret not configured: %w", err)
	}
	// In production, use proper JWT generation with expiration
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  fmt.Sprintf("host-%s", hostname),
		"type": "agent",
		"jti":  generateUniqueID(),
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte(hMACKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return tokenStr, nil
}

func generateAgentKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate agent key: %w", err)
	}
	return "agent-key-" + hex.EncodeToString(b), nil
}

// The host_id in context comes from the JWT subject claim, which is in format "host-{hostname}".
func (h *Handler) getHostIDFromContext(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	hostIDVal := r.Context().Value(hostIDKey)
	if hostIDVal == nil {
		apicommon.RespondError(w, http.StatusUnauthorized, "host_id not found in context")
		return "", 0, false
	}
	hostID, ok := hostIDVal.(string)
	if !ok {
		apicommon.RespondError(w, http.StatusBadRequest, "invalid host_id type")
		return "", 0, false
	}

	// Validate and parse host_id prefix. Use string prefix matching instead of Sscanf
	// to avoid buffer truncation issues with %s and to properly validate the format.
	if len(hostID) < 5 || hostID[:5] != "host-" || hostID[5:] == "" {
		apicommon.RespondError(w, http.StatusBadRequest, "invalid host_id format")
		return "", 0, false
	}
	hostname := hostID[5:]

	peerID, err := h.PeerStore.GetPeerIDByHostname(r.Context(), hostname)
	if err != nil {
		apicommon.RespondError(w, http.StatusNotFound, "peer not found")
		return "", 0, false
	}

	return hostID, peerID, true
}
