package peers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/api/middleware"
	runiccommon "runic/internal/common"
	"runic/internal/store"
)

// Rate limiters for rotation endpoints
var (
	rotateKeyRateLimiter       = middleware.NewRateLimiter(10, time.Minute) // 10 requests per minute per IP
	confirmRotationRateLimiter = middleware.NewRateLimiter(20, time.Minute) // 20 requests per minute per IP
)

// The token is a 32-byte random value, hex-encoded (64 chars).
func generateRotationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func generateHMACKey() (string, error) {
	return runiccommon.GenerateHMACKey()
}

// Handles both "host-<hostname>" and bare "<hostname>" formats.
func parseHostID(hostID string) string {
	hostname := hostID
	if len(hostname) > 5 && hostname[:5] == "host-" {
		hostname = hostname[5:]
	}
	return hostname
}

// RotatePeerKey initiates an HMAC key rotation for a peer. POST /api/v1/peers/:id/rotate-key
func (h *Handler) RotatePeerKey(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	peer, err := h.Store.GetPeerByID(r.Context(), peerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	hostname := peer.Hostname
	rotationToken, _, err := h.Store.GetPeerRotationState(r.Context(), hostname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	newHMACKey, err := generateHMACKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	token, err := generateRotationToken()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate rotation token")
		return
	}

	if rotationToken != "" {
		lastRotatedAt, err := h.Store.GetHMACKeyLastRotatedAt(r.Context(), peerID)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to query peer rotation state")
			return
		}

		if err == nil && lastRotatedAt.Valid {
			rotationTime, parseErr := time.Parse(time.RFC3339, lastRotatedAt.String)
			if parseErr == nil && time.Since(rotationTime) < 5*time.Minute {
				common.RespondJSON(w, http.StatusOK, map[string]interface{}{
					"peer_id":        peerID,
					"hostname":       hostname,
					"rotation_token": rotationToken,
					"message":        "Rotation already in progress. Use the existing rotation token.",
				})
				return
			}
		}
	}

	err = h.Store.StartKeyRotation(r.Context(), hostname, newHMACKey, token)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to update peer")
		return
	}

	slog.Info("HMAC key rotated by admin",
		"peer_id", peerID,
		"hostname", hostname,
		"action", "rotate_key",
	)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"peer_id":        peerID,
		"hostname":       hostname,
		"new_hmac_key":   newHMACKey,
		"rotation_token": token,
		"rotated_at":     time.Now().UTC().Format(time.RFC3339),
		"message":        "Key rotated successfully. Provide the rotation token to the agent to complete rotation.",
	})
}

// AgentRotateKey handles agent-initiated key rotation. POST /api/v1/agent/rotate-key
// The agent sends its host_id and rotation token.
// The token is consumed (set to NULL) atomically with key retrieval.
// This endpoint is PUBLIC - authentication is via the rotation token itself.
func (h *Handler) AgentRotateKey(w http.ResponseWriter, r *http.Request) {
	// Limit request body size to prevent slowloris attacks
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		HostID        string `json:"host_id"`
		RotationToken string `json:"rotation_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if rotateKeyRateLimiter.Check(r.RemoteAddr) != nil {
		common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if input.HostID == "" || input.RotationToken == "" {
		common.RespondError(w, http.StatusBadRequest, "host_id and rotation_token are required")
		return
	}

	hostname := parseHostID(input.HostID)

	var peerID int64
	var newHMACKey string

	// Atomic operation: validate token AND retrieve key AND consume token
	err := store.RunInTx(r.Context(), h.beginner, func(tx *sql.Tx) error {
		var lastRotatedAt sql.NullString
		err := tx.QueryRowContext(r.Context(), `
			SELECT id, hmac_key, hmac_key_last_rotated_at FROM peers
			WHERE hostname = ? AND hmac_key_rotation_token = ?
		`, hostname, input.RotationToken).Scan(&peerID, &newHMACKey, &lastRotatedAt)

		if err != nil {
			return err
		}

		if lastRotatedAt.Valid {
			rotationTime, parseErr := time.Parse(time.RFC3339, lastRotatedAt.String)
			if parseErr != nil || time.Since(rotationTime) > 5*time.Minute {
				// Clear expired token within the same transaction
				if execErr := h.Store.ClearRotationTokenTx(r.Context(), tx, int(peerID)); execErr != nil {
					slog.Warn("failed to clear expired rotation token", "error", execErr)
				}
				return common.NewHTTPError(http.StatusUnauthorized, "expired rotation token")
			}
		}

		// Consume the token using the already-known peerID — no redundant SELECT
		if err := h.Store.ConsumeRotationTokenByIDTx(r.Context(), tx, int(peerID)); err != nil {
			return err
		}

		slog.Info("Agent retrieved new HMAC key",
			"peer_id", peerID,
			"hostname", hostname,
			"action", "retrieve_key",
		)

		// Store the key in a response header so we can send it after commit
		w.Header().Set("X-New-HMAC-Key", newHMACKey)
		return nil
	})

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusUnauthorized, "invalid rotation token")
			return
		}
		if httpErr, ok := err.(*common.HTTPError); ok {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to process rotation")
		return
	}

	newHMACKey = w.Header().Get("X-New-HMAC-Key")
	w.Header().Del("X-New-HMAC-Key")

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"new_hmac_key": newHMACKey,
		"message":      "New key retrieved. Apply it and call /agent/confirm-rotation to complete.",
	})
}

// AgentConfirmRotation confirms completion of a key rotation. POST /api/v1/agent/confirm-rotation
// Requires the rotation token as proof of legitimate rotation.
func (h *Handler) AgentConfirmRotation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		HostID        string `json:"host_id"`
		RotationToken string `json:"rotation_token"` // Required only if rotation token still exists (not yet consumed)
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if confirmRotationRateLimiter.Check(r.RemoteAddr) != nil {
		common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if input.HostID == "" {
		common.RespondError(w, http.StatusBadRequest, "host_id is required")
		return
	}

	hostname := parseHostID(input.HostID)

	rotationToken, _, err := h.Store.GetPeerRotationState(r.Context(), hostname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	if rotationToken == "" {
		// Token already consumed - check if rotation was recent
		_, lastRotatedAt, err := h.Store.GetPeerIDAndLastRotatedAt(r.Context(), hostname)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
			return
		}

		if lastRotatedAt.Valid {
			rotationTime, parseErr := time.Parse(time.RFC3339, lastRotatedAt.String)
			if parseErr == nil && time.Since(rotationTime) < 10*time.Minute {
				common.RespondJSON(w, http.StatusOK, map[string]string{
					"status":  "already_confirmed",
					"message": "Key rotation was already completed",
				})
				return
			}
		}

		common.RespondError(w, http.StatusBadRequest, "no rotation in progress")
		return
	}

	// Token still exists - agent hasn't called rotate-key yet, or is retrying
	if input.RotationToken == "" {
		common.RespondError(w, http.StatusBadRequest, "rotation_token is required")
		return
	}
	if rotationToken != input.RotationToken {
		slog.Warn("Invalid rotation token provided to confirm-rotation",
			"hostname", hostname,
		)
		common.RespondError(w, http.StatusUnauthorized, "invalid rotation token")
		return
	}

	err = h.Store.ConfirmRotation(r.Context(), hostname)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to confirm rotation")
		return
	}

	slog.Info("Agent confirmed HMAC key rotation",
		"hostname", hostname,
		"action", "confirm_rotation",
	)

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status":  "confirmed",
		"message": "Key rotation completed successfully",
	})
}
