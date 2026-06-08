package peers

import (
	"context"
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
	rotateKeyRateLimiter       = middleware.NewRateLimiter(10, time.Minute)
	confirmRotationRateLimiter = middleware.NewRateLimiter(20, time.Minute)
)

func StopRotationRateLimiters() {
	rotateKeyRateLimiter.Stop()
	confirmRotationRateLimiter.Stop()
}

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

func parseSQLiteDatetime(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func parseHostID(hostID string) string {
	hostname := hostID
	if len(hostname) > 5 && hostID[:5] == "host-" {
		hostname = hostname[5:]
	}
	return hostname
}

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
		if lastRotatedAt.Valid {
			rotationTime, parseErr := parseSQLiteDatetime(lastRotatedAt.String)
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

func (h *Handler) consumeRotationToken(ctx context.Context, hostname, token string) (int, string, bool, error) {
	var peerID64 int64
	var newHMACKey string
	var lastRotatedAt sql.NullString
	err := store.RunInTx(ctx, h.beginner, func(tx *sql.Tx) error {
		qerr := tx.QueryRowContext(ctx, `			SELECT id, hmac_key, hmac_key_last_rotated_at FROM peers
			WHERE hostname = ? AND hmac_key_rotation_token = ?
		`, hostname, token).Scan(&peerID64, &newHMACKey, &lastRotatedAt)
		if qerr != nil {
			return qerr
		}
		if lastRotatedAt.Valid {
			rotationTime, parseErr := parseSQLiteDatetime(lastRotatedAt.String)
			if parseErr != nil || time.Since(rotationTime) > 5*time.Minute {
				return common.NewHTTPError(http.StatusUnauthorized, "expired rotation token")
			}
		}
		if cerr := h.Store.ConsumeRotationTokenByIDTx(ctx, tx, int(peerID64)); cerr != nil {
			return cerr
		}
		slog.Info("Agent retrieved new HMAC key",
			"peer_id", peerID64,
			"hostname", hostname,
			"action", "retrieve_key",
		)
		return nil
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, "", false, common.NewHTTPError(http.StatusUnauthorized, "invalid rotation token")
		}
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) && httpErr.StatusCode == http.StatusUnauthorized {
			if clearErr := h.Store.ClearRotationToken(ctx, int(peerID64)); clearErr != nil {
				slog.Warn("failed to clear expired rotation token", "error", clearErr)
			}
			return int(peerID64), "", true, err
		}
		return 0, "", false, err
	}
	return int(peerID64), newHMACKey, false, nil
}

func (h *Handler) AgentRotateKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var input struct {
		HostID        string `json:"host_id"`
		RotationToken string `json:"rotation_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if rotateKeyRateLimiter.Check(common.GetClientIP(r)) != nil {
		common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}
	if input.HostID == "" || input.RotationToken == "" {
		common.RespondError(w, http.StatusBadRequest, "host_id and rotation_token are required")
		return
	}

	hostname := parseHostID(input.HostID)
	_, newHMACKey, expired, err := h.consumeRotationToken(r.Context(), hostname, input.RotationToken)
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to process rotation")
		return
	}
	if expired {
		common.RespondError(w, http.StatusUnauthorized, "expired rotation token")
		return
	}

	w.Header().Set("X-New-HMAC-Key", newHMACKey)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"new_hmac_key": newHMACKey,
		"message":      "New key retrieved. Apply it and call /agent/confirm-rotation to complete.",
	})
}

func (h *Handler) AgentConfirmRotation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var input struct {
		HostID        string `json:"host_id"`
		RotationToken string `json:"rotation_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if confirmRotationRateLimiter.Check(common.GetClientIP(r)) != nil {
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
		_, lastRotatedAt, err := h.Store.GetPeerIDAndLastRotatedAt(r.Context(), hostname)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
			return
		}
		if lastRotatedAt.Valid {
			rotationTime, parseErr := parseSQLiteDatetime(lastRotatedAt.String)
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
	if input.RotationToken == "" {
		common.RespondError(w, http.StatusBadRequest, "rotation_token is required")
		return
	}
	if rotationToken != input.RotationToken {
		slog.Warn("Invalid rotation token provided to confirm-rotation", "hostname", hostname)
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
