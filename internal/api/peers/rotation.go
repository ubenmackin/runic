package peers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"runic/internal/api/common"
	"runic/internal/db"
)

// Simple rate limiter for public rotation endpoints
type rateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter old requests
	var recent []time.Time
	for _, t := range rl.requests[key] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= rl.limit {
		rl.requests[key] = recent
		return false
	}

	rl.requests[key] = append(recent, now)
	return true
}

// Global rate limiters for rotation endpoints
var (
	rotateKeyRateLimiter       = newRateLimiter(10, time.Minute) // 10 requests per minute per IP
	confirmRotationRateLimiter = newRateLimiter(20, time.Minute) // 20 requests per minute per IP
)

// getClientIP extracts the client IP from the request, considering proxy headers.
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (set by reverse proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		if idx := strings.Index(xff, ","); idx > 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	// Check X-Real-IP header (set by some proxies like nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// cleanup removes stale entries from the rate limiter.
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for key, times := range rl.requests {
		var recent []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				recent = append(recent, t)
			}
		}
		if len(recent) == 0 {
			delete(rl.requests, key)
		} else {
			rl.requests[key] = recent
		}
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			rotateKeyRateLimiter.cleanup()
			confirmRotationRateLimiter.cleanup()
		}
	}()
}

// generateRotationToken generates a cryptographically secure rotation token.
// The token is a 32-byte random value, hex-encoded (64 chars).
func generateRotationToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// generateHMACKey generates a random 32-byte hex-encoded HMAC key.
func generateHMACKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// parseHostID extracts the hostname from a host_id string.
// Handles both "host-<hostname>" and bare "<hostname>" formats.
func parseHostID(hostID string) string {
	hostname := hostID
	if len(hostname) > 5 && hostname[:5] == "host-" {
		hostname = hostname[5:]
	}
	return hostname
}

// validateRotationToken checks if a rotation token is valid and not expired.
// This is a pure function - it does NOT mutate state.
func validateRotationToken(database *sql.DB, peerID int, token string) (bool, error) {
	var storedToken sql.NullString
	var lastRotatedAt sql.NullString

	err := database.QueryRow(
		"SELECT hmac_key_rotation_token, hmac_key_last_rotated_at FROM peers WHERE id = ?",
		peerID,
	).Scan(&storedToken, &lastRotatedAt)

	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to query peer: %w", err)
	}

	if !storedToken.Valid || storedToken.String == "" {
		return false, nil
	}

	// Check token matches
	if storedToken.String != token {
		return false, nil
	}

	// Check 5-minute TTL
	if lastRotatedAt.Valid {
		rotationTime, err := time.Parse(time.RFC3339, lastRotatedAt.String)
		if err != nil {
			// If we can't parse the timestamp, consider the token invalid
			return false, nil
		}
		if time.Since(rotationTime) > 5*time.Minute {
			// Token expired - but don't clear it here (side effect)
			return false, nil
		}
	}

	return true, nil
}

// cleanupExpiredTokens removes expired rotation tokens from the database.
// This should be called periodically as a background job.
func cleanupExpiredTokens(database *sql.DB) (int64, error) {
	result, err := database.Exec(`
		UPDATE peers 
		SET hmac_key_rotation_token = NULL 
		WHERE hmac_key_rotation_token IS NOT NULL 
		  AND hmac_key_last_rotated_at < datetime('now', '-5 minutes')
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	affected, _ := result.RowsAffected()
	return affected, nil
}

// RotatePeerKey handles admin-initiated key rotation.
// POST /api/v1/peers/:id/rotate-key
func RotatePeerKey(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// Get current peer info
	var hostname, currentHMACKey string
	var rotationToken sql.NullString
	err = db.DB.QueryRowContext(r.Context(),
		"SELECT hostname, hmac_key, hmac_key_rotation_token FROM peers WHERE id = ?",
		peerID,
	).Scan(&hostname, &currentHMACKey, &rotationToken)

	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	// Generate new HMAC key
	newHMACKey, err := generateHMACKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	// Generate rotation token
	token, err := generateRotationToken()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate rotation token")
		return
	}

	// Check if rotation is already in progress
	if rotationToken.Valid && rotationToken.String != "" {
		// Check if existing token is still valid (not expired)
		var lastRotatedAt sql.NullString
		err = db.DB.QueryRowContext(r.Context(),
			"SELECT hmac_key_last_rotated_at FROM peers WHERE id = ?",
			peerID,
		).Scan(&lastRotatedAt)

		if err == nil && lastRotatedAt.Valid {
			rotationTime, parseErr := time.Parse(time.RFC3339, lastRotatedAt.String)
			if parseErr == nil && time.Since(rotationTime) < 5*time.Minute {
				// Existing rotation still valid, return existing token
				common.RespondJSON(w, http.StatusOK, map[string]interface{}{
					"peer_id":        peerID,
					"hostname":       hostname,
					"rotation_token": rotationToken.String,
					"message":        "Rotation already in progress. Use the existing rotation token.",
				})
				return
			}
		}
	}

	// Store new key and token in database
	_, err = db.DB.ExecContext(r.Context(),
		"UPDATE peers SET hmac_key = ?, hmac_key_rotation_token = ?, hmac_key_last_rotated_at = ? WHERE id = ?",
		newHMACKey, token, time.Now().UTC().Format(time.RFC3339), peerID,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to update peer")
		return
	}

	// Log the rotation event
	slog.Info("HMAC key rotated by admin",
		"peer_id", peerID,
		"hostname", hostname,
		"action", "rotate_key",
	)

	// Return new key and token to admin
	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"peer_id":        peerID,
		"hostname":       hostname,
		"new_hmac_key":   newHMACKey,
		"rotation_token": token,
		"rotated_at":     time.Now().UTC().Format(time.RFC3339),
		"message":        "Key rotated successfully. Provide the rotation token to the agent to complete rotation.",
	})
}

// AgentRotateKey handles agent-initiated key rotation.
// POST /api/v1/agent/rotate-key
// The agent sends its host_id and rotation token.
// The token is consumed (set to NULL) atomically with key retrieval.
// This endpoint is PUBLIC - authentication is via the rotation token itself.
func AgentRotateKey(w http.ResponseWriter, r *http.Request) {
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

	// Rate limiting
	if !rotateKeyRateLimiter.Allow(getClientIP(r)) {
		common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if input.HostID == "" || input.RotationToken == "" {
		common.RespondError(w, http.StatusBadRequest, "host_id and rotation_token are required")
		return
	}

	hostname := parseHostID(input.HostID)

	// Atomic operation: validate token AND retrieve key AND consume token
	tx, err := db.DB.BeginTx(r.Context(), nil)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to start transaction")
		return
	}
	defer tx.Rollback()

	// Get the peer's rotation token and timestamp
	var peerID int
	var newHMACKey string
	var lastRotatedAt sql.NullString
	err = tx.QueryRowContext(r.Context(), `
		SELECT id, hmac_key, hmac_key_last_rotated_at FROM peers 
		WHERE hostname = ? AND hmac_key_rotation_token = ?
	`, hostname, input.RotationToken).Scan(&peerID, &newHMACKey, &lastRotatedAt)

	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusUnauthorized, "invalid rotation token")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to process rotation")
		return
	}

	// Check expiry in Go (avoids SQLite datetime format mismatch)
	if lastRotatedAt.Valid {
		rotationTime, err := time.Parse(time.RFC3339, lastRotatedAt.String)
		if err != nil || time.Since(rotationTime) > 5*time.Minute {
			// Token expired, clear it
			tx.ExecContext(r.Context(), "UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?", peerID)
			tx.Commit()
			common.RespondError(w, http.StatusUnauthorized, "expired rotation token")
			return
		}
	}

	// Consume the token immediately - makes it single-use
	_, err = tx.ExecContext(r.Context(),
		"UPDATE peers SET hmac_key_rotation_token = NULL WHERE id = ?",
		peerID,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to consume token")
		return
	}

	if err := tx.Commit(); err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	slog.Info("Agent retrieved new HMAC key",
		"peer_id", peerID,
		"hostname", hostname,
		"action", "retrieve_key",
	)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"new_hmac_key": newHMACKey,
		"message":      "New key retrieved. Apply it and call /agent/confirm-rotation to complete.",
	})
}

// AgentConfirmRotation handles agent confirmation of key rotation.
// POST /api/v1/agent/confirm-rotation
// Requires the rotation token as proof of legitimate rotation.
func AgentConfirmRotation(w http.ResponseWriter, r *http.Request) {
	var input struct {
		HostID        string `json:"host_id"`
		RotationToken string `json:"rotation_token"` // Required only if rotation token still exists (not yet consumed)
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Rate limiting
	if !confirmRotationRateLimiter.Allow(getClientIP(r)) {
		common.RespondError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	if input.HostID == "" {
		common.RespondError(w, http.StatusBadRequest, "host_id is required")
		return
	}

	hostname := parseHostID(input.HostID)

	// Check if rotation was actually pending (token should already be NULL after AgentRotateKey)
	var peerID int
	var currentToken sql.NullString
	err := db.DB.QueryRowContext(r.Context(),
		"SELECT id, hmac_key_rotation_token FROM peers WHERE hostname = ?",
		hostname,
	).Scan(&peerID, &currentToken)

	if err == sql.ErrNoRows {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	// Verify rotation was actually pending or recently completed
	if !currentToken.Valid || currentToken.String == "" {
		// Token already consumed - check if rotation was recent
		var lastRotatedAt sql.NullString
		err = db.DB.QueryRowContext(r.Context(),
			"SELECT hmac_key_last_rotated_at FROM peers WHERE id = ?",
			peerID,
		).Scan(&lastRotatedAt)

		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
			return
		}

		if lastRotatedAt.Valid {
			rotationTime, err := time.Parse(time.RFC3339, lastRotatedAt.String)
			if err == nil && time.Since(rotationTime) < 10*time.Minute {
				// Rotation was recent, allow confirmation
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

	// Token should be NULL (consumed by AgentRotateKey), or match if agent is retrying
	if currentToken.Valid && currentToken.String != "" {
		// Token still exists - agent hasn't called rotate-key yet, or is retrying
		if input.RotationToken == "" {
			common.RespondError(w, http.StatusBadRequest, "rotation_token is required")
			return
		}
		if currentToken.String != input.RotationToken {
			slog.Warn("Invalid rotation token provided to confirm-rotation",
				"peer_id", peerID,
				"hostname", hostname,
			)
			common.RespondError(w, http.StatusUnauthorized, "invalid rotation token")
			return
		}
	}

	// Update last rotation timestamp
	_, err = db.DB.ExecContext(r.Context(),
		"UPDATE peers SET hmac_key_last_rotated_at = ? WHERE id = ?",
		time.Now().UTC().Format(time.RFC3339), peerID,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to confirm rotation")
		return
	}

	slog.Info("Agent confirmed HMAC key rotation",
		"peer_id", peerID,
		"hostname", hostname,
		"action", "confirm_rotation",
	)

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status":  "confirmed",
		"message": "Key rotation completed successfully",
	})
}
