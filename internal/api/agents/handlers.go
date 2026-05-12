// Package agents provides agent api handlers.
package agents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/alerts"
	"runic/internal/api/common"
	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
	"runic/internal/store"
)

type Handler struct {
	PeerStore      *store.PeerStore
	DashboardStore *store.DashboardStore
	AlertService   *alerts.Service
	ImportStore    *store.ImportStore
	TokenStore     *store.TokenStore
	beginner       db.Beginner
}

// NewHandler creates a new agent handler. peerStore handles peer data access, dashboardStore
// handles logs/registration-tokens/secrets, alertService is optional and can be nil.
func NewHandler(peerStore *store.PeerStore, dashboardStore *store.DashboardStore, alertService *alerts.Service, importStore *store.ImportStore, tokenStore *store.TokenStore, beginner db.Beginner) *Handler {
	return &Handler{PeerStore: peerStore, DashboardStore: dashboardStore, AlertService: alertService, ImportStore: importStore, TokenStore: tokenStore, beginner: beginner}
}

type LogEvent struct {
	Timestamp string `json:"timestamp"`
	Direction string `json:"direction"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	Action    string `json:"action"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	RawLine   string `json:"raw_line"`
}

var validActions = []string{"ACCEPT", "DROP", "REJECT"}
var validDirections = []string{"IN", "OUT"}

// Validate validates the LogEvent. Empty optional fields are allowed, but if present they must be valid.
// Returns (true, "") if valid, or (false, reason) if invalid.
func (e *LogEvent) Validate() (bool, string) {
	if e.SrcIP != "" && net.ParseIP(e.SrcIP) == nil {
		return false, fmt.Sprintf("invalid src_ip: %s", e.SrcIP)
	}
	if e.DstIP != "" && net.ParseIP(e.DstIP) == nil {
		return false, fmt.Sprintf("invalid dst_ip: %s", e.DstIP)
	}
	if e.SrcPort < 0 || e.SrcPort > 65535 {
		return false, fmt.Sprintf("src_port out of range: %d", e.SrcPort)
	}
	if e.DstPort < 0 || e.DstPort > 65535 {
		return false, fmt.Sprintf("dst_port out of range: %d", e.DstPort)
	}
	if e.Action != "" && !slices.Contains(validActions, e.Action) {
		return false, fmt.Sprintf("invalid action: %s", e.Action)
	}
	if e.Direction != "" && !slices.Contains(validDirections, e.Direction) {
		return false, fmt.Sprintf("invalid direction: %s", e.Direction)
	}
	return true, ""
}

type SSEBroadcaster interface {
	Register(hostID string) chan string
	Unregister(hostID string)
}

type LogBroadcaster interface {
	Broadcast(event *models.LogEvent)
}

type contextKey string

const (
	sseHubKey contextKey = "sse_hub"
	logHubKey contextKey = "log_hub"
	hostIDKey contextKey = "host_id"
)

func SSEHubFromContext(ctx context.Context) SSEBroadcaster {
	if h, ok := ctx.Value(sseHubKey).(SSEBroadcaster); ok {
		return h
	}
	return nil
}

func LogHubFromContext(ctx context.Context) LogBroadcaster {
	if h, ok := ctx.Value(logHubKey).(LogBroadcaster); ok {
		return h
	}
	return nil
}

func WithHubs(ctx context.Context, sseHub SSEBroadcaster, logHub LogBroadcaster) context.Context {
	ctx = context.WithValue(ctx, sseHubKey, sseHub)
	ctx = context.WithValue(ctx, logHubKey, logHub)
	return ctx
}

func (h *Handler) AgentAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		tokenString := authHeader[7:]

		secretStr, err := h.DashboardStore.GetSecret(r.Context(), "agent_jwt_secret")
		if err != nil {
			runiclog.Error("JWT secret not configured", "error", err)
			common.InternalError(w)
			return
		}
		secret := []byte(secretStr)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return secret, nil
		})

		if err != nil || !token.Valid {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Verify type is agent
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "agent" {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		// Check token revocation via jti (unique token ID)
		if jti, ok := claims["jti"].(string); ok && jti != "" && h.TokenStore != nil {
			revoked, checkErr := h.TokenStore.IsTokenRevoked(r.Context(), jti)
			if checkErr != nil {
				runiclog.Error("failed to check token revocation", "error", checkErr)
			} else if revoked {
				common.RespondError(w, http.StatusUnauthorized, "token has been revoked")
				return
			}
		}

		// Use typed context key to prevent collisions
		ctx := context.WithValue(r.Context(), hostIDKey, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (h *Handler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	var input models.AgentRegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Sanitize user input to prevent injection attacks.
	//
	// Defense-in-Depth Strategy: We use two layers of sanitization:
	//
	// 1. ENTRY POINT (here): Remove control characters (CR, LF, NUL, TAB, etc.)
	//    - This prevents header injection attacks (e.g., email header injection via
	//      embedded newlines that could add malicious headers like "Bcc: attacker@evil.com")
	//    - Control characters are removed here because they can never be legitimate in
	//      hostname/IP fields and pose systemic risks regardless of output format
	//    - We use SanitizeAlertInput which does NOT escape HTML chars (<, >, &) because
	//      these may be legitimate in hostnames and escaping should happen at output time
	//
	// 2. OUTPUT TIME (email generation): HTML escaping via htmlEscape
	//    - HTML special characters are escaped at email generation time to prevent XSS
	//    - This is done at output time rather than entry point because:
	//      a) The same data may be used in non-HTML contexts (logs, CLI, JSON APIs)
	//      b) Proper escaping depends on the output context (HTML, JSON, plain text)
	//      c) Early escaping could corrupt legitimate data or cause double-encoding
	//
	// This layered approach ensures each sanitization happens at the appropriate layer
	sanitizedHostname, modified := alerts.SanitizeAlertInput(input.Hostname, 255)
	if modified {
		runiclog.Warn("hostname was sanitized during registration", "original_length", len(input.Hostname), "sanitized_length", len(sanitizedHostname))
	}
	input.Hostname = sanitizedHostname

	sanitizedIP, modified := alerts.SanitizeAlertInput(input.IP, 45)
	if modified {
		runiclog.Warn("ip was sanitized during registration", "original_length", len(input.IP), "sanitized_length", len(sanitizedIP))
	}
	input.IP = sanitizedIP

	if input.Hostname == "" {
		common.RespondError(w, http.StatusBadRequest, "hostname required")
		return
	}

	ctx := r.Context()

	var existingID int
	existingID, _, err := h.PeerStore.FindPeerByHostname(ctx, input.Hostname)

	if errors.Is(err, sql.ErrNoRows) {
		// New server — require valid registration token
		if input.RegistrationToken == "" {
			common.RespondError(w, http.StatusUnauthorized, "registration token required")
			return
		}

		// Atomic consume: validates AND consumes in single query
		consumed, err := h.ConsumeRegistrationToken(input.RegistrationToken, input.Hostname)
		if err != nil {
			runiclog.Error("Failed to consume registration token", "error", err)
			common.InternalError(w)
			return
		}
		if !consumed {
			common.RespondError(w, http.StatusUnauthorized, "invalid registration token")
			return
		}

		hmacKey, err := GenerateHMACKey()
		if err != nil {
			runiclog.Error("Failed to generate HMAC key", "error", err)
			common.InternalError(w)
			return
		}
		agentToken, err := generateAgentToken(ctx, h.DashboardStore, input.Hostname)
		if err != nil {
			runiclog.Error("Failed to generate agent token error", "error", err)
			common.InternalError(w)
			return
		}
		agentKey, err := generateAgentKey()
		if err != nil {
			runiclog.Error("Failed to generate agent key", "error", err)
			common.InternalError(w)
			return
		}

		peerID, err := h.PeerStore.RegisterPeer(ctx, input.Hostname, input.IP, input.OSType, input.Arch, input.HasDocker, input.HasIPSet, agentKey, agentToken, hmacKey)
		if err != nil {
			runiclog.Error("Failed to create server error", "error", err)
			common.InternalError(w)
			return
		}

		if len(input.AllIPs) > 0 {
			if err := h.PeerStore.UpsertPeerIPs(ctx, int(peerID), input.AllIPs, input.IP); err != nil {
				runiclog.Warn("Failed to upsert peer IPs during registration", "error", err, "peer_id", peerID)
			}
		}

		hostID := fmt.Sprintf("host-%s", input.Hostname)

		common.RespondJSON(w, http.StatusCreated, map[string]interface{}{
			"host_id":                hostID,
			"token":                  agentToken,
			"pull_interval_seconds":  86400,
			"current_bundle_version": "",
			"hmac_key":               hmacKey,
		})

		// Trigger new_peer alert for newly registered peer
		if h.AlertService != nil {
			// Sanitize hostname before using it in alert content (subject/body/metadata).
			safeHostname, _ := alerts.SanitizeAlertInput(input.Hostname, 0)
			var newPeerID int
			if newPeerID, err = h.PeerStore.GetPeerIDByHostname(ctx, input.Hostname); err == nil {
				if err := h.AlertService.TriggerAlert(ctx, &alerts.AlertEvent{
					Type:     alerts.AlertTypeNewPeer,
					PeerID:   newPeerID,
					PeerName: safeHostname,
					Subject:  fmt.Sprintf("New Peer Registered: %s", safeHostname),
					Metadata: map[string]interface{}{
						"hostname":      safeHostname,
						"ip_address":    input.IP,
						"os_type":       input.OSType,
						"agent_version": input.AgentVersion,
						"registered_by": input.RegistrationToken,
					},
				}); err != nil {
					runiclog.Error("failed to trigger new peer alert", "error", err, "hostname", input.Hostname)
				}
			}
		}

		return
	} else if err != nil {
		runiclog.Error("Database error checking hostname error", "error", err)
		common.InternalError(w)
		return
	}

	// Existing server — always generate fresh token (handles token expiration)
	// Re-registration does NOT require a registration token
	hostID := fmt.Sprintf("host-%s", input.Hostname)

	newToken, err := generateAgentToken(ctx, h.DashboardStore, input.Hostname)
	if err != nil {
		runiclog.Error("Failed to generate agent token error", "error", err)
		common.InternalError(w)
		return
	}

	existingHMACKey, err := h.PeerStore.GetPeerHMACKey(ctx, existingID)
	if err != nil {
		runiclog.Error("Failed to fetch existing HMAC key", "error", err, "peer_id", existingID)
		common.InternalError(w)
		return
	}

	if err := h.PeerStore.UpdatePeerReRegistration(ctx, existingID, newToken, input.AgentVersion, input.HasDocker, input.HasIPSet); err != nil {
		runiclog.Error("Failed to update peer token", "error", err, "peer_id", existingID)
		common.InternalError(w)
		return
	}

	if len(input.AllIPs) > 0 {
		if err := h.PeerStore.UpsertPeerIPs(ctx, existingID, input.AllIPs, input.IP); err != nil {
			runiclog.Warn("Failed to upsert peer IPs during re-registration", "error", err, "peer_id", existingID)
		}
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"host_id":                hostID,
		"token":                  newToken,
		"pull_interval_seconds":  86400,
		"current_bundle_version": "",
		"hmac_key":               existingHMACKey,
	})
}

func (h *Handler) GetBundle(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	ifNoneMatch := r.Header.Get("If-None-Match")

	var bundle models.RuleBundleRow
	bundle, err := h.PeerStore.GetLatestBundle(r.Context(), serverID)

	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "no bundle found")
		return
	} else if err != nil {
		runiclog.Error("Failed to fetch bundle error", "error", err)
		common.InternalError(w)
		return
	}

	w.Header().Set("ETag", bundle.Version)
	if ifNoneMatch == bundle.Version {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"version":        bundle.Version,
		"version_number": bundle.VersionNumber,
		"rules":          bundle.RulesContent,
		"hmac":           bundle.HMAC,
	})
}

func (h *Handler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		BundleVersionApplied string   `json:"bundle_version_applied"`
		UptimeSeconds        float64  `json:"uptime_seconds"`
		Load1m               float64  `json:"load_1m"`
		AgentVersion         string   `json:"agent_version"`
		HasIPSet             *bool    `json:"has_ipset"`
		AllIPs               []string `json:"all_ips"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		runiclog.Error("Heartbeat: failed to decode body error", "error", err)
		// Continue anyway — agent_version and bundle_version may be empty
	}

	if err := h.PeerStore.UpdatePeerHeartbeat(r.Context(), serverID, input.AgentVersion, input.BundleVersionApplied, input.HasIPSet); err != nil {
		runiclog.Error("Failed to update heartbeat error", "error", err)
	}

	if len(input.AllIPs) > 0 {
		if primaryIP, err := h.PeerStore.GetPeerPrimaryIP(r.Context(), serverID); err == nil {
			if _, err := h.PeerStore.SyncPeerIPs(r.Context(), serverID, input.AllIPs, primaryIP); err != nil {
				runiclog.Warn("Failed to sync peer IPs during heartbeat", "error", err, "peer_id", serverID)
			}
		}
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (h *Handler) SubmitLogs(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		Events []LogEvent `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	peerHostname, err := h.PeerStore.GetPeerHostname(r.Context(), serverID)
	if err != nil {
		runiclog.Error("Failed to lookup peer hostname", "error", err, "peer_id", serverID)
		// Continue with empty hostname - better to insert logs than fail completely
		peerHostname = ""
	}

	accepted := 0
	skipped := 0

	for i := range input.Events {
		ev := &input.Events[i]
		if valid, reason := ev.Validate(); !valid {
			runiclog.Warn("Skipping invalid log event", "reason", reason)
			skipped++
			continue
		}

		// Note: Logs DB schema uses different column names than main DB
		err := h.DashboardStore.InsertFirewallLog(r.Context(), &store.FirewallLogEntry{
			PeerID:       fmt.Sprintf("%d", serverID),
			PeerHostname: peerHostname,
			Timestamp:    ev.Timestamp,
			Direction:    ev.Direction,
			SrcIP:        ev.SrcIP,
			DstIP:        ev.DstIP,
			Protocol:     ev.Protocol,
			SrcPort:      ev.SrcPort,
			DstPort:      ev.DstPort,
			Action:       ev.Action,
			RawLine:      ev.RawLine,
		})
		if err != nil {
			runiclog.Error("Failed to insert log event", "error", err)
			skipped++
			continue
		}
		accepted++

		event := models.LogEvent{
			PeerID:   serverID,
			Action:   ev.Action,
			SrcIP:    ev.SrcIP,
			DstIP:    ev.DstIP,
			Protocol: ev.Protocol,
		}
		if hub := LogHubFromContext(r.Context()); hub != nil {
			hub.Broadcast(&event)
		}
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"accepted": accepted,
		"skipped":  skipped,
	})
}

func (h *Handler) ConfirmBundleApplied(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		Version   string `json:"version"`
		AppliedAt string `json:"applied_at"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	appliedAt := input.AppliedAt
	if appliedAt == "" {
		appliedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Wrap both DB calls in a transaction to prevent partial state on crash
	err := store.RunInTx(r.Context(), h.beginner, func(tx *sql.Tx) error {
		// UpdateBundleAppliedAt and UpdatePeerBundleVersion need to be atomic.
		// Since PeerStore methods use s.db directly, we use the raw tx ExecContext.
		// This avoids duplicating the store methods while keeping the writes atomic.
		if _, execErr := tx.ExecContext(r.Context(),
			`UPDATE rule_bundles SET applied_at = ?, first_applied_at = COALESCE(first_applied_at, ?) WHERE peer_id = ? AND version = ?`,
			appliedAt, appliedAt, serverID, input.Version); execErr != nil {
			return fmt.Errorf("update bundle applied_at: %w", execErr)
		}
		if _, execErr := tx.ExecContext(r.Context(),
			`UPDATE peers SET bundle_version = ? WHERE id = ?`,
			input.Version, serverID); execErr != nil {
			return fmt.Errorf("update peer bundle version: %w", execErr)
		}
		return nil
	})
	if err != nil {
		runiclog.Error("Failed to confirm bundle apply in transaction", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// MakeHandleSSEventsHandler creates the SSE handler. This is the preferred way to create the SSE handler as it avoids context propagation issues.
func (h *Handler) MakeHandleSSEventsHandler(hub SSEBroadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, _, ok := h.getHostIDFromContext(w, r)
		if !ok {
			runiclog.Error("MakeHandleSSEventsHandler: failed to get host_id from context")
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Transfer-Encoding", "chunked")

		if hub == nil {
			common.RespondError(w, http.StatusInternalServerError, "SSE hub unavailable")
			return
		}
		ch := hub.Register(hostID)
		defer hub.Unregister(hostID)

		flusher, ok := w.(http.Flusher)
		if !ok {
			common.RespondError(w, http.StatusInternalServerError, "SSE not supported")
			return
		}

		ticker := time.NewTicker(constants.SSEKeepaliveInterval)
		defer ticker.Stop()

		if _, err := fmt.Fprintf(w, ": agent connected\n\n"); err != nil {
			return
		}
		flusher.Flush()

		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					return
				}
				if _, err := fmt.Fprintf(w, "%s", msg); err != nil {
					return
				}
				flusher.Flush()

			case <-ticker.C:
				if _, err := fmt.Fprintf(w, ": keepalive\n\n"); err != nil {
					return
				}
				flusher.Flush()

			case <-r.Context().Done():
				return
			}
		}
	}
}

func (h *Handler) AgentCheckRotation(w http.ResponseWriter, r *http.Request) {
	hostID, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	rotationToken, err := h.PeerStore.GetPeerRotationToken(r.Context(), serverID)

	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		runiclog.Error("Failed to check rotation token error", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}

	if !rotationToken.Valid || rotationToken.String == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"rotation_token": rotationToken.String,
		"host_id":        hostID,
	})
}

// SubmitBackup handles the agent's pre-Runic iptables backup. The agent posts its pre-Runic iptables backup and ipset data for import processing.
func (h *Handler) SubmitBackup(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		IPTablesBackup string `json:"iptables_backup"`
		IPSetList      string `json:"ipset_list"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if input.IPTablesBackup == "" {
		common.RespondError(w, http.StatusBadRequest, "iptables_backup is required")
		return
	}

	ctx := r.Context()

	sessionID, err := h.ImportStore.SubmitBackupSession(ctx, int64(serverID), input.IPTablesBackup, input.IPSetList)
	if err != nil {
		runiclog.Error("failed to submit backup session", "error", err, "peer_id", serverID)
		common.InternalError(w)
		return
	}

	// After the transaction commits, call ParseSession to parse the backup data,
	// This runs outside the transaction to avoid holding locks during parsing.
	if err := h.DashboardStore.ParseBackupSession(ctx, sessionID); err != nil {
		// Log the error but still return 200 — the data is saved, user can retry parse
		runiclog.Warn("ParseSession failed after backup submit", "error", err, "session_id", sessionID, "peer_id", serverID)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AgentTestKey handles POST /api/v1/agent/test-key (requires agent JWT auth)
func (h *Handler) AgentTestKey(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	hmacKey, err := h.PeerStore.GetPeerHMACKey(r.Context(), serverID)

	if errors.Is(err, sql.ErrNoRows) {
		common.RespondError(w, http.StatusNotFound, "peer not found")
		return
	}
	if err != nil {
		runiclog.Error("Failed to get HMAC key error", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}

	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(input.Message))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(input.Signature), []byte(expected)) {
		common.RespondError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
