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
	"runic/internal/importer"
	"runic/internal/models"
	"runic/internal/store"
)

// Handler provides HTTP handlers for agent endpoints with dependency injection.
type Handler struct {
	PeerStore    *store.PeerStore
	DB           db.DB // Used for SubmitBackup's store.RunInTx and registration token queries
	LogsDB       db.Querier
	AlertService *alerts.Service
}

// NewHandler creates a new agent handler with the given dependencies.
// peerStore handles peer data access, db is the main database for transactions,
// logsDB is the separate logs database, alertService is optional and can be nil.
func NewHandler(peerStore *store.PeerStore, db db.DB, logsDB db.Querier, alertService *alerts.Service) *Handler {
	return &Handler{PeerStore: peerStore, DB: db, LogsDB: logsDB, AlertService: alertService}
}

// LogEvent represents a validated firewall log event from an agent.
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

// Validate checks that the LogEvent fields are well-formed.
// Empty optional fields are allowed, but if present they must be valid.
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

// SSEBroadcaster interfaces to avoid import cycles
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

// SSEHubFromContext returns the SSEHub from context (set by API middleware)
func SSEHubFromContext(ctx context.Context) SSEBroadcaster {
	if h, ok := ctx.Value(sseHubKey).(SSEBroadcaster); ok {
		return h
	}
	return nil
}

// LogHubFromContext returns the LogHub from context (set by API middleware)
func LogHubFromContext(ctx context.Context) LogBroadcaster {
	if h, ok := ctx.Value(logHubKey).(LogBroadcaster); ok {
		return h
	}
	return nil
}

// WithHubs injects hub dependencies into the context.
func WithHubs(ctx context.Context, sseHub SSEBroadcaster, logHub LogBroadcaster) context.Context {
	ctx = context.WithValue(ctx, sseHubKey, sseHub)
	ctx = context.WithValue(ctx, logHubKey, logHub)
	return ctx
}

// AgentAuthMiddleware handles authentication for agent endpoints.
func (h *Handler) AgentAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		tokenString := authHeader[7:]

		secretStr, err := db.GetSecret(r.Context(), h.DB, "agent_jwt_secret")
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

		// Use typed context key to prevent collisions
		ctx := context.WithValue(r.Context(), hostIDKey, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// RegisterAgent handles agent registration.
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
	// for the specific threat vector it addresses.
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
		agentToken, err := generateAgentToken(ctx, h.DB, input.Hostname)
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

		// Insert all reported IPs into peer_ips
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

	newToken, err := generateAgentToken(ctx, h.DB, input.Hostname)
	if err != nil {
		runiclog.Error("Failed to generate agent token error", "error", err)
		common.InternalError(w)
		return
	}

	// Fetch existing HMAC key (don't regenerate on reinstall)
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

	// Update peer IPs on re-registration if the agent reports IPs
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

// GetBundle handles bundle download requests from agents.
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

// Heartbeat handles agent heartbeat requests.
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

	// Update peer heartbeat and status
	if err := h.PeerStore.UpdatePeerHeartbeat(r.Context(), serverID, input.AgentVersion, input.BundleVersionApplied, input.HasIPSet); err != nil {
		runiclog.Error("Failed to update heartbeat error", "error", err)
	}

	// Update peer IPs if the agent reports them
	if len(input.AllIPs) > 0 {
		// Look up the primary IP for this peer
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

// SubmitLogs handles log submissions from agents.
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

	// Look up the peer hostname from main DB for denormalization
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
		_, err := h.LogsDB.ExecContext(r.Context(),
			`INSERT INTO firewall_logs (peer_id, peer_hostname, timestamp, event_type, source_ip, dest_ip, protocol, source_port, dest_port, action, details) 
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fmt.Sprintf("%d", serverID), peerHostname, ev.Timestamp, ev.Direction, ev.SrcIP, ev.DstIP, ev.Protocol, ev.SrcPort, ev.DstPort, ev.Action, ev.RawLine)
		if err != nil {
			runiclog.Error("Failed to insert log event", "error", err)
			skipped++
			continue
		}
		accepted++

		event := models.LogEvent{
			PeerID:   fmt.Sprintf("%d", serverID),
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

// ConfirmBundleApplied handles confirmation that a bundle was applied.
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

	// Update applied_at timestamp on the bundle
	appliedAt := input.AppliedAt
	if appliedAt == "" {
		appliedAt = time.Now().UTC().Format(time.RFC3339)
	}

	err := h.PeerStore.UpdateBundleAppliedAt(r.Context(), serverID, input.Version, appliedAt)
	if err != nil {
		runiclog.Error("Failed to confirm bundle apply error", "error", err)
	}

	// Update peer's bundle_version
	if err := h.PeerStore.UpdatePeerBundleVersion(r.Context(), serverID, input.Version); err != nil {
		runiclog.Error("Failed to update peer bundle version", "error", err)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// MakeHandleSSEventsHandler creates an SSE handler with explicit SSE hub injection.
// This is the preferred way to create the SSE handler as it avoids context propagation issues.
func (h *Handler) MakeHandleSSEventsHandler(hub SSEBroadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, _, ok := h.getHostIDFromContext(w, r)
		if !ok {
			runiclog.Error("MakeHandleSSEventsHandler: failed to get host_id from context")
			return
		}

		// Set SSE headers
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

// AgentCheckRotation checks if a rotation is pending for the agent.
func (h *Handler) AgentCheckRotation(w http.ResponseWriter, r *http.Request) {
	hostID, serverID, ok := h.getHostIDFromContext(w, r)
	if !ok {
		return
	}

	// Check if there's a pending rotation token
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

// SubmitBackup handles backup data submissions from agents.
// The agent posts its pre-Runic iptables backup and ipset data for import processing.
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
	var sessionID int64

	err := store.RunInTx(ctx, h.DB, func(tx *sql.Tx) error {
		var existingID int64
		var existingStatus string
		err := tx.QueryRowContext(ctx, "SELECT id, status FROM import_sessions WHERE peer_id = ? AND status IN ('pending','parsed','reviewing')", serverID).Scan(&existingID, &existingStatus)

		switch {
		case err == nil:
			sessionID = existingID
			if existingStatus == "pending" {
				_, err = tx.ExecContext(ctx, "UPDATE import_sessions SET raw_backup = ?, raw_ipsets = ?, updated_at = CURRENT_TIMESTAMP WHERE peer_id = ? AND status = 'pending'", input.IPTablesBackup, input.IPSetList, serverID)
				if err != nil {
					return common.NewHTTPError(http.StatusInternalServerError, "failed to update import session", err)
				}
			}
		case errors.Is(err, sql.ErrNoRows):
			result, err := tx.ExecContext(ctx, "INSERT INTO import_sessions (peer_id, status, raw_backup, raw_ipsets) VALUES (?, 'pending', ?, ?)", serverID, input.IPTablesBackup, input.IPSetList)
			if err != nil {
				return common.NewHTTPError(http.StatusInternalServerError, "failed to create import session", err)
			}
			sessionID, err = result.LastInsertId()
			if err != nil {
				return common.NewHTTPError(http.StatusInternalServerError, "failed to get session ID", err)
			}
		default:
			return common.NewHTTPError(http.StatusInternalServerError, "database error", err)
		}
		return nil
	})

	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			runiclog.Error(httpErr.Message, "error", httpErr.Err, "peer_id", serverID)
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
		} else {
			runiclog.Error("transaction failed", "error", err, "peer_id", serverID)
			common.InternalError(w)
		}
		return
	}

	// After the transaction commits, call ParseSession to parse the backup data,
	// insert rules, run the resolver, and update status to 'parsed'.
	// This runs outside the transaction to avoid holding locks during parsing.
	if sqlDB, ok := h.DB.(*sql.DB); ok {
		if err := importer.ParseSession(ctx, sqlDB, sessionID); err != nil {
			// Log the error but still return 200 — the data is saved, user can retry parse
			runiclog.Warn("ParseSession failed after backup submit", "error", err, "session_id", sessionID, "peer_id", serverID)
		}
	} else {
		runiclog.Warn("Cannot run ParseSession: DB is not *sql.DB", "peer_id", serverID)
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// AgentTestKey validates an HMAC signature using the peer's current key.
// POST /api/v1/agent/test-key (requires agent JWT auth)
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

	// Get peer's current HMAC key
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

	if input.Signature != expected {
		common.RespondError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
