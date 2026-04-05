package agents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/api/common"
	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

// Handler provides HTTP handlers for agent endpoints with dependency injection.
type Handler struct {
	DB db.Querier
}

// NewHandler creates a new agent handler with the given database connection.
func NewHandler(db db.Querier) *Handler {
	return &Handler{DB: db}
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

// Hub interfaces to avoid import cycles
type SSEBroadcaster interface {
	Register(hostID string) chan string
	Unregister(hostID string)
}

type LogBroadcaster interface {
	Broadcast(event models.LogEvent)
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
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]

		// Parse token
		secretStr, err := db.GetSecret(r.Context(), h.DB, "agent_jwt_secret")
		if err != nil {
			runiclog.Error("JWT secret not configured", "error", err)
			http.Error(w, `{"error": "server misconfiguration"}`, http.StatusInternalServerError)
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
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// Verify type is agent
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "agent" {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// Inject host_id into context
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
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
		http.Error(w, `{"error": "invalid JSON"}`, http.StatusBadRequest)
		return
	}

	if input.Hostname == "" {
		http.Error(w, `{"error": "hostname required"}`, http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Check if hostname already exists
	var existingID int
	var existingToken sql.NullString
	err := h.DB.QueryRowContext(ctx, "SELECT id, agent_token FROM peers WHERE hostname = ?", input.Hostname).Scan(&existingID, &existingToken)

	if err == sql.ErrNoRows {
		// New server — require valid registration token
		if input.RegistrationToken == "" {
			http.Error(w, `{"error": "registration token required"}`, http.StatusUnauthorized)
			return
		}

		// Atomic consume: validates AND consumes in single query
		consumed, err := h.ConsumeRegistrationToken(input.RegistrationToken, input.Hostname)
		if err != nil {
			runiclog.Error("Failed to consume registration token", "error", err)
			http.Error(w, `{"error": "internal server error"}`, http.StatusInternalServerError)
			return
		}
		if !consumed {
			http.Error(w, `{"error": "invalid registration token"}`, http.StatusUnauthorized)
			return
		}

		// Token consumed — now create the peer
		hmacKey, err := GenerateHMACKey()
		if err != nil {
			runiclog.Error("Failed to generate HMAC key", "error", err)
			http.Error(w, `{"error": "failed to generate HMAC key"}`, http.StatusInternalServerError)
			return
		}
		agentToken, err := generateAgentToken(ctx, h.DB, input.Hostname)
		if err != nil {
			runiclog.Error("Failed to generate agent token error", "error", err)
			http.Error(w, `{"error": "failed to generate agent token"}`, http.StatusInternalServerError)
			return
		}
		agentKey, err := generateAgentKey()
		if err != nil {
			runiclog.Error("Failed to generate agent key", "error", err)
			http.Error(w, `{"error": "failed to generate agent key"}`, http.StatusInternalServerError)
			return
		}

		_, err = h.DB.ExecContext(ctx, `INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, has_ipset, agent_key, agent_token, hmac_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'online')`, input.Hostname, input.IP, input.OSType, input.Arch, input.HasDocker, input.HasIPSet, agentKey, agentToken, hmacKey)
		if err != nil {
			runiclog.Error("Failed to create server error", "error", err)
			http.Error(w, `{"error": "failed to create server"}`, http.StatusInternalServerError)
			return
		}

		hostID := fmt.Sprintf("host-%s", input.Hostname)

		common.RespondJSON(w, http.StatusCreated, map[string]interface{}{
			"host_id":                hostID,
			"token":                  agentToken,
			"pull_interval_seconds":  86400,
			"current_bundle_version": "",
			"hmac_key":               hmacKey,
		})
		return
	} else if err != nil {
		runiclog.Error("Database error checking hostname error", "error", err)
		http.Error(w, `{"error": "database error"}`, http.StatusInternalServerError)
		return
	}

	// Existing server — always generate fresh token (handles token expiration)
	// Re-registration does NOT require a registration token
	hostID := fmt.Sprintf("host-%s", input.Hostname)

	// Always generate fresh token for re-registration
	newToken, err := generateAgentToken(ctx, h.DB, input.Hostname)
	if err != nil {
		runiclog.Error("Failed to generate agent token error", "error", err)
		http.Error(w, `{"error": "failed to generate agent token"}`, http.StatusInternalServerError)
		return
	}

	// Fetch existing HMAC key (don't regenerate on reinstall)
	var existingHMACKey string
	if err := h.DB.QueryRowContext(ctx, "SELECT hmac_key FROM peers WHERE id = ?", existingID).Scan(&existingHMACKey); err != nil {
		runiclog.Error("Failed to fetch existing HMAC key", "error", err, "peer_id", existingID)
		http.Error(w, `{"error": "failed to fetch peer data"}`, http.StatusInternalServerError)
		return
	}

	if _, err := h.DB.ExecContext(ctx, "UPDATE peers SET agent_token = ?, status = 'online', agent_version = ?, has_docker = ?, has_ipset = ? WHERE id = ?", newToken, input.AgentVersion, input.HasDocker, input.HasIPSet, existingID); err != nil {
		runiclog.Error("Failed to update peer token", "error", err, "peer_id", existingID)
		http.Error(w, `{"error": "failed to update peer"}`, http.StatusInternalServerError)
		return
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

	// Check If-None-Match header
	ifNoneMatch := r.Header.Get("If-None-Match")

	// Get latest bundle for this peer
	var bundle models.RuleBundleRow
	err := h.DB.QueryRowContext(r.Context(), `SELECT id, peer_id, version, version_number, rules_content, hmac, created_at FROM rule_bundles WHERE peer_id = ? ORDER BY created_at DESC LIMIT 1`, serverID).Scan(&bundle.ID, &bundle.PeerID, &bundle.Version, &bundle.VersionNumber, &bundle.RulesContent, &bundle.HMAC, &bundle.CreatedAt)

	if err == sql.ErrNoRows {
		http.Error(w, `{"error": "no bundle found"}`, http.StatusNotFound)
		return
	} else if err != nil {
		runiclog.Error("Failed to fetch bundle error", "error", err)
		http.Error(w, `{"error": "failed to fetch bundle"}`, http.StatusInternalServerError)
		return
	}

	// Check ETag
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
		BundleVersionApplied string  `json:"bundle_version_applied"`
		UptimeSeconds        float64 `json:"uptime_seconds"`
		Load1m               float64 `json:"load_1m"`
		AgentVersion         string  `json:"agent_version"`
		HasIPSet             *bool   `json:"has_ipset"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		runiclog.Error("Heartbeat: failed to decode body error", "error", err)
		// Continue anyway — agent_version and bundle_version may be empty
	}

	// Update peer heartbeat and status
	_, err := h.DB.ExecContext(r.Context(), `UPDATE peers SET last_heartbeat = CURRENT_TIMESTAMP, status = 'online', agent_version = ?, bundle_version = ?, has_ipset = ? WHERE id = ?`, input.AgentVersion, input.BundleVersionApplied, input.HasIPSet, serverID)
	if err != nil {
		runiclog.Error("Failed to update heartbeat error", "error", err)
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
		http.Error(w, `{"error": "invalid JSON"}`, http.StatusBadRequest)
		return
	}

	accepted := 0
	skipped := 0

	for _, ev := range input.Events {
		if valid, reason := ev.Validate(); !valid {
			runiclog.Warn("Skipping invalid log event", "reason", reason)
			skipped++
			continue
		}

		_, err := h.DB.ExecContext(r.Context(), `INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, serverID, ev.Timestamp, ev.Direction, ev.SrcIP, ev.DstIP, ev.Protocol, ev.SrcPort, ev.DstPort, ev.Action, ev.RawLine)
		if err != nil {
			runiclog.Error("Failed to insert log event", "error", err)
			skipped++
			continue
		}
		accepted++

		// Fan out to WebSocket clients
		event := models.LogEvent{
			PeerID:   fmt.Sprintf("%d", serverID),
			Action:   ev.Action,
			SrcIP:    ev.SrcIP,
			DstIP:    ev.DstIP,
			Protocol: ev.Protocol,
		}
		if hub := LogHubFromContext(r.Context()); hub != nil {
			hub.Broadcast(event)
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
		http.Error(w, `{"error": "invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Update applied_at timestamp on the bundle
	appliedAt := input.AppliedAt
	if appliedAt == "" {
		appliedAt = time.Now().UTC().Format(time.RFC3339)
	}

	_, err := h.DB.ExecContext(r.Context(), `UPDATE rule_bundles SET applied_at = ? WHERE peer_id = ? AND version = ?`, appliedAt, serverID, input.Version)
	if err != nil {
		runiclog.Error("Failed to confirm bundle apply error", "error", err)
	}

	// Update peer's bundle_version
	if _, err := h.DB.ExecContext(r.Context(), "UPDATE peers SET bundle_version = ? WHERE id = ?", input.Version, serverID); err != nil {
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

		// Use the explicitly provided hub
		if hub == nil {
			http.Error(w, "SSE hub unavailable", http.StatusInternalServerError)
			return
		}
		ch := hub.Register(hostID)
		defer hub.Unregister(hostID)

		// Ensure flush
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}

		// Send keepalive periodically
		ticker := time.NewTicker(constants.SSEKeepaliveInterval)
		defer ticker.Stop()

		// Notify client connected
		fmt.Fprintf(w, ": agent connected\n\n")
		flusher.Flush()

		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					// Channel closed
					return
				}
				fmt.Fprintf(w, "%s\n\n", msg)
				flusher.Flush()

			case <-ticker.C:
				// Keepalive
				fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()

			case <-r.Context().Done():
				// Client disconnected
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
	var rotationToken sql.NullString
	err := h.DB.QueryRowContext(r.Context(),
		"SELECT hmac_key_rotation_token FROM peers WHERE id = ?",
		serverID,
	).Scan(&rotationToken)

	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}
	if err != nil {
		runiclog.Error("Failed to check rotation token error", "error", err)
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	if !rotationToken.Valid || rotationToken.String == "" {
		// No rotation pending
		w.WriteHeader(http.StatusNoContent)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"rotation_token": rotationToken.String,
		"host_id":        hostID,
	})
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
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Get peer's current HMAC key
	var hmacKey string
	err := h.DB.QueryRowContext(r.Context(),
		"SELECT hmac_key FROM peers WHERE id = ?",
		serverID,
	).Scan(&hmacKey)

	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}
	if err != nil {
		runiclog.Error("Failed to get HMAC key error", "error", err)
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(input.Message))
	expected := hex.EncodeToString(mac.Sum(nil))

	if input.Signature != expected {
		common.RespondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
