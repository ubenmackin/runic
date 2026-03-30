package agents

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

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
func AgentAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) <= 7 || authHeader[:7] != "Bearer " {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]

		// Parse token
		secret, err := requireEnv("RUNIC_AGENT_JWT_SECRET")
		if err != nil {
			runiclog.Error("JWT secret not configured error", "error", err)
			http.Error(w, `{"error": "server misconfiguration"}`, http.StatusInternalServerError)
			return
		}

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

// respondJSON is a helper for JSON responses.
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// RegisterAgent handles agent registration.
func RegisterAgent(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Hostname     string `json:"hostname"`
		IP           string `json:"ip"`
		OSType       string `json:"os_type"`
		Arch         string `json:"arch"`
		Kernel       string `json:"kernel"`
		AgentVersion string `json:"agent_version"`
		HasDocker    bool   `json:"has_docker"`
	}

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
	err := db.DB.QueryRowContext(ctx, "SELECT id, agent_token FROM peers WHERE hostname = ?", input.Hostname).Scan(&existingID, &existingToken)

	if err == sql.ErrNoRows {
		// New server — create record
		hmacKey := GenerateHMACKey()
		agentToken, err := generateAgentToken(input.Hostname)
		if err != nil {
			runiclog.Error("Failed to generate agent token error", "error", err)
			http.Error(w, `{"error": "failed to generate agent token"}`, http.StatusInternalServerError)
			return
		}
		agentKey := generateAgentKey()

		_, err = db.DB.ExecContext(ctx, `INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, agent_token, hmac_key, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'online')`, input.Hostname, input.IP, input.OSType, input.Arch, input.HasDocker, agentKey, agentToken, hmacKey)
		if err != nil {
			runiclog.Error("Failed to create server error", "error", err)
			http.Error(w, `{"error": "failed to create server"}`, http.StatusInternalServerError)
			return
		}

		hostID := fmt.Sprintf("host-%s", input.Hostname)

		respondJSON(w, http.StatusCreated, map[string]interface{}{
			"host_id":                hostID,
			"token":                  agentToken,
			"pull_interval_seconds":  30,
			"current_bundle_version": "",
			"hmac_key":               hmacKey,
		})
		return
	} else if err != nil {
		runiclog.Error("Database error checking hostname error", "error", err)
		http.Error(w, `{"error": "database error"}`, http.StatusInternalServerError)
		return
	}

	// Existing server — re-issue token (agent reinstall scenario)
	hostID := fmt.Sprintf("host-%s", input.Hostname)
	if existingToken.Valid && existingToken.String != "" {
		// Token exists, return it along with existing server info
		var bundleVersion sql.NullString
		var existingHMACKey string
		db.DB.QueryRowContext(ctx, "SELECT bundle_version, hmac_key FROM peers WHERE id = ?", existingID).Scan(&bundleVersion, &existingHMACKey)

		respondJSON(w, http.StatusOK, map[string]interface{}{
			"host_id":                hostID,
			"token":                  existingToken.String,
			"pull_interval_seconds":  30,
			"current_bundle_version": bundleVersion.String,
			"hmac_key":               existingHMACKey,
		})
		return
	}

	// Generate new token for reinstall
	newToken, err := generateAgentToken(input.Hostname)
	if err != nil {
		runiclog.Error("Failed to generate agent token error", "error", err)
		http.Error(w, `{"error": "failed to generate agent token"}`, http.StatusInternalServerError)
		return
	}

	// Fetch existing HMAC key (don't regenerate on reinstall)
	var existingHMACKey string
	db.DB.QueryRowContext(ctx, "SELECT hmac_key FROM peers WHERE id = ?", existingID).Scan(&existingHMACKey)

	db.DB.ExecContext(ctx, "UPDATE peers SET agent_token = ?, status = 'online' WHERE id = ?", newToken, existingID)

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"host_id":                hostID,
		"token":                  newToken,
		"pull_interval_seconds":  30,
		"current_bundle_version": "",
		"hmac_key":               existingHMACKey,
	})
}

// GetBundle handles bundle download requests from agents.
func GetBundle(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	// Check If-None-Match header
	ifNoneMatch := r.Header.Get("If-None-Match")

	// Get latest bundle for this peer
	var bundle models.RuleBundleRow
	err := db.DB.QueryRowContext(r.Context(), `SELECT id, peer_id, version, rules_content, hmac, created_at FROM rule_bundles WHERE peer_id = ? ORDER BY created_at DESC LIMIT 1`, serverID).Scan(&bundle.ID, &bundle.PeerID, &bundle.Version, &bundle.RulesContent, &bundle.HMAC, &bundle.CreatedAt)

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

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"version": bundle.Version,
		"rules":   bundle.RulesContent,
		"hmac":    bundle.HMAC,
	})
}

// Heartbeat handles agent heartbeat requests.
func Heartbeat(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		BundleVersionApplied string  `json:"bundle_version_applied"`
		UptimeSeconds        float64 `json:"uptime_seconds"`
		Load1m               float64 `json:"load_1m"`
		AgentVersion         string  `json:"agent_version"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		runiclog.Error("Heartbeat: failed to decode body error", "error", err)
		// Continue anyway — agent_version and bundle_version may be empty
	}

	// Update peer heartbeat and status
	_, err := db.DB.ExecContext(r.Context(), `UPDATE peers SET last_heartbeat = CURRENT_TIMESTAMP, status = 'online', agent_version = ?, bundle_version = ? WHERE id = ?`, input.AgentVersion, input.BundleVersionApplied, serverID)
	if err != nil {
		runiclog.Error("Failed to update heartbeat error", "error", err)
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

// SubmitLogs handles log submissions from agents.
func SubmitLogs(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		Events []map[string]interface{} `json:"events"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, `{"error": "invalid JSON"}`, http.StatusBadRequest)
		return
	}

	// Insert log events (simplified — in production would batch insert)
	eventCount := 0
	for _, ev := range input.Events {
		// Extract fields
		timestamp, _ := ev["timestamp"].(string)
		direction, _ := ev["direction"].(string)
		srcIP, _ := ev["src_ip"].(string)
		dstIP, _ := ev["dst_ip"].(string)
		protocol, _ := ev["protocol"].(string)
		action, _ := ev["action"].(string)
		rawLine, _ := ev["raw_line"].(string)

		// Get port values if present
		srcPort := 0
		if spt, ok := ev["src_port"].(float64); ok {
			srcPort = int(spt)
		}
		dstPort := 0
		if dpt, ok := ev["dst_port"].(float64); ok {
			dstPort = int(dpt)
		}

		_, err := db.DB.ExecContext(r.Context(), `INSERT INTO firewall_logs (peer_id, timestamp, direction, src_ip, dst_ip, protocol, src_port, dst_port, action, raw_line) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, serverID, timestamp, direction, srcIP, dstIP, protocol, srcPort, dstPort, action, rawLine)
		if err == nil {
			eventCount++
		}
	}

	// Fan out to WebSocket clients
	for _, ev := range input.Events {
		if ev["action"] == nil {
			continue
		}
		action, ok := ev["action"].(string)
		if !ok {
			continue
		}
		event := models.LogEvent{
			PeerID: fmt.Sprintf("%d", serverID),
			Action: action,
		}
		if v, ok := ev["src_ip"].(string); ok {
			event.SrcIP = v
		}
		if v, ok := ev["dst_ip"].(string); ok {
			event.DstIP = v
		}
		if v, ok := ev["protocol"].(string); ok {
			event.Protocol = v
		}
		if hostname, ok := ev["hostname"].(string); ok {
			event.Hostname = hostname
		}
		if hub := LogHubFromContext(r.Context()); hub != nil {
			hub.Broadcast(event)
		}
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"accepted": eventCount,
	})
}

// ConfirmBundleApplied handles confirmation that a bundle was applied.
func ConfirmBundleApplied(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := getHostIDFromContext(w, r)
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

	_, err := db.DB.ExecContext(r.Context(), `UPDATE rule_bundles SET applied_at = ? WHERE peer_id = ? AND version = ?`, appliedAt, serverID, input.Version)
	if err != nil {
		runiclog.Error("Failed to confirm bundle apply error", "error", err)
	}

	// Update peer's bundle_version
	db.DB.ExecContext(r.Context(), "UPDATE peers SET bundle_version = ? WHERE id = ?", input.Version, serverID)

	respondJSON(w, http.StatusOK, map[string]string{"status": "confirmed"})
}

// HandleSSEvents handles SSE connections for agents.
// Deprecated: Use MakeHandleSSEventsHandler for explicit dependency injection.
func HandleSSEvents(w http.ResponseWriter, r *http.Request) {
	hostID, _, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Transfer-Encoding", "chunked")

	// Register with SSE hub
	hub := SSEHubFromContext(r.Context())
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

// MakeHandleSSEventsHandler creates an SSE handler with explicit SSE hub injection.
// This is the preferred way to create the SSE handler as it avoids context propagation issues.
func MakeHandleSSEventsHandler(hub SSEBroadcaster) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hostID, _, ok := getHostIDFromContext(w, r)
		if !ok {
			runiclog.Error("HandleSSEvents: failed to get host_id from context")
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
		fmt.Fprintf(w, ": agent connected\\n\\n")
		flusher.Flush()

		for {
			select {
			case msg, ok := <-ch:
				if !ok {
					// Channel closed
					return
				}
				fmt.Fprintf(w, "%s\\n\\n", msg)
				flusher.Flush()

			case <-ticker.C:
				// Keepalive
				fmt.Fprintf(w, ": keepalive\\n\\n")
				flusher.Flush()

			case <-r.Context().Done():
				// Client disconnected
				return
			}
		}
	}
}

// AgentCheckRotation checks if a rotation is pending for the agent.
func AgentCheckRotation(w http.ResponseWriter, r *http.Request) {
	hostID, serverID, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	// Check if there's a pending rotation token
	var rotationToken sql.NullString
	err := db.DB.QueryRowContext(r.Context(),
		"SELECT hmac_key_rotation_token FROM peers WHERE id = ?",
		serverID,
	).Scan(&rotationToken)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}
	if err != nil {
		runiclog.Error("Failed to check rotation token error", "error", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	if !rotationToken.Valid || rotationToken.String == "" {
		// No rotation pending
		w.WriteHeader(http.StatusNoContent)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"rotation_token": rotationToken.String,
		"host_id":        hostID,
	})
}

// AgentTestKey validates an HMAC signature using the peer's current key.
// POST /api/v1/agent/test-key (requires agent JWT auth)
func AgentTestKey(w http.ResponseWriter, r *http.Request) {
	_, serverID, ok := getHostIDFromContext(w, r)
	if !ok {
		return
	}

	var input struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		respondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	// Get peer's current HMAC key
	var hmacKey string
	err := db.DB.QueryRowContext(r.Context(),
		"SELECT hmac_key FROM peers WHERE id = ?",
		serverID,
	).Scan(&hmacKey)

	if err == sql.ErrNoRows {
		respondJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}
	if err != nil {
		runiclog.Error("Failed to get HMAC key error", "error", err)
		respondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	// Verify HMAC signature
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(input.Message))
	expected := hex.EncodeToString(mac.Sum(nil))

	if input.Signature != expected {
		respondJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid signature"})
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}
