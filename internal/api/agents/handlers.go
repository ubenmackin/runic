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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"runic/internal/alerts"
	"runic/internal/api/common"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
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

var validProtocols = []string{"tcp", "udp", "icmp", "icmpv6", "sctp", "dccp", "udplite", "esp", "ah", "gre", "igmp"}

// maxRawLineBytes caps the stored raw log line at 4KB to bound DB row size.
const maxRawLineBytes = 4096

// maxLogEventsPerRequest caps the number of log events accepted per SubmitLogs
// request so a single 1MB body cannot trigger unbounded inserts and broadcasts.
const maxLogEventsPerRequest = 1000

// maxVersionLen caps version strings (agent version, bundle version) stored
// directly in the peers table.
const maxVersionLen = 255

// maxLoggedIPLen caps the length of an IP value included in log fields so a
// malformed 1MB string cannot bloat logs.
const maxLoggedIPLen = 64

// maxLoggedReasonLen caps the length of a validation reason included in log
// fields so unbounded input cannot bloat logs.
const maxLoggedReasonLen = 256

// truncateForLog bounds a value included in structured log fields. It returns
// s unchanged when it fits, otherwise the first maxLen bytes.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// validateAllIPs rejects the request when any entry fails to parse as an IP
// address. The first invalid entry is reported with a truncated value so the
// response and logs stay bounded. Callers map the returned error to 400.
func validateAllIPs(ips []string) error {
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP address in all_ips: %q", truncateForLog(ip, maxLoggedIPLen))
		}
	}
	return nil
}

// Validate validates the LogEvent. Empty optional fields are allowed, but if present they must be valid.
// Returns (true, "") if valid, or (false, reason) if invalid.
func (e *LogEvent) Validate() (bool, string) {
	if e.Timestamp != "" && !isValidLogTimestamp(e.Timestamp) {
		return false, fmt.Sprintf("invalid timestamp: %s", e.Timestamp)
	}
	if e.SrcIP != "" && net.ParseIP(e.SrcIP) == nil {
		return false, fmt.Sprintf("invalid src_ip: %s", e.SrcIP)
	}
	if e.DstIP != "" && net.ParseIP(e.DstIP) == nil {
		return false, fmt.Sprintf("invalid dst_ip: %s", e.DstIP)
	}
	if e.Protocol != "" && !slices.Contains(validProtocols, strings.ToLower(e.Protocol)) {
		return false, fmt.Sprintf("invalid protocol: %s", e.Protocol)
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
	if len(e.RawLine) > maxRawLineBytes {
		return false, fmt.Sprintf("raw_line too large: %d bytes (max %d)", len(e.RawLine), maxRawLineBytes)
	}
	return true, ""
}

// isValidLogTimestamp reports whether ts parses as RFC3339 (with or without
// fractional seconds), a SQLite datetime ("2006-01-02 15:04:05"), or a
// date-only value ("2006-01-02").
func isValidLogTimestamp(ts string) bool {
	if _, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return true
	}
	if _, err := time.Parse(time.RFC3339, ts); err == nil {
		return true
	}
	if _, err := time.Parse("2006-01-02 15:04:05", ts); err == nil {
		return true
	}
	if _, err := time.Parse("2006-01-02", ts); err == nil {
		return true
	}
	return false
}

// filterValidIPs returns only the entries that parse as IP addresses, logging
// and skipping invalid values so a single malformed entry cannot poison the
// peer_ips table. Callers must run validateAllIPs first when the blueprint
// requires a 400 on invalid entries; this filter remains as a best-effort
// backstop. Logged values are truncated to keep logs bounded.
func filterValidIPs(ips []string) []string {
	valid := make([]string, 0, len(ips))
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			runiclog.Warn("Skipping invalid peer IP", "ip", truncateForLog(ip, maxLoggedIPLen))
			continue
		}
		valid = append(valid, ip)
	}
	return valid
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
		tokenString := auth.ExtractBearerToken(authHeader)
		if tokenString == "" {
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		if h.DashboardStore == nil {
			runiclog.Error("JWT secret store unavailable")
			common.InternalError(w)
			return
		}

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

		// Check token revocation via jti (unique token ID). Fail closed to match
		// the convention in internal/auth/auth.go:IsRevoked and
		// internal/api/logs/handlers.go:65: a missing jti, a missing store,
		// or a lookup error must reject the request rather than skip the check.
		jti, ok := claims["jti"].(string)
		if !ok || jti == "" || h.TokenStore == nil {
			runiclog.Error("agent token missing revocation identifier or token store unavailable")
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		revCtx, cancel := context.WithTimeout(r.Context(), constants.RevocationCheckTimeout)
		defer cancel()
		revoked, checkErr := h.TokenStore.IsTokenRevoked(revCtx, jti)
		if checkErr != nil {
			runiclog.Error("failed to check token revocation", "error", checkErr)
			common.RespondError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if revoked {
			common.RespondError(w, http.StatusUnauthorized, "token has been revoked")
			return
		}

		// Use typed context key to prevent collisions
		ctx := context.WithValue(r.Context(), hostIDKey, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func (h *Handler) registerNewPeer(ctx context.Context, input *models.AgentRegisterRequest, w http.ResponseWriter) (int, string, string, error) {
	if input.RegistrationToken == "" {
		return 0, "", "", common.NewHTTPError(http.StatusUnauthorized, "registration token required")
	}

	if err := validateAllIPs(input.AllIPs); err != nil {
		return 0, "", "", common.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	consumed, err := h.ConsumeRegistrationToken(ctx, input.RegistrationToken, input.Hostname)
	if err != nil {
		return 0, "", "", fmt.Errorf("consume token: %w", err)
	}
	if !consumed {
		return 0, "", "", common.NewHTTPError(http.StatusUnauthorized, "invalid registration token")
	}

	hmacKey, err := GenerateHMACKey()
	if err != nil {
		return 0, "", "", fmt.Errorf("generate HMAC key: %w", err)
	}
	agentToken, err := generateAgentToken(ctx, h.DashboardStore, input.Hostname)
	if err != nil {
		return 0, "", "", fmt.Errorf("generate agent token: %w", err)
	}
	agentKey, err := generateAgentKey()
	if err != nil {
		return 0, "", "", fmt.Errorf("generate agent key: %w", err)
	}

	peerID, err := h.PeerStore.RegisterPeer(ctx, input.Hostname, input.IP, input.OSType, input.Arch, input.HasDocker, input.HasIPSet, agentKey, agentToken, hmacKey)
	if err != nil {
		return 0, "", "", fmt.Errorf("register peer: %w", err)
	}

	if len(input.AllIPs) > 0 {
		if validIPs := filterValidIPs(input.AllIPs); len(validIPs) > 0 {
			if err := h.PeerStore.UpsertPeerIPs(ctx, int(peerID), validIPs, input.IP); err != nil {
				runiclog.Warn("Failed to upsert peer IPs during registration", "error", err, "peer_id", peerID)
			}
		}
	}

	return int(peerID), agentToken, hmacKey, nil
}

func (h *Handler) reRegisterExistingPeer(ctx context.Context, input *models.AgentRegisterRequest, existingID int) (string, string, error) {
	if err := validateAllIPs(input.AllIPs); err != nil {
		return "", "", common.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	newToken, err := generateAgentToken(ctx, h.DashboardStore, input.Hostname)
	if err != nil {
		return "", "", fmt.Errorf("generate agent token: %w", err)
	}

	existingHMACKey, err := h.PeerStore.GetPeerHMACKey(ctx, existingID)
	if err != nil {
		return "", "", fmt.Errorf("fetch existing HMAC key: %w", err)
	}

	if err := h.PeerStore.UpdatePeerReRegistration(ctx, existingID, newToken, input.AgentVersion, input.HasDocker, input.HasIPSet); err != nil {
		return "", "", fmt.Errorf("update peer re-registration: %w", err)
	}

	if len(input.AllIPs) > 0 {
		if validIPs := filterValidIPs(input.AllIPs); len(validIPs) > 0 {
			if err := h.PeerStore.UpsertPeerIPs(ctx, existingID, validIPs, input.IP); err != nil {
				runiclog.Warn("Failed to upsert peer IPs during re-registration", "error", err, "peer_id", existingID)
			}
		}
	}

	return newToken, existingHMACKey, nil
}

func (h *Handler) RegisterAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input models.AgentRegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			common.RespondError(w, http.StatusRequestEntityTooLarge, "request body too large")
			return
		}
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

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

	if input.IP != "" && net.ParseIP(input.IP) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	ctx := r.Context()

	existingID, _, err := h.PeerStore.FindPeerByHostname(ctx, input.Hostname)

	if errors.Is(err, sql.ErrNoRows) {
		_, agentToken, hmacKey, err := h.registerNewPeer(ctx, &input, w)
		if err != nil {
			var httpErr *common.HTTPError
			if errors.As(err, &httpErr) {
				common.RespondError(w, httpErr.StatusCode, httpErr.Message)
				return
			}
			runiclog.Error("Failed to register new peer", "error", err)
			common.InternalError(w)
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

		if h.AlertService != nil {
			safeHostname, _ := alerts.SanitizeAlertInput(input.Hostname, 0)
			if peerID, getPeerErr := h.PeerStore.GetPeerIDByHostname(ctx, input.Hostname); getPeerErr == nil {
				if err := h.AlertService.TriggerAlert(ctx, &alerts.AlertEvent{
					Type:     alerts.AlertTypeNewPeer,
					PeerID:   peerID,
					PeerName: safeHostname,
					Subject:  fmt.Sprintf("New Peer Registered: %s", safeHostname),
					Metadata: map[string]interface{}{
						"hostname":      safeHostname,
						"ip_address":    input.IP,
						"os_type":       input.OSType,
						"agent_version": input.AgentVersion,
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

	newToken, existingHMACKey, err := h.reRegisterExistingPeer(ctx, &input, existingID)
	if err != nil {
		var httpErr *common.HTTPError
		if errors.As(err, &httpErr) {
			common.RespondError(w, httpErr.StatusCode, httpErr.Message)
			return
		}
		runiclog.Error("Failed to re-register existing peer", "error", err)
		common.InternalError(w)
		return
	}

	hostID := fmt.Sprintf("host-%s", input.Hostname)
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

	// Limit request body size to prevent slowloris attacks
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		BundleVersionApplied string   `json:"bundle_version_applied"`
		UptimeSeconds        float64  `json:"uptime_seconds"`
		Load1m               float64  `json:"load_1m"`
		AgentVersion         string   `json:"agent_version"`
		HasIPSet             *bool    `json:"has_ipset"`
		AllIPs               []string `json:"all_ips"`
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

	if len(input.AgentVersion) > maxVersionLen {
		common.RespondError(w, http.StatusBadRequest, fmt.Sprintf("agent_version too large: %d bytes (max %d)", len(input.AgentVersion), maxVersionLen))
		return
	}
	if len(input.BundleVersionApplied) > maxVersionLen {
		common.RespondError(w, http.StatusBadRequest, fmt.Sprintf("bundle_version_applied too large: %d bytes (max %d)", len(input.BundleVersionApplied), maxVersionLen))
		return
	}
	if err := validateAllIPs(input.AllIPs); err != nil {
		common.RespondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Best-effort: record the heartbeat and capture the previously stored
	// agent version in a single transaction so concurrent heartbeats cannot
	// interleave a separate pre-read and update (TOCTOU). Failures here must
	// not fail the heartbeat itself.
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	prevHostname := ""
	prevVersion := ""
	prevKnown := false
	var heartbeatErr error
	if hostname, ver, known, err := h.PeerStore.UpdatePeerHeartbeatWithPrev(ctx, serverID, input.AgentVersion, input.BundleVersionApplied, input.HasIPSet); err != nil {
		heartbeatErr = err
		runiclog.Error("Failed to update heartbeat error", "error", heartbeatErr)
	} else {
		prevHostname = hostname
		if ver.Valid {
			prevVersion = ver.String
		}
		prevKnown = known
	}

	// Record agent version changes only (no duplicate spam): when the
	// reported version is non-empty, differs from the stored value, and both
	// the pre-read and the heartbeat update succeeded.
	// alert_history is intentionally untouched.
	if prevKnown && heartbeatErr == nil && input.AgentVersion != "" && input.AgentVersion != prevVersion && h.DashboardStore != nil {
		detail := fmt.Sprintf("agent version changed from %q to %q", prevVersion, input.AgentVersion)
		if prevVersion == "" {
			detail = fmt.Sprintf("agent version reported as %q", input.AgentVersion)
		}
		if err := h.DashboardStore.InsertAgentUpdateLog(ctx, fmt.Sprintf("%d", serverID), prevHostname, "agent", "", detail); err != nil {
			runiclog.Warn("Heartbeat: failed to insert agent version log", "error", err, "peer_id", serverID)
		}
	}

	if len(input.AllIPs) > 0 {
		if validIPs := filterValidIPs(input.AllIPs); len(validIPs) > 0 {
			if primaryIP, err := h.PeerStore.GetPeerPrimaryIP(ctx, serverID); err == nil {
				if _, err := h.PeerStore.SyncPeerIPs(ctx, serverID, validIPs, primaryIP); err != nil {
					runiclog.Warn("Failed to sync peer IPs during heartbeat", "error", err, "peer_id", serverID)
				}
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Events []LogEvent `json:"events"`
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

	if len(input.Events) > maxLogEventsPerRequest {
		common.RespondError(w, http.StatusBadRequest, fmt.Sprintf("too many events: %d (max %d)", len(input.Events), maxLogEventsPerRequest))
		return
	}

	// Bound the DB section so a stalled logs database cannot hold the
	// handler (and its 1MB body) open indefinitely.
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	peerHostname, err := h.PeerStore.GetPeerHostname(ctx, serverID)
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
			runiclog.Warn("Skipping invalid log event", "reason", truncateForLog(reason, maxLoggedReasonLen))
			skipped++
			continue
		}

		// Note: Logs DB schema uses different column names than main DB
		err := h.DashboardStore.InsertFirewallLog(ctx, &store.FirewallLogEntry{
			PeerID:       fmt.Sprintf("%d", serverID),
			PeerHostname: peerHostname,
			Timestamp:    ev.Timestamp,
			EventType:    ev.Direction,
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Version   string `json:"version"`
		AppliedAt string `json:"applied_at"`
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

	if strings.TrimSpace(input.Version) == "" {
		common.RespondError(w, http.StatusBadRequest, "version required")
		return
	}
	if len(input.Version) > maxVersionLen {
		common.RespondError(w, http.StatusBadRequest, fmt.Sprintf("version too large: %d bytes (max %d)", len(input.Version), maxVersionLen))
		return
	}

	appliedAt := input.AppliedAt
	if appliedAt == "" {
		appliedAt = time.Now().UTC().Format(time.RFC3339)
	}

	// Wrap both DB calls in a transaction to prevent partial state on crash
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()
	err := store.RunInTx(ctx, h.beginner, func(tx *sql.Tx) error {
		if err := h.PeerStore.UpdateBundleAppliedAtTx(ctx, tx, serverID, input.Version, appliedAt); err != nil {
			return fmt.Errorf("update bundle applied_at: %w", err)
		}
		if err := h.PeerStore.UpdatePeerBundleVersionTx(ctx, tx, serverID, input.Version); err != nil {
			return fmt.Errorf("update peer bundle version: %w", err)
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

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit (iptables backup can be large)

	var input struct {
		IPTablesBackup string `json:"iptables_backup"`
		IPSetList      string `json:"ipset_list"`
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

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Message   string `json:"message"`
		Signature string `json:"signature"`
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
