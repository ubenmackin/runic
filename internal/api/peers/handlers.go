// Package peers provides API peers handlers.
package peers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"runic/internal/agent/transport"
	"runic/internal/alerts"
	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/api/downloads"
	"runic/internal/api/events"
	"runic/internal/auth"
	runiccommon "runic/internal/common"
	sharedarch "runic/internal/common/arch"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/common/version"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/store"
)

// SettingsStore is defined as an interface here for testability.
type SettingsStore interface {
	GetSystemConfig(ctx context.Context, key string) (string, error)
}

type Handler struct {
	Store          *store.PeerStore
	beginner       db.Beginner
	Compiler       *engine.Compiler
	SSEHub         events.NotifyUpdateAgenter
	SettingsStore  SettingsStore
	DashboardStore *store.DashboardStore
	// PendingStore is optional and enables push-job audit rows for bulk
	// fan-out (UpdateAllAgents). When nil, the fan-out still runs but no
	// job record is created. Set post-construction like DashboardStore.
	PendingStore *store.PendingStore
	// AlertService is optional and records agent-update activity in
	// alert_history via TriggerAlert. When nil, update requests still
	// succeed but no alert history is recorded. Set post-construction
	// like DashboardStore.
	AlertService *alerts.Service
	// DownloadsDir is the staged agent-binary directory served by
	// /downloads. UpdateAgent and UpdateAllAgents verify all required
	// arch binaries are present before reporting sent; a stale dir yields
	// failed_validation instead of a dishonest sent. An empty dir is
	// fail-closed (treated as all-missing) so a miswired deploy cannot
	// report sent. Set by API.RegisterRoutes from the downloadsDir arg.
	DownloadsDir string
}

func NewHandler(peerStore *store.PeerStore, beginner db.Beginner, compiler *engine.Compiler, sseHub events.NotifyUpdateAgenter, settingsStore SettingsStore) *Handler {
	return &Handler{Store: peerStore, beginner: beginner, Compiler: compiler, SSEHub: sseHub, SettingsStore: settingsStore}
}

var validOSTypes = []string{
	"debian", "ubuntu", "rhel", "arch", "opensuse", "raspbian", "linux",
	"armbian", "ios", "ipados", "macos", "tvos", "windows", "other",
}

// validArchs aliases the canonical peer arch set in internal/common/arch
// (shared with the agent updater and the /downloads freshness check) so
// peer validation can never drift from what the updater can serve.
var validArchs = sharedarch.ValidPeerArchs

type peerByIPResponse struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	IsManual  bool   `json:"is_manual"`
}

func (h *Handler) GetPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := h.Store.ListPeers(r.Context())
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peers")
		return
	}

	common.RespondJSON(w, http.StatusOK, peers)
}

func (h *Handler) GetPeer(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	peer, err := h.Store.GetPeerByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	common.RespondJSON(w, http.StatusOK, peer)
}

func (h *Handler) CreatePeer(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		OSType    string `json:"os_type"`
		Arch      string `json:"arch"`
		AgentKey  string `json:"agent_key"`
		HasDocker bool   `json:"has_docker"`
		IsManual  bool   `json:"is_manual"`
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

	if err := common.ValidateHostname(input.Hostname); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid hostname")
		return
	}

	if net.ParseIP(input.IPAddress) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	if input.OSType != "" && !slices.Contains(validOSTypes, input.OSType) {
		common.RespondError(w, http.StatusBadRequest, "os_type must be one of: "+strings.Join(validOSTypes, ", "))
		return
	}

	if input.Arch != "" && !slices.Contains(validArchs, input.Arch) {
		common.RespondError(w, http.StatusBadRequest, "arch must be one of: "+strings.Join(validArchs, ", "))
		return
	}

	if !input.IsManual && input.AgentKey == "" {
		common.RespondError(w, http.StatusBadRequest, "agent_key is required for agent peers")
		return
	}

	agentKey := input.AgentKey
	if input.IsManual && agentKey == "" {
		agentKey = "manual-" + input.Hostname + "-" + input.IPAddress
	}

	hmacKey, err := agents.GenerateHMACKey()
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to generate HMAC key")
		return
	}

	id, err := h.Store.CreatePeer(r.Context(), input.Hostname, input.IPAddress, input.OSType, input.Arch, agentKey, hmacKey, input.HasDocker, input.IsManual)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to create peer", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		Hostname    string `json:"hostname"`
		IPAddress   string `json:"ip_address"`
		OSType      string `json:"os_type"`
		Arch        string `json:"arch"`
		HasDocker   *bool  `json:"has_docker"`
		Description string `json:"description"`
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

	if input.Hostname != "" {
		if err := common.ValidateHostname(input.Hostname); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	if input.IPAddress != "" {
		if err := common.ValidateIPAddress(input.IPAddress); err != nil {
			common.RespondError(w, http.StatusBadRequest, err.Error())
			return
		}
	}

	peer, err := h.Store.GetPeerByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}
	if !peer.IsManual {
		common.RespondError(w, http.StatusBadRequest, "can only edit manual peers")
		return
	}

	hasDocker := peer.HasDocker
	if input.HasDocker != nil {
		hasDocker = *input.HasDocker
	}

	err = h.Store.UpdatePeer(r.Context(), id, input.Hostname, input.IPAddress, input.OSType, input.Arch, hasDocker, input.Description)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to update peer", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "peer updated"})
}

func (h *Handler) CompilePeer(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	if h.Compiler == nil {
		log.ErrorContext(r.Context(), "compiler not initialized")
		common.RespondError(w, http.StatusInternalServerError, "compiler not available")
		return
	}

	bundle, err := h.Compiler.CompileAndStore(r.Context(), id)
	if err != nil {
		log.ErrorContext(r.Context(), "compilation failed", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"version": bundle.Version,
		"hmac":    bundle.HMAC,
		"size":    len(bundle.RulesContent),
	})
}

func (h *Handler) DeletePeer(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	err = h.Store.CheckDeleteConstraints(r.Context(), peerID)
	if err != nil {
		constraintErr, ok := err.(*common.DeleteConstraintError)
		if ok {
			common.RespondJSON(w, http.StatusConflict, constraintErr.ToResponse())
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to check constraints")
		return
	}

	err = h.Store.DeletePeer(r.Context(), peerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "Peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "Failed to delete peer")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetPeerBundle returns the compiled bundle for a peer.
// Supports include_pending query parameter:
// - include_pending=true: Returns the latest bundle (what's been compiled/applied but not necessarily synced)
// - include_pending=false or not provided: Returns the deployed bundle matching peers.bundle_version
func (h *Handler) GetPeerBundle(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	includePending := r.URL.Query().Get("include_pending") == "true"

	if includePending {
		pendingData, deployedData, version, hmac, deployedVersion, versionNumber, err := h.Store.GetPeerBundleWithDeployed(r.Context(), id)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				log.WarnContext(r.Context(), "no bundle found", "peer_id", id, "include_pending", includePending)
				common.RespondError(w, http.StatusNotFound, "bundle not found")
				return
			}
			log.ErrorContext(r.Context(), "failed to get bundle", "error", err)
			common.InternalError(w)
			return
		}

		response := map[string]interface{}{
			"rules":          pendingData,
			"version":        version,
			"version_number": versionNumber,
			"hmac":           hmac,
		}
		if deployedData != "" {
			response["deployed_rules"] = deployedData
			response["deployed_version"] = deployedVersion
		}
		common.RespondJSON(w, http.StatusOK, response)
		return
	}

	// Deployed bundle mode — single call, no double-query
	bundleData, version, versionNumber, hmac, _, err := h.Store.GetPeerBundle(r.Context(), id, false)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.WarnContext(r.Context(), "no bundle found", "peer_id", id, "include_pending", includePending)
			common.RespondError(w, http.StatusNotFound, "bundle not found")
			return
		}
		log.ErrorContext(r.Context(), "failed to get bundle", "error", err)
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"rules":          bundleData,
		"version":        version,
		"version_number": versionNumber,
		"hmac":           hmac,
	})
}

func (h *Handler) GetPeerByIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		common.RespondError(w, http.StatusBadRequest, "ip parameter required")
		return
	}

	peer, err := h.Store.GetPeerByIP(r.Context(), ip)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, peerByIPResponse{
		ID:        peer.ID,
		Hostname:  peer.Hostname,
		IPAddress: peer.IPAddress,
		IsManual:  peer.IsManual,
	})
}

func (h *Handler) GetPeerByHostname(w http.ResponseWriter, r *http.Request) {
	hostname := r.URL.Query().Get("hostname")
	if hostname == "" {
		common.RespondError(w, http.StatusBadRequest, "hostname parameter required")
		return
	}

	peer, err := h.Store.GetPeerByHostname(r.Context(), hostname)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.InternalError(w)
		return
	}

	common.RespondJSON(w, http.StatusOK, peerByIPResponse{
		ID:        peer.ID,
		Hostname:  peer.Hostname,
		IPAddress: peer.IPAddress,
		IsManual:  peer.IsManual,
	})
}

func (h *Handler) GetPeerIPs(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	// ListPeerIPs returns an empty slice for non-existent peers — no need for
	// a separate existence check.
	peerIPs, err := h.Store.ListPeerIPs(r.Context(), id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IPs")
		return
	}

	common.RespondJSON(w, http.StatusOK, peerIPs)
}

// AddPeerIP adds an IP address to a peer. POST /api/v1/peers/{id}/ips
func (h *Handler) AddPeerIP(w http.ResponseWriter, r *http.Request) {
	id, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var input struct {
		IPAddress string `json:"ip_address"`
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

	if net.ParseIP(input.IPAddress) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	// Single query: ListPeerIPs handles both existence verification (empty = no peer)
	// and duplicate IP detection.
	existingIPs, err := h.Store.ListPeerIPs(r.Context(), id)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check duplicate IP")
		return
	}
	for _, existing := range existingIPs {
		if existing.IPAddress == input.IPAddress {
			common.RespondError(w, http.StatusConflict, "IP address already exists for this peer")
			return
		}
	}

	err = h.Store.AddPeerIP(r.Context(), id, input.IPAddress, false)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to add peer IP", "error", err)
		common.InternalError(w)
		return
	}

	// Return the known inserted data directly instead of re-querying.
	common.RespondJSON(w, http.StatusCreated, store.PeerIPView{
		PeerID:    id,
		IPAddress: input.IPAddress,
		IsPrimary: false,
	})
}

func (h *Handler) DeletePeerIP(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}

	ipID, err := common.ParseIDParam(r, "ip_id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP ID")
		return
	}

	ip, err := h.Store.GetPeerIP(r.Context(), ipID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer IP not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IP")
		return
	}

	if ip.PeerID != peerID {
		common.RespondError(w, http.StatusNotFound, "peer IP not found for this peer")
		return
	}

	if ip.IsPrimary {
		common.RespondError(w, http.StatusBadRequest, "cannot delete primary IP address")
		return
	}

	if err := h.Store.DeletePeerIPIfOrphan(r.Context(), ipID, peerID, ip.IPAddress); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusConflict, "cannot delete IP: referenced by one or more policies")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to delete peer IP")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// updateAllStaggerDelay spaces bulk SSE notifications so a 21-wide fan-out
// does not hit /downloads as a single burst. Only peers that actually need
// the update are notified (up-to-date peers are skipped via agent_version),
// and each successful notify sleeps this delay before the next send. The
// agent download path already retries 429/5xx with backoff honoring
// Retry-After, so the stagger plus the raised download limiter (60/min)
// keeps the burst under the ceiling while staying well inside the handler
// timeout (21 * 50ms ~= 1s).
const updateAllStaggerDelay = 50 * time.Millisecond

// isAgentUpToDate reports whether a heartbeat agent_version already matches
// the server's latest_agent_version. Empty, unknown, or dev builds never
// count as up-to-date so the fan-out fails open and notifies.
func isAgentUpToDate(agentVersion, latest string) bool {
	agentVersion = strings.TrimSpace(agentVersion)
	latest = strings.TrimSpace(latest)
	if agentVersion == "" || latest == "" {
		return false
	}
	if latest == "dev" {
		return false
	}
	return agentVersion == latest
}

// isUpdateEligibleArch reports whether a peer arch can self-update. Empty
// arch fails open (unknown legacy peer, notify) so only an explicit
// unsupported arch (armv6, other, or any value outside the canonical
// updater set) is ineligible.
func isUpdateEligibleArch(peerArch string) bool {
	if strings.TrimSpace(peerArch) == "" {
		return true
	}
	return sharedarch.IsUpdateSupportedArch(peerArch)
}

// unsupportedArchReason describes why a peer arch cannot self-update. The
// canonical supported set lives in internal/common/arch.
func unsupportedArchReason(peerArch string) string {
	return fmt.Sprintf("unsupported architecture %q: no agent binary servable (supported: %s)", peerArch, strings.Join(sharedarch.UpdateArchs, ", "))
}

// hasMoreSendCandidates reports whether any peer after index i still needs
// an update notification (not already up-to-date and arch-eligible). Used
// to avoid a needless stagger sleep when a sent peer is followed only by
// trailing skips or unsupported-arch peers that will never send.
func hasMoreSendCandidates(allPeers []store.PeerView, i int, latest string) bool {
	for j := i + 1; j < len(allPeers); j++ {
		if isAgentUpToDate(allPeers[j].AgentVersion, latest) {
			continue
		}
		if !isUpdateEligibleArch(allPeers[j].Arch) {
			continue
		}
		return true
	}
	return false
}

// stagedBinariesMissing returns the required agent binaries absent from the
// staged downloads dir, or nil when everything is staged. An empty dir is
// fail-closed (MissingBinaries reports all-missing) so a miswired empty
// dir never reports sent dishonestly.
func (h *Handler) stagedBinariesMissing() []string {
	if h == nil {
		return nil
	}
	return downloads.MissingBinaries(h.DownloadsDir)
}

// recordUpdateAllPeerOutcome maps the rich fan-out outcome to the
// push_job_peers CHECK-constrained status so audit rows keep working:
// sent -> notified, not_connected/channel_full/failed_validation/canceled
// -> failed with the reason preserved in error_message.
// skipped_up_to_date stays pending
// with the skip reason in error_message: the CHECK has no skipped status
// and applied carries bundle-applied semantics, so skips are tracked
// separately in the response and excluded from succeeded counts rather
// than recorded as applied. Agent-update jobs use agent_-prefixed IDs so
// the bundle_failed evaluator (which ignores agent_ jobs) never counts
// not_connected/channel_full/failed_validation/canceled as bundle
// failures. Failures to write the audit row only warn.
func (h *Handler) recordUpdateAllPeerOutcome(ctx context.Context, jobID string, trackJob bool, peerID int, outcome, detail string) {
	if !trackJob {
		return
	}
	var status string
	switch outcome {
	case "sent":
		status = "notified"
		detail = ""
	case "skipped_up_to_date":
		status = "pending"
	case "not_connected", "channel_full", "failed_validation", "canceled":
		status = "failed"
	default:
		status = "failed"
	}
	if err := h.PendingStore.UpdatePushJobPeerStatus(ctx, jobID, peerID, status, detail); err != nil {
		log.WarnContext(ctx, "failed to update push job peer status", "error", err, "job_id", jobID, "peer_id", peerID)
	}
}

// UpdateAgent triggers a self-update for a peer's agent. POST /api/v1/peers/{id}/update-agent
//
// The status key is canonical with events.UpdateAgentOutcome.String():
// sent, not_connected, channel_full, skipped_up_to_date, failed_validation.
// Previous keys update_sent and agent_not_connected are deprecated aliases
// for sent and not_connected and are no longer returned.
func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	peer, err := h.Store.GetPeerByID(ctx, peerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "database error")
		return
	}
	if peer.IsManual {
		common.RespondError(w, http.StatusBadRequest, "cannot update a manual peer")
		return
	}

	instanceURL, err := h.SettingsStore.GetSystemConfig(ctx, "instance_url")
	if err != nil || instanceURL == "" {
		common.RespondError(w, http.StatusBadRequest, "instance URL not configured — set it in Settings to enable agent updates")
		return
	}
	// Version-skip first: an already-current peer needs no download, so a
	// stale downloads dir, unsupported arch, or malformed instance_url must
	// not turn an honest skip into failed_validation.
	if peer.AgentVersion.Valid && isAgentUpToDate(peer.AgentVersion.String, version.AgentVersion) {
		log.InfoContext(ctx, "UpdateAgent: peer already up to date, skipping notify", "peer_id", peerID, "hostname", peer.Hostname, "agent_version", peer.AgentVersion.String, "latest_agent_version", version.AgentVersion)
		common.RespondJSON(w, http.StatusOK, map[string]string{"status": "skipped_up_to_date", "hostname": peer.Hostname, "agent_version": peer.AgentVersion.String, "latest_agent_version": version.AgentVersion})
		return
	}
	// Per-peer arch gate: armv6/other peers have no servable self-update
	// binary (GOARCH never reports armv6, other is never servable), so
	// reporting sent would 404 on download. Empty arch fails open (unknown
	// legacy peer, notify) to preserve existing behavior.
	if !isUpdateEligibleArch(peer.Arch) {
		reason := unsupportedArchReason(peer.Arch)
		log.WarnContext(ctx, "UpdateAgent: unsupported peer arch, refusing to notify", "peer_id", peerID, "arch", peer.Arch, "reason", reason)
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"status": "failed_validation", "reason": reason})
		return
	}
	if err := transport.ValidateUpdateURLShape(instanceURL); err != nil {
		log.WarnContext(ctx, "UpdateAgent: invalid instance URL, refusing to notify", "instance_url", instanceURL, "peer_id", peerID, "reason", err.Error())
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"status": "failed_validation", "reason": err.Error()})
		return
	}
	if missing := h.stagedBinariesMissing(); len(missing) > 0 {
		log.WarnContext(ctx, "UpdateAgent: agent binaries missing from downloads dir, refusing to report sent", "peer_id", peerID, "missing", strings.Join(missing, ","), "downloads_dir", h.DownloadsDir)
		common.RespondJSON(w, http.StatusServiceUnavailable, map[string]interface{}{"status": "failed_validation", "reason": "agent binaries not staged: " + strings.Join(missing, ", ")})
		return
	}

	if h.SSEHub == nil {
		common.RespondError(w, http.StatusInternalServerError, "SSE hub not available")
		return
	}
	hostID := fmt.Sprintf("host-%s", peer.Hostname)
	switch h.SSEHub.NotifyUpdateAgent(hostID, instanceURL) {
	case events.UpdateAgentChannelFull:
		log.Debug("UpdateAgent: agent channel full (backpressure, retryable)", "host_id", hostID)
		common.RespondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": events.UpdateAgentChannelFull.String()})
		return
	case events.UpdateAgentSent:
		// Delivered below.
	default:
		log.Debug("UpdateAgent: agent not connected", "host_id", hostID)
		common.RespondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": events.UpdateAgentNotConnected.String()})
		return
	}
	// Alert on a detached bounded context so a handler deadline firing
	// after the SSE send cannot cancel the alert history write.
	alertCtx, alertCancel := context.WithTimeout(context.WithoutCancel(ctx), constants.UpdateFanoutAuditTimeout)
	h.triggerAgentUpdatedAlert(alertCtx, peerID, peer.Hostname, auth.UsernameFromContext(ctx), instanceURL, "single", "")
	alertCancel()
	log.InfoContext(ctx, "UpdateAgent: update sent via SSE", "host_id", hostID)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": events.UpdateAgentSent.String()})
}

// UpdateAllAgents triggers a self-update for all agent-based peers. POST /api/v1/peers/update-agents
//
// Bulk fan-out follows the pending-changes/push-all template: the run is
// recorded as a push job (CreatePushJob + CreatePushJobPeers) with per-peer
// outcomes and finalized with counts, so delivery is auditable and retryable
// via the existing push-job APIs. Unlike bundle pushes, agent self-updates
// are synchronous SSE notifications and must NOT be enqueued on the
// PushWorker: the worker compiles rule bundles and sends bundle-updated
// events, so enqueueing here would spuriously recompile and repush bundles
// to every peer. The job is therefore finalized inline once the fan-out
// completes, and the endpoint reports 200/status completed (never
// 202/queued, which is reserved for enqueued background jobs). The response
// keeps the delivery detail clients rely on (sent/not_connected/channel_full)
// alongside the push-all keys; job_id is only present when a push-job row
// was created.
//
// Wide-fleet safety: ListAgentBasedPeers already excludes manual peers. The
// fan-out stays inline SSE but spreads successful notifications by
// updateAllStaggerDelay so a 21-wide burst plus agent 429/5xx retries with
// backoff stays under the raised /downloads limiter (60/min, Retry-After
// honored agent-side). Peers already at latest_agent_version (heartbeat
// agent_version) are skipped without notifying and reported as
// skipped_up_to_date (skipped is an alias); malformed instance_url, a stale
// downloads dir, or an unsupported peer arch (armv6/other, which have no
// servable self-update binary) yields failed_validation instead of a
// dishonest sent. Only sent peers trigger agent_updated alerts, preserving
// alert semantics.
// A connected client whose SSE channel is full is reported as channel_full
// (retryable backpressure), never as not_connected. Push-job audit and alert
// writes run on a detached bounded context so a 5s handler deadline firing
// mid-fan-out cannot cancel them; peers never reached before the deadline
// are marked canceled (failed, not pending) so counts add up.
func (h *Handler) UpdateAllAgents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := runiccommon.WithHandlerTimeout(r.Context())
	defer cancel()

	allPeers, err := h.Store.ListAgentBasedPeers(ctx)
	if err != nil {
		log.ErrorContext(ctx, "failed to query agent-based peers", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query peers")
		return
	}

	if len(allPeers) == 0 {
		// total_peers is canonical; total is a deprecated alias kept for
		// backward compatibility. New outcome keys are always present (as
		// empty lists) so clients can rely on a stable schema.
		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"status":             "no_peers",
			"total_peers":        0,
			"total":              0,
			"sent":               0,
			"not_connected":      []string{},
			"channel_full":       []string{},
			"skipped":            []string{},
			"skipped_up_to_date": []string{},
			"failed_validation":  []string{},
			"canceled":           []string{},
		})
		return
	}

	instanceURL, err := h.SettingsStore.GetSystemConfig(ctx, "instance_url")
	if err != nil || instanceURL == "" {
		common.RespondError(w, http.StatusBadRequest, "instance URL not configured — set it in Settings to enable agent updates")
		return
	}

	if h.SSEHub == nil {
		common.RespondError(w, http.StatusInternalServerError, "SSE hub not available")
		return
	}

	initiatedBy := auth.UsernameFromContext(ctx)

	// Global pre-validation: a malformed instance_url or a stale downloads
	// dir must never be reported as sent. Both are fanned out as per-peer
	// failed_validation so the response stays honest and the push-job audit
	// records failures instead of phantom successes.
	var globalValidationErr error
	if err := transport.ValidateUpdateURLShape(instanceURL); err != nil {
		log.WarnContext(ctx, "UpdateAllAgents: invalid instance URL, reporting failed_validation", "instance_url", instanceURL, "reason", err.Error())
		globalValidationErr = err
	}
	if globalValidationErr == nil {
		if missing := h.stagedBinariesMissing(); len(missing) > 0 {
			log.WarnContext(ctx, "UpdateAllAgents: agent binaries missing from downloads dir, reporting failed_validation", "missing", strings.Join(missing, ","), "downloads_dir", h.DownloadsDir)
			globalValidationErr = fmt.Errorf("agent binaries not staged: %s", strings.Join(missing, ", "))
		}
	}

	latestAgentVersion := version.AgentVersion

	// Detached audit context: push-job peer-status writes and the final
	// finalize must complete even after the 5s handler deadline fires
	// mid-fan-out. Bounded so shutdown cannot hang indefinitely.
	auditCtx, auditCancel := context.WithTimeout(context.WithoutCancel(ctx), constants.UpdateFanoutAuditTimeout)
	defer auditCancel()

	// Open the audit job before fanning out, mirroring PushAllRules.
	// No job row exists when PendingStore is nil, so only mint a job ID
	// when the run will actually be tracked.
	trackJob := h.PendingStore != nil
	jobID := ""
	if trackJob {
		generatedID, genErr := common.GeneratePushJobID()
		if genErr != nil {
			log.ErrorContext(ctx, "failed to generate push job ID", "error", genErr)
			common.InternalError(w)
			return
		}
		// Agent-update runs reuse push_jobs for audit but must not pollute
		// bundle_failed: the evaluator ignores agent_-prefixed job IDs.
		jobID = "agent_" + strings.TrimPrefix(generatedID, "job_")
		if err := h.PendingStore.CreatePushJob(auditCtx, jobID, initiatedBy, len(allPeers)); err != nil {
			log.ErrorContext(ctx, "failed to create push job", "error", err)
			common.InternalError(w)
			return
		}
		peers := make([]struct {
			ID       int
			Hostname string
		}, len(allPeers))
		for i := range allPeers {
			peers[i] = struct {
				ID       int
				Hostname string
			}{ID: allPeers[i].ID, Hostname: allPeers[i].Hostname}
		}
		if err := h.PendingStore.CreatePushJobPeers(auditCtx, jobID, peers); err != nil {
			log.ErrorContext(ctx, "failed to create push job peers", "error", err)
			// The job row from CreatePushJob already exists — finalize it as
			// failed so no orphan 'pending' job is left behind for the
			// push-job SSE/poll APIs to surface.
			if ferr := h.PendingStore.FinalizePushJobWithCounts(auditCtx, jobID, 0, len(allPeers)); ferr != nil {
				log.WarnContext(ctx, "failed to finalize orphaned push job", "error", ferr, "job_id", jobID)
			}
			common.InternalError(w)
			return
		}
	}

	notConnected := []string{}
	channelFull := []string{}
	skippedUpToDate := []string{}
	failedValidation := []string{}
	canceled := []string{}
	sent := 0
	handled := make([]bool, len(allPeers))
	canceledFanout := false
fanout:
	for i := range allPeers {
		select {
		case <-ctx.Done():
			log.WarnContext(ctx, "UpdateAllAgents: context canceled, aborting fan-out", "sent", sent, "peer_index", i)
			canceledFanout = true
			break fanout
		default:
		}
		p := &allPeers[i]
		hostID := fmt.Sprintf("host-%s", p.Hostname)
		// Version-skip: ListAgentBasedPeers already carries the heartbeat
		// agent_version, so no per-peer lookup is needed. Skipped peers
		// need no download, so they skip even when the per-peer arch or
		// global validation (instance_url, staged binaries) would
		// otherwise fail. Empty versions fail open (notify).
		if isAgentUpToDate(p.AgentVersion, latestAgentVersion) {
			skippedUpToDate = append(skippedUpToDate, p.Hostname)
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "skipped_up_to_date", fmt.Sprintf("skipped: already up to date (%s)", p.AgentVersion))
			log.InfoContext(ctx, "UpdateAllAgents: peer already up to date, skipping notify", "host_id", hostID, "agent_version", p.AgentVersion, "latest_agent_version", latestAgentVersion)
			handled[i] = true
			continue
		}
		// Per-peer arch gate: armv6/other peers have no servable
		// self-update binary, so notifying would report sent then 404 on
		// download. Empty arch fails open (unknown legacy peer, notify).
		if !isUpdateEligibleArch(p.Arch) {
			reason := unsupportedArchReason(p.Arch)
			failedValidation = append(failedValidation, p.Hostname)
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "failed_validation", reason)
			log.WarnContext(ctx, "UpdateAllAgents: skipping notify due to unsupported arch", "host_id", hostID, "arch", p.Arch, "reason", reason)
			handled[i] = true
			continue
		}
		if globalValidationErr != nil {
			failedValidation = append(failedValidation, p.Hostname)
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "failed_validation", globalValidationErr.Error())
			log.WarnContext(ctx, "UpdateAllAgents: skipping notify due to failed validation", "host_id", hostID, "reason", globalValidationErr.Error())
			handled[i] = true
			continue
		}
		switch h.SSEHub.NotifyUpdateAgent(hostID, instanceURL) {
		case events.UpdateAgentSent:
			sent++
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "sent", "")
			// Alert on a fresh detached bounded context per peer so one
			// slow SMTP/DB write neither inherits the handler deadline
			// nor consumes the shared audit deadline.
			alertCtx, alertCancel := context.WithTimeout(context.WithoutCancel(ctx), constants.UpdateFanoutAuditTimeout)
			h.triggerAgentUpdatedAlert(alertCtx, p.ID, p.Hostname, initiatedBy, instanceURL, "update-all", jobID)
			alertCancel()
			log.InfoContext(ctx, "UpdateAllAgents: update sent via SSE", "host_id", hostID)
			handled[i] = true
			// Stagger only successful sends: skipped, unsupported-arch,
			// and not-connected peers download nothing, so only sent
			// peers pressure /downloads. Sleep only when more send
			// candidates remain and honor ctx cancellation while
			// staggering. The timer is stopped on cancellation so
			// repeated fan-outs cannot leak unreclaimable timers.
			if hasMoreSendCandidates(allPeers, i, latestAgentVersion) {
				stagger := time.NewTimer(updateAllStaggerDelay)
				select {
				case <-ctx.Done():
					stagger.Stop()
					log.WarnContext(ctx, "UpdateAllAgents: context canceled during stagger, aborting fan-out", "sent", sent, "host_id", hostID)
					canceledFanout = true
					break fanout
				case <-stagger.C:
				}
			}
		case events.UpdateAgentChannelFull:
			channelFull = append(channelFull, p.Hostname)
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "channel_full", "agent channel full (backpressure, retryable)")
			log.Debug("UpdateAllAgents: agent channel full (backpressure, retryable)", "host_id", hostID)
			handled[i] = true
		default:
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "not_connected", "agent not connected")
			log.Debug("UpdateAllAgents: agent not connected", "host_id", hostID)
			notConnected = append(notConnected, p.Hostname)
			handled[i] = true
		}
	}

	// On handler timeout, peers never reached must not stay pending on a
	// finalized job with no retry. Mark each unprocessed peer canceled
	// (failed, not pending) on the detached audit context so counts add up.
	if canceledFanout || ctx.Err() != nil {
		for i := range allPeers {
			if handled[i] {
				continue
			}
			p := &allPeers[i]
			canceled = append(canceled, p.Hostname)
			h.recordUpdateAllPeerOutcome(auditCtx, jobID, trackJob, p.ID, "canceled", "handler timeout before notify (canceled)")
			log.WarnContext(ctx, "UpdateAllAgents: marking unprocessed peer canceled on timeout", "host_id", fmt.Sprintf("host-%s", p.Hostname), "peer_id", p.ID)
		}
	}

	// Skipped peers are tracked separately in the response and stay pending
	// in the audit (never applied); only actual sends count as succeeded.
	// Channel-full, canceled, not-connected, and failed-validation all
	// count as failed so succeeded+failed+canceled bookkeeping matches the
	// non-skipped peers.
	succeeded := sent
	failed := len(notConnected) + len(failedValidation) + len(channelFull) + len(canceled)
	if trackJob {
		if err := h.PendingStore.FinalizePushJobWithCounts(auditCtx, jobID, succeeded, failed); err != nil {
			log.WarnContext(ctx, "failed to finalize push job", "error", err, "job_id", jobID)
		}
	}

	// The fan-out above already completed inline, so report it as completed
	// with 200. Only include job_id when a push-job row actually exists.
	// total_peers is canonical (matching push-all); total is a deprecated
	// alias kept for backward compatibility. skipped is an alias for
	// skipped_up_to_date; both are always present for schema stability.
	// channel_full and canceled are always present (as empty lists when no
	// backpressure or timeout occurred) so clients can rely on a stable
	// schema.
	if notConnected == nil {
		notConnected = []string{}
	}
	if channelFull == nil {
		channelFull = []string{}
	}
	if skippedUpToDate == nil {
		skippedUpToDate = []string{}
	}
	if failedValidation == nil {
		failedValidation = []string{}
	}
	if canceled == nil {
		canceled = []string{}
	}
	response := map[string]interface{}{
		"status":             "completed",
		"total_peers":        len(allPeers),
		"total":              len(allPeers),
		"sent":               sent,
		"not_connected":      notConnected,
		"channel_full":       channelFull,
		"skipped":            skippedUpToDate,
		"skipped_up_to_date": skippedUpToDate,
		"failed_validation":  failedValidation,
		"canceled":           canceled,
	}
	if trackJob {
		response["job_id"] = jobID
		log.InfoContext(ctx, "update-all agents completed", "job_id", jobID, "total", len(allPeers), "sent", sent, "skipped_up_to_date", len(skippedUpToDate), "not_connected", len(notConnected), "channel_full", len(channelFull), "failed_validation", len(failedValidation), "canceled", len(canceled), "initiated_by", initiatedBy)
	} else {
		log.InfoContext(ctx, "update-all agents completed", "total", len(allPeers), "sent", sent, "skipped_up_to_date", len(skippedUpToDate), "not_connected", len(notConnected), "channel_full", len(channelFull), "failed_validation", len(failedValidation), "canceled", len(canceled), "initiated_by", initiatedBy)
	}

	common.RespondJSON(w, http.StatusOK, response)
}

// triggerAgentUpdatedAlert records a delivered agent update as an alert.
// It is best-effort: a nil AlertService skips silently, and trigger failures
// only log a warning so the update request itself never fails. When no enabled
// agent_updated rule exists the alert pipeline records no history.
func (h *Handler) triggerAgentUpdatedAlert(ctx context.Context, peerID int, hostname, initiatedBy, instanceURL, scope, jobID string) {
	if h.AlertService == nil {
		return
	}
	if initiatedBy == "" {
		initiatedBy = "unknown"
	}
	safeHostname, _ := alerts.SanitizeAlertInput(hostname, 0)
	safeInitiatedBy, _ := alerts.SanitizeAlertInput(initiatedBy, 0)
	metadata := map[string]interface{}{
		"hostname":     safeHostname,
		"initiated_by": safeInitiatedBy,
		"instance_url": instanceURL,
		"job_scope":    scope,
	}
	if jobID != "" {
		metadata["job_id"] = jobID
	}
	event := &alerts.AlertEvent{
		Type:      alerts.AlertTypeAgentUpdated,
		PeerID:    peerID,
		PeerName:  safeHostname,
		Timestamp: time.Now(),
		Subject:   fmt.Sprintf("Agent update sent to %s", safeHostname),
		Message:   fmt.Sprintf("Agent update notification delivered to peer %s (initiated by %s)", safeHostname, safeInitiatedBy),
		Metadata:  metadata,
	}
	if err := h.AlertService.TriggerAlert(ctx, event); err != nil {
		log.WarnContext(ctx, "failed to trigger agent updated alert", "error", err, "peer_id", peerID)
	}
}

// RegisterReadRoutes registers read-only (GET) routes for the viewer role.
func (h *Handler) RegisterReadRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("/by-ip", h.GetPeerByIP).Methods("GET")
	r.HandleFunc("/by-hostname", h.GetPeerByHostname).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeer).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("", h.CreatePeer).Methods("POST")
	r.HandleFunc("/by-ip", h.GetPeerByIP).Methods("GET")
	r.HandleFunc("/by-hostname", h.GetPeerByHostname).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeer).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeletePeer).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/compile", h.CompilePeer).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/rotate-key", h.RotatePeerKey).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips", h.GetPeerIPs).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/ips", h.AddPeerIP).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips/{ip_id:[0-9]+}", h.DeletePeerIP).Methods("DELETE")
}
