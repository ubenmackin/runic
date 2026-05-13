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
	"regexp"
	"slices"
	"strings"

	"github.com/gorilla/mux"

	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/api/events"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/engine"
	"runic/internal/store"
)

// SettingsStore is defined as an interface here for testability.
type SettingsStore interface {
	GetSystemConfig(ctx context.Context, key string) (string, error)
}

type Handler struct {
	Store         *store.PeerStore
	beginner      db.Beginner
	Compiler      *engine.Compiler
	SSEHub        events.NotifyUpdateAgenter
	SettingsStore SettingsStore
}

func NewHandler(peerStore *store.PeerStore, beginner db.Beginner, compiler *engine.Compiler, sseHub events.NotifyUpdateAgenter, settingsStore SettingsStore) *Handler {
	return &Handler{Store: peerStore, beginner: beginner, Compiler: compiler, SSEHub: sseHub, SettingsStore: settingsStore}
}

// must start and end with alphanumeric (single-char hostnames allowed).
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

var validOSTypes = []string{
	"debian", "ubuntu", "rhel", "arch", "opensuse", "raspbian", "linux",
	"armbian", "ios", "ipados", "macos", "tvos", "windows", "other",
}

var validArchs = []string{"amd64", "arm64", "arm", "armv6", "other"}

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

func (h *Handler) CreatePeer(w http.ResponseWriter, r *http.Request) {
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
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if input.Hostname == "" || len(input.Hostname) > 253 || !hostnameRegex.MatchString(input.Hostname) {
		common.RespondError(w, http.StatusBadRequest, "hostname must be 1-253 characters, alphanumeric with hyphens and dots only")
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

	var input struct {
		Hostname    string `json:"hostname"`
		IPAddress   string `json:"ip_address"`
		OSType      string `json:"os_type"`
		Arch        string `json:"arch"`
		HasDocker   *bool  `json:"has_docker"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
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

	common.RespondJSON(w, http.StatusOK, map[string]string{"message": "Peer deleted"})
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
			common.RespondJSON(w, http.StatusOK, nil) // No peer found
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
			common.RespondJSON(w, http.StatusOK, nil) // No peer found
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
	// a separate existence check (T007-#3).
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

	var input struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if net.ParseIP(input.IPAddress) == nil {
		common.RespondError(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	// Single query: ListPeerIPs handles both existence verification (empty = no peer)
	// and duplicate IP detection (T007-#2).
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

	// Return the known inserted data directly instead of re-querying (T007-#2).
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

	_, err = h.Store.GetPeerByID(r.Context(), peerID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer")
		return
	}

	peerIPs, err := h.Store.ListPeerIPs(r.Context(), peerID)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query peer IPs")
		return
	}

	var targetIP *store.PeerIPView
	for i := range peerIPs {
		if peerIPs[i].ID == ipID {
			targetIP = &peerIPs[i]
			break
		}
	}

	if targetIP == nil {
		common.RespondError(w, http.StatusNotFound, "peer IP not found")
		return
	}

	// Cannot delete primary IP
	if targetIP.IsPrimary {
		common.RespondError(w, http.StatusBadRequest, "cannot delete primary IP address")
		return
	}

	policyCount, err := h.Store.CountPolicyRefsForPeerIP(r.Context(), peerID, targetIP.IPAddress)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to check policy references")
		return
	}
	if policyCount > 0 {
		common.RespondError(w, http.StatusConflict, fmt.Sprintf("cannot delete IP: referenced by %d policy/policies", policyCount))
		return
	}

	err = h.Store.DeletePeerIP(r.Context(), ipID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			common.RespondError(w, http.StatusNotFound, "peer IP not found")
			return
		}
		common.RespondError(w, http.StatusInternalServerError, "failed to delete peer IP")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UpdateAgent triggers a self-update for a peer's agent. POST /api/v1/peers/{id}/update-agent
func (h *Handler) UpdateAgent(w http.ResponseWriter, r *http.Request) {
	peerID, err := common.ParseIDParam(r, "id")
	if err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid peer ID")
		return
	}
	ctx := r.Context()

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

	if h.SSEHub == nil {
		common.RespondError(w, http.StatusInternalServerError, "SSE hub not available")
		return
	}
	hostID := fmt.Sprintf("host-%s", peer.Hostname)
	delivered := h.SSEHub.NotifyUpdateAgent(hostID, instanceURL)
	if !delivered {
		common.RespondJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "agent_not_connected"})
		return
	}
	log.Info("UpdateAgent: update sent via SSE", "host_id", hostID)
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "update_sent"})
}

// RegisterReadRoutes registers read-only (GET) routes for the viewer role.
func (h *Handler) RegisterReadRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("/by-ip", h.GetPeerByIP).Methods("GET")
	r.HandleFunc("/by-hostname", h.GetPeerByHostname).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/ips", h.GetPeerIPs).Methods("GET")
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.GetPeers).Methods("GET")
	r.HandleFunc("", h.CreatePeer).Methods("POST")
	r.HandleFunc("/by-ip", h.GetPeerByIP).Methods("GET")
	r.HandleFunc("/by-hostname", h.GetPeerByHostname).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.GetPeers).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/{id:[0-9]+}", h.DeletePeer).Methods("DELETE")
	r.HandleFunc("/{id:[0-9]+}/bundle", h.GetPeerBundle).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/compile", h.CompilePeer).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/rotate-key", h.RotatePeerKey).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips", h.GetPeerIPs).Methods("GET")
	r.HandleFunc("/{id:[0-9]+}/ips", h.AddPeerIP).Methods("POST")
	r.HandleFunc("/{id:[0-9]+}/ips/{ip_id:[0-9]+}", h.DeletePeerIP).Methods("DELETE")
}
