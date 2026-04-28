// Package events provides events functionality.
package events

import (
	"fmt"
	"sync"

	runiclog "runic/internal/common/log"
)

// NotifyUpdateAgenter is the interface for sending update_agent SSE events.
// Defined here to avoid import cycles and DRY violations.
type NotifyUpdateAgenter interface {
	NotifyUpdateAgent(hostID string, controlPlaneURL string) bool
}

type SSEHub struct {
	clients         map[string]chan string // host_id -> event channel
	pushJobClients  map[string]chan string // job_id -> SSE channel
	frontendClients map[string]chan string // client_id -> event channel for frontend users
	mu              sync.RWMutex
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients:         make(map[string]chan string),
		pushJobClients:  make(map[string]chan string),
		frontendClients: make(map[string]chan string),
	}
}

func (h *SSEHub) Register(hostID string) chan string {
	ch := make(chan string, 4)
	h.mu.Lock()
	h.clients[hostID] = ch
	h.mu.Unlock()
	return ch
}

func (h *SSEHub) Unregister(hostID string) {
	h.mu.Lock()
	if ch, ok := h.clients[hostID]; ok {
		close(ch)
		delete(h.clients, hostID)
	}
	h.mu.Unlock()
}

func (h *SSEHub) NotifyBundleUpdated(hostID string, version string) bool {
	h.mu.RLock()
	ch, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		runiclog.Warn("NotifyBundleUpdated: agent not connected", "host_id", hostID)
		return false
	}
	select {
	case ch <- fmt.Sprintf("event: bundle_updated\ndata: {\"version\":%q}\n\n", version):
		return true
	default:
		runiclog.Warn("NotifyBundleUpdated: channel full, dropping update", "host_id", hostID)
		return false
	}
}

// NotifyFetchBackup sends a fetch_backup event to the agent, requesting it to
// read and POST its pre-Runic iptables backup and ipset data.
func (h *SSEHub) NotifyFetchBackup(hostID string) bool {
	h.mu.RLock()
	ch, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		runiclog.Warn("NotifyFetchBackup: agent not connected", "host_id", hostID)
		return false
	}
	select {
	case ch <- fmt.Sprintf("event: fetch_backup\ndata: {\"host_id\":%q}\n\n", hostID):
		return true
	default:
		runiclog.Warn("NotifyFetchBackup: channel full, dropping update", "host_id", hostID)
		return false
	}
}

// NotifyUpdateAgent sends an update_agent event to the agent, instructing it
// to self-update by running the install script with the given control plane URL.
func (h *SSEHub) NotifyUpdateAgent(hostID string, controlPlaneURL string) bool {
	h.mu.RLock()
	ch, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		runiclog.Warn("NotifyUpdateAgent: agent not connected", "host_id", hostID)
		return false
	}
	select {
	case ch <- fmt.Sprintf("event: update_agent\ndata: {\"control_plane_url\":%q}\n\n", controlPlaneURL):
		return true
	default:
		runiclog.Warn("NotifyUpdateAgent: channel full, dropping update", "host_id", hostID)
		return false
	}
}

// RegisterPushJob registers a channel for push job progress events.
func (h *SSEHub) RegisterPushJob(jobID string) chan string {
	ch := make(chan string, 16) // larger buffer for progress events
	h.mu.Lock()
	h.pushJobClients[jobID] = ch
	h.mu.Unlock()
	return ch
}

// UnregisterPushJob removes and closes the channel for a push job.
func (h *SSEHub) UnregisterPushJob(jobID string) {
	h.mu.Lock()
	if ch, ok := h.pushJobClients[jobID]; ok {
		close(ch)
		delete(h.pushJobClients, jobID)
	}
	h.mu.Unlock()
}

// NotifyPushJobProgress sends a progress event to all listeners of a push job.
func (h *SSEHub) NotifyPushJobProgress(jobID string, eventType string, payload string) {
	h.mu.RLock()
	ch, ok := h.pushJobClients[jobID]
	h.mu.RUnlock()
	if ok {
		event := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, payload)
		select {
		case ch <- event:
		default: // client not reading, skip
		}
	}
}

// NotifyPendingChangeAdded notifies agents about pending configuration changes.
// The frontend can use this to immediately refresh the peers list.
func (h *SSEHub) NotifyPendingChangeAdded(hostID string, peerID int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	msg := fmt.Sprintf("event: pending_change_added\ndata: {\"peer_id\":%d}\n\n", peerID)
	if ch, ok := h.clients[hostID]; ok {
		select {
		case ch <- msg:
		default: // Channel full, skip
		}
	}
}

// RegisterFrontend registers a frontend client for receiving events.
// clientID should be a unique identifier (e.g., user ID or random UUID).
func (h *SSEHub) RegisterFrontend(clientID string) chan string {
	ch := make(chan string, 8) // buffer for multiple event types
	h.mu.Lock()
	h.frontendClients[clientID] = ch
	h.mu.Unlock()
	return ch
}

func (h *SSEHub) UnregisterFrontend(clientID string) {
	h.mu.Lock()
	if ch, ok := h.frontendClients[clientID]; ok {
		close(ch)
		delete(h.frontendClients, clientID)
	}
	h.mu.Unlock()
}

func (h *SSEHub) NotifyFrontendPendingChangeAdded(peerID int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	msg := fmt.Sprintf("event: pending_change_added\ndata: {\"peer_id\":%d}\n\n", peerID)
	for _, ch := range h.frontendClients {
		select {
		case ch <- msg:
		default: // Channel full, skip
		}
	}
}
