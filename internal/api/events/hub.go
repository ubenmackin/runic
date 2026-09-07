// Package events provides events functionality.
package events

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	runiclog "runic/internal/common/log"
)

// A NotifyUpdateAgenter is an interface for notifying agents to self-update.
// Defined here to avoid import cycles and DRY violations.
type NotifyUpdateAgenter interface {
	NotifyUpdateAgent(hostID string, controlPlaneURL string) bool
}

type hostEntry struct {
	ch chan string
	// pending counts in-flight NotifyBundleUpdated timed sends on ch.
	// All accesses happen under SSEHub.mu. Unregister and Register wait for
	// pending to drain before closing ch, which orders the timed send (which
	// holds no lock during its wait) before the close and keeps the race
	// detector clean.
	pending int
}

type SSEHub struct {
	clients         map[string]*hostEntry    // host_id -> event channel entry
	pushJobClients  map[string][]chan string // job_id -> SSE channels (supports multiple listeners)
	frontendClients map[string]chan string   // client_id -> event channel for frontend users
	mu              sync.RWMutex
	// sendMu serializes non-blocking channel sends against closes so a
	// notifier holding a copied channel reference never races with a
	// concurrent close. The client map is copied under mu, then the send or
	// close proceeds under sendMu. Sends hold RLock (allowing concurrent
	// sends) while closes hold Lock. NotifyBundleUpdated uses a timed wait
	// and must not hold sendMu during the wait, so its sends are instead
	// ordered by the per-entry pending count (see hostEntry).
	sendMu  sync.RWMutex
	dropped atomic.Uint64
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients:         make(map[string]*hostEntry),
		pushJobClients:  make(map[string][]chan string),
		frontendClients: make(map[string]chan string),
	}
}

// DroppedCount reports the number of SSE events dropped for slow consumers.
func (h *SSEHub) DroppedCount() uint64 {
	return h.dropped.Load()
}

func (h *SSEHub) Register(hostID string) chan string {
	ch := make(chan string, 4)
	entry := &hostEntry{ch: ch}
	h.mu.Lock()
	existing := h.clients[hostID]
	h.clients[hostID] = entry
	h.mu.Unlock()
	if existing != nil {
		// Close the replaced channel after in-flight timed sends drain.
		// The previous consumer observes the close and shuts down.
		h.closeHostEntry(existing)
	}
	return ch
}

func (h *SSEHub) Unregister(hostID string) {
	h.mu.Lock()
	entry, ok := h.clients[hostID]
	if ok {
		delete(h.clients, hostID)
	}
	h.mu.Unlock()
	if ok {
		h.closeHostEntry(entry)
	}
}

// closeHostEntry waits for in-flight NotifyBundleUpdated timed sends on the
// entry to finish, then closes the channel. The wait polls under mu so the
// timed send (which holds no lock during its 100ms wait) is ordered before
// the close. Non-blocking trySend callers are ordered by sendMu.
func (h *SSEHub) closeHostEntry(entry *hostEntry) {
	for {
		h.mu.RLock()
		pending := entry.pending
		h.mu.RUnlock()
		if pending <= 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	h.sendMu.Lock()
	safeClose(entry.ch)
	h.sendMu.Unlock()
}

func (h *SSEHub) NotifyBundleUpdated(hostID string, version string) (sent bool) {
	h.mu.Lock()
	entry, ok := h.clients[hostID]
	if ok {
		entry.pending++
	}
	h.mu.Unlock()
	if !ok {
		runiclog.Warn("NotifyBundleUpdated: agent not connected", "host_id", hostID)
		return false
	}
	ch := entry.ch
	msg := fmt.Sprintf("event: bundle_updated\ndata: {\"version\":%q}\n\n", version)
	// The channel is copied under mu and the timed send proceeds without
	// holding sendMu, so a slow consumer's 100ms wait never blocks
	// Register/Unregister closes. Closes wait for pending to drain, so the
	// send is ordered before any concurrent close; the recover remains as a
	// final guard and reports a concurrent disconnect as a drop.
	defer func() {
		if recover() != nil {
			runiclog.Warn("NotifyBundleUpdated: client disconnected during send", "host_id", hostID)
			h.dropped.Add(1)
			sent = false
		}
		h.mu.Lock()
		entry.pending--
		h.mu.Unlock()
	}()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case ch <- msg:
		return true
	case <-timer.C:
		runiclog.Warn("NotifyBundleUpdated: slow consumer, dropping update", "host_id", hostID)
		h.dropped.Add(1)
		return false
	}
}

func (h *SSEHub) NotifyFetchBackup(hostID string) bool {
	h.mu.RLock()
	entry, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		runiclog.Warn("NotifyFetchBackup: agent not connected", "host_id", hostID)
		return false
	}
	msg := fmt.Sprintf("event: fetch_backup\ndata: {\"host_id\":%q}\n\n", hostID)
	if !h.trySend(entry.ch, msg) {
		runiclog.Warn("NotifyFetchBackup: channel full, dropping update", "host_id", hostID)
		return false
	}
	return true
}

// NotifyUpdateAgent sends an update event to the agent, instructing it
// to self-update by running the install script with the given control plane URL.
func (h *SSEHub) NotifyUpdateAgent(hostID string, controlPlaneURL string) bool {
	h.mu.RLock()
	entry, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		runiclog.Warn("NotifyUpdateAgent: agent not connected", "host_id", hostID)
		return false
	}
	msg := fmt.Sprintf("event: update_agent\ndata: {\"control_plane_url\":%q}\n\n", controlPlaneURL)
	if !h.trySend(entry.ch, msg) {
		runiclog.Warn("NotifyUpdateAgent: channel full, dropping update", "host_id", hostID)
		return false
	}
	return true
}

func (h *SSEHub) RegisterPushJob(jobID string) chan string {
	ch := make(chan string, 16) // larger buffer for progress events
	h.mu.Lock()
	h.pushJobClients[jobID] = append(h.pushJobClients[jobID], ch)
	h.mu.Unlock()
	return ch
}

func (h *SSEHub) UnregisterPushJob(jobID string, ch chan string) {
	h.mu.Lock()
	clients := h.pushJobClients[jobID]
	for i, c := range clients {
		if c == ch {
			h.pushJobClients[jobID] = append(clients[:i], clients[i+1:]...)
			if len(h.pushJobClients[jobID]) == 0 {
				delete(h.pushJobClients, jobID)
			}
			h.mu.Unlock()
			if ch != nil {
				h.sendMu.Lock()
				safeClose(ch)
				h.sendMu.Unlock()
			}
			return
		}
	}
	h.mu.Unlock()
}

func (h *SSEHub) NotifyPushJobProgress(jobID string, eventType string, payload string) {
	h.mu.RLock()
	clients := append([]chan string(nil), h.pushJobClients[jobID]...)
	h.mu.RUnlock()
	if len(clients) == 0 {
		return
	}
	event := fmt.Sprintf("event: %s\ndata: %s\n\n", eventType, payload)
	for _, ch := range clients {
		h.trySend(ch, event)
	}
}

// NotifyPendingChangeAdded notifies connected agents and frontends that a pending change was added.
// The frontend can use this to immediately refresh the peers list.
func (h *SSEHub) NotifyPendingChangeAdded(hostID string, peerID int) {
	h.mu.RLock()
	entry, ok := h.clients[hostID]
	h.mu.RUnlock()
	if !ok {
		return
	}
	msg := fmt.Sprintf("event: pending_change_added\ndata: {\"peer_id\":%d}\n\n", peerID)
	h.trySend(entry.ch, msg)
}

// RegisterFrontend registers a frontend SSE client. clientID should be a unique identifier (e.g., user ID or random UUID).
func (h *SSEHub) RegisterFrontend(clientID string) chan string {
	ch := make(chan string, 8) // buffer for multiple event types
	h.mu.Lock()
	existing, ok := h.frontendClients[clientID]
	h.frontendClients[clientID] = ch
	h.mu.Unlock()
	if ok {
		// Close the replaced channel outside the map lock, serialized
		// against concurrent sends via sendMu.
		h.sendMu.Lock()
		safeClose(existing)
		h.sendMu.Unlock()
	}
	return ch
}

func (h *SSEHub) UnregisterFrontend(clientID string) {
	h.mu.Lock()
	ch, ok := h.frontendClients[clientID]
	if ok {
		delete(h.frontendClients, clientID)
	}
	h.mu.Unlock()
	if ok {
		h.sendMu.Lock()
		safeClose(ch)
		h.sendMu.Unlock()
	}
}

func (h *SSEHub) NotifyFrontendPendingChangeAdded(peerID int) {
	h.mu.RLock()
	clients := make([]chan string, 0, len(h.frontendClients))
	for _, ch := range h.frontendClients {
		clients = append(clients, ch)
	}
	h.mu.RUnlock()
	msg := fmt.Sprintf("event: pending_change_added\ndata: {\"peer_id\":%d}\n\n", peerID)
	for _, ch := range clients {
		h.trySend(ch, msg)
	}
}

// trySend performs a non-blocking send, returning false when the channel is
// full or has been closed by a concurrent unregister or re-registration.
// Drops are counted in DroppedCount so slow-consumer pressure is observable,
// matching the log Hub behavior.
func (h *SSEHub) trySend(ch chan string, msg string) (sent bool) {
	h.sendMu.RLock()
	defer h.sendMu.RUnlock()
	defer func() {
		if recover() != nil {
			h.dropped.Add(1)
			sent = false
		}
	}()
	select {
	case ch <- msg:
		return true
	default:
		h.dropped.Add(1)
		return false
	}
}

// safeClose closes ch, tolerating a redundant close. Callers must hold
// sendMu.Lock so the close is serialized against concurrent sends.
func safeClose(ch chan string) {
	defer func() {
		_ = recover()
	}()
	close(ch)
}
