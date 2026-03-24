package events

import (
	"fmt"
	"sync"
)

type SSEHub struct {
	clients map[string]chan string // host_id -> event channel
	mu      sync.RWMutex
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[string]chan string),
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

func (h *SSEHub) NotifyBundleUpdated(hostID string, version string) {
	h.mu.RLock()
	ch, ok := h.clients[hostID]
	h.mu.RUnlock()
	if ok {
		select {
		case ch <- fmt.Sprintf("event: bundle_updated\ndata: {\"version\":\"%s\"}\n\n", version):
		default: // agent not listening, will pull on poll
		}
	}
}
