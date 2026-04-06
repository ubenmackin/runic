package logs

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"runic/internal/models"
)

// =============================================================================
// Hub Tests
// =============================================================================

func TestNewHub(t *testing.T) {
	hub := NewHub()

	if hub == nil {
		t.Fatal("expected hub to not be nil")
	}

	if hub.clients == nil {
		t.Error("expected clients map to be initialized")
	}

	if hub.broadcast == nil {
		t.Error("expected broadcast channel to be initialized")
	}

	if hub.register == nil {
		t.Error("expected register channel to be initialized")
	}

	if hub.unregister == nil {
		t.Error("expected unregister channel to be initialized")
	}
}

func TestHub_Broadcast(t *testing.T) {
	hub := NewHub()
	client := &Client{
		hub:    hub,
		send:   make(chan []byte, 256),
		filter: LogFilter{}, // Empty filter accepts all
	}

	// Manually register client (bypass channel)
	hub.mu.Lock()
	hub.clients[client] = true
	hub.mu.Unlock()

	// Create and broadcast log event
	event := &models.LogEvent{
		ID:        1,
		PeerID:    "test-peer",
		Action:    "ACCEPT",
		SrcIP:     "192.168.1.100",
		DstIP:     "10.0.0.1",
		DstPort:   22,
		Protocol:  "tcp",
		Timestamp: time.Now(),
	}

	hub.Broadcast(event)

	// Wait for message to be sent
	select {
	case msg := <-client.send:
		var received models.LogEvent
		if err := json.Unmarshal(msg, &received); err != nil {
			t.Fatalf("failed to unmarshal message: %v", err)
		}
		if received.ID != event.ID {
			t.Errorf("expected ID=%d, got %d", event.ID, received.ID)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for broadcast message")
	}
}

func TestHub_Broadcast_WithFilter(t *testing.T) {
	hub := NewHub()
	client := &Client{
		hub:  hub,
		send: make(chan []byte, 256),
		filter: LogFilter{
			PeerID: "peer-1", // Only receive logs for peer-1
		},
	}

	// Manually register client
	hub.mu.Lock()
	hub.clients[client] = true
	hub.mu.Unlock()

	// Broadcast event for different peer - should not be received
	event := &models.LogEvent{
		ID:        1,
		PeerID:    "peer-2", // Different peer
		Action:    "ACCEPT",
		Timestamp: time.Now(),
	}

	hub.Broadcast(event)

	// Should not receive any message
	select {
	case <-client.send:
		t.Error("expected no message for filtered peer")
	case <-time.After(100 * time.Millisecond):
		// This is expected - no message should be sent
	}
}

func TestHub_Broadcast_MultipleClients(t *testing.T) {
	hub := NewHub()

	// Create two clients with different filters
	client1 := &Client{
		hub:  hub,
		send: make(chan []byte, 256),
		filter: LogFilter{
			PeerID: "peer1",
		},
	}
	client2 := &Client{
		hub:  hub,
		send: make(chan []byte, 256),
		filter: LogFilter{
			PeerID: "peer2",
		},
	}

	// Register both clients
	hub.mu.Lock()
	hub.clients[client1] = true
	hub.clients[client2] = true
	hub.mu.Unlock()

	// Broadcast to peer1 - only client1 should receive
	event := &models.LogEvent{
		ID:        1,
		PeerID:    "peer1",
		Action:    "ACCEPT",
		Timestamp: time.Now(),
	}

	hub.Broadcast(event)

	// client1 should receive
	select {
	case <-client1.send:
	case <-time.After(100 * time.Millisecond):
		t.Error("expected client1 to receive message")
	}

	// client2 should not receive
	select {
	case <-client2.send:
		t.Error("expected client2 to NOT receive message")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestHub_Broadcast_EmptyClients(t *testing.T) {
	hub := NewHub()

	// Broadcast with no clients - should not panic
	event := &models.LogEvent{
		ID:        1,
		PeerID:    "test-peer",
		Action:    "ACCEPT",
		Timestamp: time.Now(),
	}

	// Should not panic
	hub.Broadcast(event)
}

func TestHub_Run(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		hub.Run(ctx)
	}()

	// Register a client
	client := &Client{
		hub:  hub,
		send: make(chan []byte, 256),
	}
	hub.register <- client

	// Wait for registration
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	_, ok := hub.clients[client]
	hub.mu.RUnlock()
	if !ok {
		t.Error("expected client to be registered")
	}

	// Unregister the client
	hub.unregister <- client
	time.Sleep(10 * time.Millisecond)

	hub.mu.RLock()
	_, ok = hub.clients[client]
	hub.mu.RUnlock()
	if ok {
		t.Error("expected client to be unregistered")
	}

	// Cancel context to stop hub
	cancel()
	time.Sleep(10 * time.Millisecond)
	wg.Wait()
}

func TestHub_Run_Broadcast(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		hub.Run(ctx)
	}()

	// Register a client with empty filter
	client := &Client{
		hub:    hub,
		send:   make(chan []byte, 256),
		filter: LogFilter{},
	}
	hub.register <- client

	// Wait for registration
	time.Sleep(10 * time.Millisecond)

	// Broadcast via channel
	msg := []byte(`{"test": "message"}`)
	hub.broadcast <- msg

	// Wait for message
	select {
	case received := <-client.send:
		if string(received) != string(msg) {
			t.Errorf("expected %s, got %s", msg, received)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for broadcast message")
	}

	// Cleanup
	cancel()
	time.Sleep(10 * time.Millisecond)
	wg.Wait()
}

func TestHub_Run_ContextCancellation(t *testing.T) {
	hub := NewHub()
	ctx, cancel := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		hub.Run(ctx)
	}()

	// Cancel immediately to stop
	cancel()
	wg.Wait()
}

// =============================================================================
// Client matchesFilter Tests
// =============================================================================

func TestClient_MatchesFilter(t *testing.T) {
	tests := []struct {
		name     string
		filter   LogFilter
		event    *models.LogEvent
		expected bool
	}{
		{
			name:   "empty filter matches all",
			filter: LogFilter{},
			event: &models.LogEvent{
				PeerID:  "peer1",
				Action:  "ACCEPT",
				SrcIP:   "192.168.1.1",
				DstPort: 22,
			},
			expected: true,
		},
		{
			name: "peer_id filter matches",
			filter: LogFilter{
				PeerID: "peer1",
			},
			event: &models.LogEvent{
				PeerID: "peer1",
			},
			expected: true,
		},
		{
			name: "peer_id filter does not match",
			filter: LogFilter{
				PeerID: "peer1",
			},
			event: &models.LogEvent{
				PeerID: "peer2",
			},
			expected: false,
		},
		{
			name: "action filter matches",
			filter: LogFilter{
				Action: "ACCEPT",
			},
			event: &models.LogEvent{
				Action: "ACCEPT",
			},
			expected: true,
		},
		{
			name: "action filter does not match",
			filter: LogFilter{
				Action: "ACCEPT",
			},
			event: &models.LogEvent{
				Action: "DROP",
			},
			expected: false,
		},
		{
			name: "src_ip filter matches",
			filter: LogFilter{
				SrcIP: "192.168.1.1",
			},
			event: &models.LogEvent{
				SrcIP: "192.168.1.1",
			},
			expected: true,
		},
		{
			name: "src_ip filter does not match",
			filter: LogFilter{
				SrcIP: "192.168.1.1",
			},
			event: &models.LogEvent{
				SrcIP: "192.168.1.2",
			},
			expected: false,
		},
		{
			name: "dst_port filter matches",
			filter: LogFilter{
				DstPort: 22,
			},
			event: &models.LogEvent{
				DstPort: 22,
			},
			expected: true,
		},
		{
			name: "dst_port filter does not match",
			filter: LogFilter{
				DstPort: 22,
			},
			event: &models.LogEvent{
				DstPort: 80,
			},
			expected: false,
		},
		{
			name: "dst_port 0 matches any",
			filter: LogFilter{
				DstPort: 0, // Default - matches any
			},
			event: &models.LogEvent{
				DstPort: 22,
			},
			expected: true,
		},
		{
			name: "multiple filters all match",
			filter: LogFilter{
				PeerID:  "peer1",
				Action:  "ACCEPT",
				SrcIP:   "192.168.1.1",
				DstPort: 22,
			},
			event: &models.LogEvent{
				PeerID:  "peer1",
				Action:  "ACCEPT",
				SrcIP:   "192.168.1.1",
				DstPort: 22,
			},
			expected: true,
		},
		{
			name: "multiple filters one fails",
			filter: LogFilter{
				PeerID: "peer1",
				Action: "ACCEPT",
			},
			event: &models.LogEvent{
				PeerID: "peer1",
				Action: "DROP",
			},
			expected: false,
		},
		{
			name: "peer_id empty matches any",
			filter: LogFilter{
				PeerID: "",
			},
			event: &models.LogEvent{
				PeerID: "any-peer",
			},
			expected: true,
		},
		{
			name: "action empty matches any",
			filter: LogFilter{
				Action: "",
			},
			event: &models.LogEvent{
				Action: "any-action",
			},
			expected: true,
		},
		{
			name: "src_ip empty matches any",
			filter: LogFilter{
				SrcIP: "",
			},
			event: &models.LogEvent{
				SrcIP: "any-ip",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &Client{
				filter: tt.filter,
			}
			result := client.matchesFilter(tt.event)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// =============================================================================
// LogFilter Tests
// =============================================================================

func TestLogFilter_Struct(t *testing.T) {
	filter := LogFilter{
		PeerID:  "peer1",
		Action:  "ACCEPT",
		SrcIP:   "192.168.1.1",
		DstPort: 22,
	}

	if filter.PeerID != "peer1" {
		t.Errorf("expected PeerID='peer1', got '%s'", filter.PeerID)
	}
	if filter.Action != "ACCEPT" {
		t.Errorf("expected Action='ACCEPT', got '%s'", filter.Action)
	}
	if filter.SrcIP != "192.168.1.1" {
		t.Errorf("expected SrcIP='192.168.1.1', got '%s'", filter.SrcIP)
	}
	if filter.DstPort != 22 {
		t.Errorf("expected DstPort=22, got %d", filter.DstPort)
	}
}

func TestLogFilter_ZeroValue(t *testing.T) {
	var filter LogFilter

	// Zero value filter should match everything
	event := &models.LogEvent{
		PeerID:  "any",
		Action:  "any",
		SrcIP:   "any",
		DstPort: 0,
	}

	client := &Client{
		filter: filter,
	}

	if !client.matchesFilter(event) {
		t.Error("expected zero-value filter to match any event")
	}
}
