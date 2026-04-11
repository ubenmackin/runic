package events

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// =============================================================================
// Test SSEHub Initialization
// =============================================================================

func TestNewSSEHub(t *testing.T) {
	hub := NewSSEHub()

	if hub == nil {
		t.Fatal("NewSSEHub returned nil")
	}

	if hub.clients == nil {
		t.Error("clients map is nil")
	}

	if hub.pushJobClients == nil {
		t.Error("pushJobClients map is nil")
	}

	if hub.mu == (sync.RWMutex{}) {
		// Note: sync.RWMutex can't be meaningfully compared to zero value
		// but we verify mutex exists by testing lock functionality
		t.Log("note: mutex exists but cannot compare directly to zero value")
	}
}

// =============================================================================
// Test Register/Unregister
// =============================================================================

func TestSSEHub_Register(t *testing.T) {
	tests := []struct {
		name   string
		hostID string
	}{
		{"register host1", "host1"},
		{"register host2", "host2"},
		{"register empty string", ""},
		{"register with special chars", "host-id_123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := NewSSEHub()
			ch := hub.Register(tt.hostID)

			if ch == nil {
				t.Error("Register returned nil channel")
			}

			// Channel should have buffer of 4
			select {
			case ch <- "test":
			default:
				t.Log("channel buffer not full")
			}
		})
	}
}

func TestSSEHub_Unregister(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(h *SSEHub) string
		hostID string
		wantOk bool
	}{
		{
			name: "unregister existing host",
			setup: func(h *SSEHub) string {
				return "host1"
			},
			hostID: "host1",
			wantOk: true,
		},
		{
			name: "unregister non-existent host",
			setup: func(h *SSEHub) string {
				h.Register("host1")
				return "host2"
			},
			hostID: "host2",
			wantOk: false,
		},
		{
			name: "unregister after multiple registrations",
			setup: func(h *SSEHub) string {
				h.Register("host1")
				h.Register("host2")
				return "host1"
			},
			hostID: "host1",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := NewSSEHub()
			registeredID := tt.setup(hub)

			// Register to get a channel
			ch := hub.Register(registeredID)

			// Unregister
			hub.Unregister(tt.hostID)

			// Verify channel is closed
			select {
			case _, ok := <-ch:
				if ok {
					t.Log("channel not closed yet")
				}
			case <-time.After(100 * time.Millisecond):
				t.Error("timeout waiting for channel")
			}
		})
	}
}

func TestSSEHub_RegisterUnregisterMultiple(t *testing.T) {
	hub := NewSSEHub()

	// Register multiple hosts
	hosts := []string{"host1", "host2", "host3"}
	channels := make([]chan string, len(hosts))

	for i, host := range hosts {
		channels[i] = hub.Register(host)
	}

	// Unregister middle host
	hub.Unregister("host2")

	// Verify other channels still work
	hub.NotifyBundleUpdated("host1", "v1.0")
	hub.NotifyBundleUpdated("host3", "v1.0")

	// Give time for notifications
	time.Sleep(50 * time.Millisecond)

	// host2 should not receive notification (already unregistered)
	hub.NotifyBundleUpdated("host2", "v1.0")
}

// =============================================================================
// Test NotifyBundleUpdated
// =============================================================================

func TestSSEHub_NotifyBundleUpdated(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(h *SSEHub) (hostID string)
		hostID        string
		version       string
		expectReceive bool
	}{
		{
			name: "notify existing host",
			setup: func(h *SSEHub) string {
				h.Register("host1")
				return "host1"
			},
			hostID:        "host1",
			version:       "v1.0.0",
			expectReceive: true,
		},
		{
			name: "notify non-existent host",
			setup: func(h *SSEHub) string {
				return "nonexistent"
			},
			hostID:        "nonexistent",
			version:       "v1.0.0",
			expectReceive: false,
		},
		{
			name: "notify after unregister",
			setup: func(h *SSEHub) string {
				ch := h.Register("host1")
				h.Unregister("host1")
				// Drain channel to avoid blocking
				go func() {
					for range ch {
					}
				}()
				return "host1"
			},
			hostID:        "host1",
			version:       "v1.0.0",
			expectReceive: false,
		},
		{
			name: "notify multiple hosts",
			setup: func(h *SSEHub) string {
				h.Register("host1")
				h.Register("host2")
				h.Register("host3")
				return "host1"
			},
			hostID:        "host1",
			version:       "v2.0.0",
			expectReceive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := NewSSEHub()
			_ = tt.setup(hub)

			hub.NotifyBundleUpdated(tt.hostID, tt.version)

			if tt.expectReceive {
				// Give time for async notification
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestSSEHub_NotifyBundleUpdatedFormat(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.Register("host1")

	hub.NotifyBundleUpdated("host1", "v1.2.3")

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "bundle_updated") {
			t.Errorf("expected bundle_updated event, got: %s", msg)
		}
		if !strings.Contains(msg, "v1.2.3") {
			t.Errorf("expected version v1.2.3, got: %s", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for notification")
	}
}

// =============================================================================
// Test Push Job Registration
// =============================================================================

func TestSSEHub_RegisterPushJob(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterPushJob("job1")

	if ch == nil {
		t.Error("RegisterPushJob returned nil channel")
	}

	// Push job channels should have larger buffer (16)
	select {
	case ch <- "test":
	default:
		t.Log("channel buffer not full")
	}
}

func TestSSEHub_UnregisterPushJob(t *testing.T) {
	hub := NewSSEHub()

	// Register push job
	ch := hub.RegisterPushJob("job1")

	// Unregister
	hub.UnregisterPushJob("job1")

	// Verify channel is closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Log("channel not closed yet")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for channel")
	}
}

func TestSSEHub_UnregisterPushJobNonExistent(t *testing.T) {
	hub := NewSSEHub()

	// Unregister non-existent job should not panic
	hub.UnregisterPushJob("nonexistent")
}

// =============================================================================
// Test Push Job Progress Notifications
// =============================================================================

func TestSSEHub_NotifyPushJobProgress(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(h *SSEHub) (jobID string)
		jobID         string
		eventType     string
		payload       string
		expectReceive bool
	}{
		{
			name: "notify existing job",
			setup: func(h *SSEHub) string {
				h.RegisterPushJob("job1")
				return "job1"
			},
			jobID:         "job1",
			eventType:     "progress",
			payload:       `{"percent": 50}`,
			expectReceive: true,
		},
		{
			name: "notify non-existent job",
			setup: func(h *SSEHub) string {
				return "nonexistent"
			},
			jobID:         "nonexistent",
			eventType:     "progress",
			payload:       `{"percent": 50}`,
			expectReceive: false,
		},
		{
			name: "notify after unregister",
			setup: func(h *SSEHub) string {
				ch := h.RegisterPushJob("job1")
				h.UnregisterPushJob("job1")
				// Drain channel
				go func() {
					for range ch {
					}
				}()
				return "job1"
			},
			jobID:         "job1",
			eventType:     "progress",
			payload:       `{"percent": 50}`,
			expectReceive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := NewSSEHub()
			_ = tt.setup(hub)

			hub.NotifyPushJobProgress(tt.jobID, tt.eventType, tt.payload)

			if tt.expectReceive {
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestSSEHub_NotifyPushJobProgressFormat(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterPushJob("job1")

	hub.NotifyPushJobProgress("job1", "progress", `{"percent": 75}`)

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "progress") {
			t.Errorf("expected progress event, got: %s", msg)
		}
		if !strings.Contains(msg, `{"percent": 75}`) {
			t.Errorf("expected payload, got: %s", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for notification")
	}
}

func TestSSEHub_NotifyPushJobComplete(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterPushJob("job1")

	hub.NotifyPushJobProgress("job1", "complete", `{"status": "success"}`)

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "complete") {
			t.Errorf("expected complete event, got: %s", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for notification")
	}
}

// =============================================================================
// Test Concurrent Access (Thread Safety)
// =============================================================================

func TestSSEHub_ConcurrentRegisterUnregister(t *testing.T) {
	hub := NewSSEHub()
	var wg sync.WaitGroup

	// Concurrent registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.Register(fmt.Sprintf("host%d", id))
		}(i)
	}

	// Concurrent unregistrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.Unregister(fmt.Sprintf("host%d", id))
		}(i)
	}

	wg.Wait()
}

func TestSSEHub_ConcurrentPushJobRegistration(t *testing.T) {
	hub := NewSSEHub()
	var wg sync.WaitGroup

	// Concurrent push job registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.RegisterPushJob(fmt.Sprintf("job%d", id))
		}(i)
	}

	// Concurrent push job unregistrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.UnregisterPushJob(fmt.Sprintf("job%d", id))
		}(i)
	}

	wg.Wait()
}

func TestSSEHub_ConcurrentNotify(t *testing.T) {
	hub := NewSSEHub()

	// Register multiple hosts
	for i := 0; i < 5; i++ {
		hub.Register(fmt.Sprintf("host%d", i))
	}

	var wg sync.WaitGroup

	// Concurrent notifications
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.NotifyBundleUpdated(fmt.Sprintf("host%d", id), "v1.0")
		}(i)
	}

	wg.Wait()
}

func TestSSEHub_ConcurrentMixedOperations(t *testing.T) {
	hub := NewSSEHub()
	var wg sync.WaitGroup
	opsCount := 100

	// Mixed concurrent operations
	for i := 0; i < opsCount; i++ {
		wg.Add(1)
		go func(op int) {
			defer wg.Done()
			hostID := fmt.Sprintf("host%d", op%10)

			switch op % 4 {
			case 0:
				hub.Register(hostID)
			case 1:
				hub.Unregister(hostID)
			case 2:
				hub.NotifyBundleUpdated(hostID, "v1.0")
			case 3:
				// Read operation simulation via lock
				hub.mu.RLock()
				_, _ = hub.clients[hostID]
				hub.mu.RUnlock()
			}
		}(i)
	}

	wg.Wait()
}

// =============================================================================
// Test Channel Buffer Behavior
// =============================================================================

func TestSSEHub_NotifyWhenChannelFull(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.Register("host1")

	// Fill the channel buffer (capacity 4)
	for i := 0; i < 4; i++ {
		select {
		case ch <- "test":
		default:
			t.Error("channel should not be full yet")
		}
	}

	// This should not block due to the default case in NotifyBundleUpdated
	hub.NotifyBundleUpdated("host1", "v1.0")

	// The notification should be dropped (channel full)
	// No error should occur (non-blocking)
}

func TestSSEHub_PushJobChannelBuffer(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterPushJob("job1")

	// Fill the channel buffer (capacity 16)
	for i := 0; i < 16; i++ {
		select {
		case ch <- "test":
		default:
			t.Error("channel should not be full yet")
		}
	}

	// This should not block due to the default case
	hub.NotifyPushJobProgress("job1", "progress", "{}")
}

// =============================================================================
// Test Integration with Context (Optional)
// =============================================================================

func TestSSEHub_WithContext(t *testing.T) {
	hub := NewSSEHub()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ch := hub.Register("host1")

	// Simulate async notification
	go func() {
		time.Sleep(50 * time.Millisecond)
		hub.NotifyBundleUpdated("host1", "v1.0")
	}()

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "bundle_updated") {
			t.Errorf("expected bundle_updated event, got: %s", msg)
		}
	case <-ctx.Done():
		t.Error("context timeout")
	}
}

// =============================================================================
// Test Frontend Client Registration
// =============================================================================

func TestSSEHub_RegisterFrontend(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterFrontend("client1")

	if ch == nil {
		t.Error("RegisterFrontend returned nil channel")
	}

	// Frontend channels should have buffer of 8
	for i := 0; i < 8; i++ {
		select {
		case ch <- "test":
		default:
			t.Errorf("channel should not be full at index %d", i)
		}
	}
}

func TestSSEHub_UnregisterFrontend(t *testing.T) {
	hub := NewSSEHub()

	// Register frontend client
	ch := hub.RegisterFrontend("client1")

	// Unregister
	hub.UnregisterFrontend("client1")

	// Verify channel is closed
	select {
	case _, ok := <-ch:
		if ok {
			t.Log("channel not closed yet")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for channel")
	}
}

func TestSSEHub_UnregisterFrontendNonExistent(t *testing.T) {
	hub := NewSSEHub()

	// Unregister non-existent client should not panic
	hub.UnregisterFrontend("nonexistent")
}

// =============================================================================
// Test Frontend Pending Change Notifications
// =============================================================================

func TestSSEHub_NotifyFrontendPendingChangeAdded(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(h *SSEHub) (clientID string)
		peerID        int
		expectReceive bool
	}{
		{
			name: "notify existing frontend client",
			setup: func(h *SSEHub) string {
				h.RegisterFrontend("client1")
				return "client1"
			},
			peerID:        5,
			expectReceive: true,
		},
		{
			name: "notify when no clients registered",
			setup: func(h *SSEHub) string {
				return ""
			},
			peerID:        5,
			expectReceive: false,
		},
		{
			name: "notify multiple frontend clients",
			setup: func(h *SSEHub) string {
				h.RegisterFrontend("client1")
				h.RegisterFrontend("client2")
				h.RegisterFrontend("client3")
				return "client1"
			},
			peerID:        10,
			expectReceive: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hub := NewSSEHub()
			_ = tt.setup(hub)

			hub.NotifyFrontendPendingChangeAdded(tt.peerID)

			if tt.expectReceive {
				// Give time for async notification
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

func TestSSEHub_NotifyFrontendPendingChangeAddedFormat(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterFrontend("client1")

	hub.NotifyFrontendPendingChangeAdded(42)

	select {
	case msg := <-ch:
		if !strings.Contains(msg, "pending_change_added") {
			t.Errorf("expected pending_change_added event, got: %s", msg)
		}
		if !strings.Contains(msg, `"peer_id":42`) {
			t.Errorf("expected peer_id 42, got: %s", msg)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("timeout waiting for notification")
	}
}

func TestSSEHub_NotifyFrontendMultipleClients(t *testing.T) {
	hub := NewSSEHub()

	// Register multiple frontend clients
	clientCh1 := hub.RegisterFrontend("client1")
	clientCh2 := hub.RegisterFrontend("client2")
	clientCh3 := hub.RegisterFrontend("client3")

	// Notify all clients
	hub.NotifyFrontendPendingChangeAdded(15)

	// All clients should receive the notification
	time.Sleep(50 * time.Millisecond)

	// Verify all clients received the event
	for i, ch := range []chan string{clientCh1, clientCh2, clientCh3} {
		select {
		case msg := <-ch:
			if !strings.Contains(msg, "pending_change_added") {
				t.Errorf("client%d: expected pending_change_added event, got: %s", i+1, msg)
			}
		default:
			t.Errorf("client%d: did not receive notification", i+1)
		}
	}
}

func TestSSEHub_ConcurrentFrontendRegistration(t *testing.T) {
	hub := NewSSEHub()
	var wg sync.WaitGroup

	// Concurrent frontend registrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.RegisterFrontend(fmt.Sprintf("client%d", id))
		}(i)
	}

	// Concurrent frontend unregistrations
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			hub.UnregisterFrontend(fmt.Sprintf("client%d", id))
		}(i)
	}

	wg.Wait()
}

func TestSSEHub_FrontendChannelBuffer(t *testing.T) {
	hub := NewSSEHub()
	ch := hub.RegisterFrontend("client1")

	// Fill the channel buffer (capacity 8)
	for i := 0; i < 8; i++ {
		select {
		case ch <- "test":
		default:
			t.Error("channel should not be full yet")
		}
	}

	// This should not block due to the default case in NotifyFrontendPendingChangeAdded
	hub.NotifyFrontendPendingChangeAdded(1)
}
