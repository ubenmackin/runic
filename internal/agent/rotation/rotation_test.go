package rotation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
)

func helperConfig() *identity.Config {
	return &identity.Config{
		ControlPlaneURL: "http://localhost:8080",
		HostID:          "host-test-peer",
		Token:           "test-agent-token",
		HMACKey:         "old-hmac-key-12345678901234567890123456789012",
	}
}

func TestNewManager(t *testing.T) {
	manager := NewManager(&http.Client{})

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}

	if manager.state != StateIdle {
		t.Errorf("NewManager() state = %v, want %v", manager.state, StateIdle)
	}
}

func TestCheckAndRotate_NoRotationPending(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/check-rotation" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

func TestCheckAndRotate_NoRotationPending_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/agent/check-rotation" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateIdle {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateIdle)
	}
}

func TestCheckAndRotate_RotationSuccess(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		currentCall := callCount
		mu.Unlock()

		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "test-rotation-token-abc123",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)

		case "/api/v1/agent/confirm-rotation":
			w.WriteHeader(http.StatusOK)

		default:
			http.NotFound(w, r)
		}

		t.Logf("Call %d: %s %s", currentCall, r.Method, r.URL.Path)
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	cfg.HMACKey = "old-hmac-key-12345678901234567890123456789012"
	manager := NewManager(server.Client())

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}

	if manager.GetState() != StateConfirmed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateConfirmed)
	}

	if newKey != "new-hmac-key-abcdef123456789012345678901234" {
		t.Errorf("CheckAndRotate() newKey = %s, want new-hmac-key-abcdef123456789012345678901234", newKey)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was mutated by Manager = %s, want old key preserved", cfg.HMACKey)
	}

	// Verify last rotation timestamp was set
	if manager.GetLastRotation().IsZero() {
		t.Error("last rotation timestamp was not set")
	}
}

func TestCheckAndRotate_TokenExpired(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "expired-token",
			})

		case "/api/v1/agent/rotate-key":
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "invalid or expired rotation token",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with expired token")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on failure: %s", cfg.HMACKey)
	}
}

func TestCheckAndRotate_KeyTestFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusUnauthorized)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed when key test fails")
	}

	if manager.GetState() != StateFallback {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFallback)
	}

	// Verify old key was preserved (Manager no longer mutates config pointer)
	if cfg.HMACKey != "old-hmac-key-12345678901234567890123456789012" {
		t.Errorf("config HMACKey was changed on key test failure: %s", cfg.HMACKey)
	}
}

func TestCheckAndRotate_ConfirmFailsNonFatal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-abcdef123456789012345678901234",
			})

		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)

		case "/api/v1/agent/confirm-rotation":
			w.WriteHeader(http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	// Confirm-rotation failure IS now fatal (error state)
	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Fatal("CheckAndRotate() expected error when confirm-rotation fails")
	}
	if !strings.Contains(err.Error(), "confirm rotation") {
		t.Errorf("CheckAndRotate() error = %v, want 'confirm rotation'", err)
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

func TestCheckAndRotate_SkipsInProgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when rotation is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	// Manually set state to rotating
	manager.mu.Lock()
	manager.state = StateRotating
	manager.mu.Unlock()

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	// State should remain rotating (not changed)
	if manager.GetState() != StateRotating {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateRotating)
	}
}

func TestCheckAndRotate_SkipsTesting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("HTTP request should not be made when testing is in progress")
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	// Manually set state to testing
	manager.mu.Lock()
	manager.state = StateTesting
	manager.mu.Unlock()

	newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err != nil {
		t.Fatalf("CheckAndRotate() error = %v", err)
	}
	if newKey != "" {
		t.Errorf("CheckAndRotate() newKey = %s, want empty", newKey)
	}

	if manager.GetState() != StateTesting {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateTesting)
	}
}

func TestCheckAndRotate_EmptyKeyFromServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "",
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with empty key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

func TestCheckAndRotate_UnexpectedStatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.WriteHeader(http.StatusInternalServerError)

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with unexpected status code")
	}
}

func TestGetState(t *testing.T) {
	manager := NewManager(&http.Client{})

	// Test initial state
	if manager.GetState() != StateIdle {
		t.Errorf("GetState() = %v, want %v", manager.GetState(), StateIdle)
	}

	// Test after manual state change
	manager.mu.Lock()
	manager.state = StateRotating
	manager.mu.Unlock()

	if manager.GetState() != StateRotating {
		t.Errorf("GetState() = %v, want %v", manager.GetState(), StateRotating)
	}
}

func TestGetLastRotation(t *testing.T) {
	manager := NewManager(&http.Client{})

	// Initially should be zero
	if !manager.GetLastRotation().IsZero() {
		t.Error("GetLastRotation() should be zero initially")
	}

	expected := time.Now().UTC()
	manager.mu.Lock()
	manager.lastRotation = expected
	manager.mu.Unlock()

	if manager.GetLastRotation() != expected {
		t.Errorf("GetLastRotation() = %v, want %v", manager.GetLastRotation(), expected)
	}
}

func TestRotationStateConstants(t *testing.T) {
	states := []RotationState{
		StateIdle,
		StateRotating,
		StateTesting,
		StateConfirmed,
		StateFailed,
		StateFallback,
	}

	for _, state := range states {
		if state == "" {
			t.Errorf("RotationState constant is empty: %v", state)
		}
	}
}

func TestCheckAndRotate_CheckRotationReturnsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-valid-json"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON response")
	}
}

func TestCheckAndRotate_RotateKeyReturnsInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "valid-token",
			})

		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("not-valid-json"))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	_, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
	if err == nil {
		t.Error("CheckAndRotate() should have failed with invalid JSON from rotate-key")
	}

	if manager.GetState() != StateFailed {
		t.Errorf("CheckAndRotate() state = %v, want %v", manager.GetState(), StateFailed)
	}
}

func TestCheckAndRotate_Concurrent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/agent/check-rotation":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"rotation_token": "concurrent-token",
			})
		case "/api/v1/agent/rotate-key":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"new_hmac_key": "new-hmac-key-concurrent-12345678901234",
			})
		case "/api/v1/agent/test-key":
			w.WriteHeader(http.StatusOK)
		case "/api/v1/agent/confirm-rotation":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	cfg := helperConfig()
	cfg.ControlPlaneURL = server.URL
	manager := NewManager(server.Client())

	var wg sync.WaitGroup
	var errMu sync.Mutex
	var errs []error
	var successCount int
	var skipCount int
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			newKey, err := manager.CheckAndRotate(context.Background(), cfg.HMACKey, cfg.Token, cfg.ControlPlaneURL, cfg.HostID)
			errMu.Lock()
			defer errMu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			// Record terminal outcomes: empty means skipped (already in
			// progress) or no rotation; non-empty means a rotation won.
			// Either is valid under concurrency; what matters is no panic,
			// no unexpected error, and at least one successful rotation.
			if newKey != "" {
				successCount++
			} else {
				skipCount++
			}
		}()
	}
	wg.Wait()

	// The concurrent run must not panic and must end in a defined rotation
	// state.
	state := manager.GetState()
	switch state {
	case StateIdle, StateRotating, StateTesting, StateConfirmed, StateFailed, StateFallback:
	default:
		t.Fatalf("concurrent CheckAndRotate ended in invalid state %q", state)
	}
	errMu.Lock()
	nErrs := len(errs)
	nSuccess := successCount
	nSkip := skipCount
	errDetails := make([]string, 0, nErrs)
	for _, err := range errs {
		errDetails = append(errDetails, err.Error())
	}
	errMu.Unlock()
	if nErrs != 0 {
		t.Fatalf("concurrent rotation returned %d unexpected errors: %v", nErrs, errDetails)
	}
	if nSuccess == 0 {
		t.Errorf("concurrent rotation had no successful rotation (successes=0 skips=%d); at least one winner is expected", nSkip)
	}
	if nSuccess+nSkip != 20 {
		t.Errorf("concurrent rotation outcome count = %d, want 20 (successes=%d skips=%d errors=%d)", nSuccess+nSkip, nSuccess, nSkip, nErrs)
	}
	t.Logf("concurrent rotation finished state=%s successes=%d skips=%d errors=%d", state, nSuccess, nSkip, nErrs)
}
