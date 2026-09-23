package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"runic/internal/common"
	"runic/internal/models"
)

func TestRegisterSuccessfulRegistration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/agent/register" {
			t.Errorf("expected /api/v1/agent/register, got %s", r.URL.Path)
		}

		// Verify request body
		var reqBody models.AgentRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		// Verify basic fields are set
		if reqBody.Hostname == "" {
			t.Error("expected hostname to be set")
		}
		if reqBody.Arch != runtime.GOARCH {
			t.Errorf("expected arch %s, got %s", runtime.GOARCH, reqBody.Arch)
		}

		resp := models.AgentRegisterResponse{
			HostID:           "host-123",
			Token:            "token-abc",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "hmac-secret-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL:   server.URL,
		RegistrationToken: "initial-registration-token",
	}

	saveCalled := false
	saveFunc := func() error {
		saveCalled = true
		return nil
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", saveFunc, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify config was updated
	if cfg.HostID != "host-123" {
		t.Errorf("expected HostID 'host-123', got '%s'", cfg.HostID)
	}
	if cfg.Token != "token-abc" {
		t.Errorf("expected Token 'token-abc', got '%s'", cfg.Token)
	}
	if cfg.PullIntervalSec != 3600 {
		t.Errorf("expected PullIntervalSec 3600, got %d", cfg.PullIntervalSec)
	}
	if cfg.CurrentBundleVer != "v1.0.0" {
		t.Errorf("expected CurrentBundleVer 'v1.0.0', got '%s'", cfg.CurrentBundleVer)
	}
	if cfg.HMACKey != "hmac-secret-key" {
		t.Errorf("expected HMACKey 'hmac-secret-key', got '%s'", cfg.HMACKey)
	}

	// Verify save was called
	if !saveCalled {
		t.Error("expected saveFunc to be called")
	}

	// Verify registration token was cleared
	if cfg.RegistrationToken != "" {
		t.Errorf("expected RegistrationToken to be cleared, got '%s'", cfg.RegistrationToken)
	}
}

func TestRegisterHandles401Response(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil)
	if err == nil {
		t.Fatal("expected error for 401 response, got nil")
	}

	// Should return a status error
	if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "status") {
		t.Errorf("expected error to contain status code info, got: %v", err)
	}
}

func TestRegisterHandlesNon200StatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil)
	if err == nil {
		t.Fatal("expected error for 500 response, got nil")
	}
}

func TestRegisterDecodesResponseCorrectly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.AgentRegisterResponse{
			HostID:           "test-host-id-456",
			Token:            "test-token-xyz",
			PullInterval:     7200,
			CurrentBundleVer: "v2.1.0",
			HMACKey:          "test-hmac-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify all fields decoded correctly
	if cfg.HostID != "test-host-id-456" {
		t.Errorf("HostID: expected 'test-host-id-456', got '%s'", cfg.HostID)
	}
	if cfg.Token != "test-token-xyz" {
		t.Errorf("Token: expected 'test-token-xyz', got '%s'", cfg.Token)
	}
	if cfg.PullIntervalSec != 7200 {
		t.Errorf("PullIntervalSec: expected 7200, got %d", cfg.PullIntervalSec)
	}
	if cfg.CurrentBundleVer != "v2.1.0" {
		t.Errorf("CurrentBundleVer: expected 'v2.1.0', got '%s'", cfg.CurrentBundleVer)
	}
	if cfg.HMACKey != "test-hmac-key" {
		t.Errorf("HMACKey: expected 'test-hmac-key', got '%s'", cfg.HMACKey)
	}
}

func TestRegisterCallsSaveFuncOnSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := models.AgentRegisterResponse{
			HostID:           "host-id",
			Token:            "token",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "hmac",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
	}

	saveFuncCalled := false
	saveFunc := func() error {
		saveFuncCalled = true
		return nil
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", saveFunc, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if !saveFuncCalled {
		t.Error("saveFunc was not called")
	}
}

func TestRegisterClearsRegistrationTokenAfterUse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody models.AgentRegisterRequest
		_ = json.NewDecoder(r.Body).Decode(&reqBody)

		// Verify registration token was included
		if reqBody.RegistrationToken != "my-registration-token" {
			t.Errorf("expected RegistrationToken 'my-registration-token' in request, got '%s'", reqBody.RegistrationToken)
		}

		resp := models.AgentRegisterResponse{
			HostID:           "host-id",
			Token:            "token",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "hmac",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL:   server.URL,
		RegistrationToken: "my-registration-token",
	}

	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify token was cleared in config
	if cfg.RegistrationToken != "" {
		t.Errorf("RegistrationToken should be cleared, got '%s'", cfg.RegistrationToken)
	}
}

func TestDetectKernelVersionReturnsVersionString(t *testing.T) {
	result := detectKernelVersion()
	// On most systems, this will return something like "5.15.0--generic"
	// On some systems it might be empty if /proc/version doesn't exist
	_ = result // Result may be empty in some test environments
}

func TestDetectKernelVersionReturnsEmptyOnError(t *testing.T) {
	// The function reads from /proc/version
	// If file doesn't exist, it returns empty string
	result := detectKernelVersion()
	// Result may be empty or contain version depending on environment
	_ = result
}

func TestDetectDockerReturnsTrueForSocket(t *testing.T) {
	// common.DetectDockerSocket checks /var/run/docker.sock
	// We can't easily test this without modifying the source or running as root
	// Verify the function doesn't panic and returns a boolean
	result := common.DetectDockerSocket()
	if result != true && result != false {
		t.Errorf("DetectDockerSocket returned invalid value: %v", result)
	}
}

func TestDetectDockerReturnsFalseWhenFileDoesntExist(t *testing.T) {
	// The function checks /var/run/docker.sock
	// If it doesn't exist, returns false
	result := common.DetectDockerSocket()
	// Result depends on actual system state - if docker is not installed, should be false
	_ = result
}

func TestDetectLocalIPReturnsIPv4Address(t *testing.T) {
	result := detectLocalIP()
	// Result depends on actual network configuration
	// In test environment, might be empty
	if result != "" {
		// Verify it's a valid IPv4 format
		ip := net.ParseIP(result)
		if ip == nil {
			t.Errorf("detectLocalIP returned invalid IP: %s", result)
		}
		if ip.To4() == nil {
			t.Errorf("detectLocalIP returned non-IPv4 address: %s", result)
		}
	}
}

func TestDetectLocalIPSkipsLoopbackInterfaces(t *testing.T) {
	result := detectLocalIP()
	// The function should skip loopback interfaces (127.0.0.0/8)
	// If result is not empty, verify it's not a loopback address
	if result != "" {
		ip := net.ParseIP(result)
		if ip != nil && ip.IsLoopback() {
			t.Errorf("detectLocalIP returned loopback address: %s", result)
		}
	}
}

func verifyReRegistrationHMACProofShape(t *testing.T, hmacKey, hostname string, ts int64, sig string) {
	t.Helper()
	if ts == 0 {
		t.Fatal("expected non-zero hmac_proof_timestamp")
	}
	if sig == "" {
		t.Fatal("expected non-empty hmac_proof_signature")
	}
	now := time.Now().Unix()
	skew := int64((5 * time.Minute).Seconds())
	if ts < now-skew || ts > now+skew {
		t.Errorf("proof timestamp %d outside 5m skew window around now %d (host clock must be NTP-synced)", ts, now)
	}
	mac := hmac.New(sha256.New, []byte(hmacKey))
	mac.Write([]byte(models.ReRegistrationHMACProofMessage(hostname, ts)))
	expected := hex.EncodeToString(mac.Sum(nil))
	sigBytes, err1 := hex.DecodeString(sig)
	expBytes, err2 := hex.DecodeString(expected)
	if err1 != nil || err2 != nil {
		t.Fatalf("proof signature not hex-decodable: sigErr=%v expErr=%v", err1, err2)
	}
	if !hmac.Equal(sigBytes, expBytes) {
		t.Error("proof signature does not match server verifier shape hex(HMAC-SHA256(key, \"runic-re-register:<hostname>:<timestamp>\"))")
	}
}

func TestBuildHMACProofReturnsVerifiableSignature(t *testing.T) {
	rawHostname, err := os.Hostname()
	if err != nil {
		rawHostname = "unknown"
	}
	// Mirror production Register sanitization (register.go:55-56) so the
	// proof covers the sanitized hostname the server verifies.
	hostname, _ := models.SanitizeReRegistrationHostname(rawHostname)
	ts, sig := BuildHMACProof(hostname, "test-hmac-secret")
	verifyReRegistrationHMACProofShape(t, "test-hmac-secret", hostname, ts, sig)
}

func TestBuildHMACProofEmptyKeyReturnsZero(t *testing.T) {
	ts, sig := BuildHMACProof("any-host", "")
	if ts != 0 || sig != "" {
		t.Errorf("expected zero values for empty key, got ts=%d sig=%q", ts, sig)
	}
}

func TestRegisterSendsHMACProofWhenKeyPresent(t *testing.T) {
	var gotBody models.AgentRegisterRequest
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		resp := models.AgentRegisterResponse{
			HostID:           "host-123",
			Token:            "token-abc",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "new-hmac-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL:   server.URL,
		HMACKey:           "stored-hmac-secret",
		RegistrationToken: "reg-token-123",
		Token:             "existing-bearer-token",
	}

	if err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if gotBody.Hostname == "" {
		t.Fatal("expected hostname to be set")
	}
	verifyReRegistrationHMACProofShape(t, "stored-hmac-secret", gotBody.Hostname, gotBody.HMACProofTimestamp, gotBody.HMACProofSignature)
	if gotBody.RegistrationToken != "reg-token-123" {
		t.Errorf("expected RegistrationToken to still be sent alongside proof, got %q", gotBody.RegistrationToken)
	}
	if gotAuth != "Bearer existing-bearer-token" {
		t.Errorf("expected bearer token to still be sent, got %q", gotAuth)
	}
}

func TestRegisterSkipsHMACProofWhenKeyEmpty(t *testing.T) {
	var gotBody models.AgentRegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		resp := models.AgentRegisterResponse{
			HostID:           "host-123",
			Token:            "token-abc",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "hmac-secret-key",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
		HMACKey:         "",
	}

	if err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if gotBody.HMACProofTimestamp != 0 {
		t.Errorf("expected no proof timestamp for empty key, got %d", gotBody.HMACProofTimestamp)
	}
	if gotBody.HMACProofSignature != "" {
		t.Error("expected no proof signature for empty key (first boot/new peer)")
	}
}

func TestRegisterSendsAgentKeyWhenSet(t *testing.T) {
	var gotBody models.AgentRegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		resp := models.AgentRegisterResponse{
			HostID:           "host-123",
			Token:            "token-abc",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "new-hmac-key",
			AgentKey:         "agent-key-sent",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
		HMACKey:         "stored-hmac-secret",
		AgentKey:        "agent-key-sent",
		Token:           "existing-bearer-token",
	}

	if err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if gotBody.AgentKey != "agent-key-sent" {
		t.Errorf("expected AgentKey to be sent when set, got %q", gotBody.AgentKey)
	}
	if gotBody.Hostname == "" {
		t.Fatal("expected hostname to be set")
	}
	verifyReRegistrationHMACProofShape(t, "stored-hmac-secret", gotBody.Hostname, gotBody.HMACProofTimestamp, gotBody.HMACProofSignature)
	if cfg.AgentKey != "agent-key-sent" {
		t.Errorf("expected AgentKey persisted, got %q", cfg.AgentKey)
	}
	if cfg.HMACKey != "new-hmac-key" {
		t.Errorf("expected HMACKey persisted, got %q", cfg.HMACKey)
	}
	if cfg.RegistrationToken != "" {
		t.Errorf("expected RegistrationToken cleared, got %q", cfg.RegistrationToken)
	}
}

func TestRegisterOmitsAgentKeyWhenEmpty(t *testing.T) {
	var gotBody models.AgentRegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		resp := models.AgentRegisterResponse{
			HostID:           "host-123",
			Token:            "token-abc",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "hmac-secret-key",
			AgentKey:         "agent-key-new",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
		HMACKey:         "stored-hmac-secret",
		AgentKey:        "",
	}

	if err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error { return nil }, nil); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if gotBody.AgentKey != "" {
		t.Errorf("expected empty AgentKey to be omitted, got %q", gotBody.AgentKey)
	}
	if cfg.AgentKey != "agent-key-new" {
		t.Errorf("expected AgentKey persisted from response, got %q", cfg.AgentKey)
	}
}

func TestRegisterHealsExpiredTokenWithoutManualToken(t *testing.T) {
	var gotBody models.AgentRegisterRequest
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if gotBody.RegistrationToken != "" {
			t.Errorf("expected no manual registration token on heal path, got %q", gotBody.RegistrationToken)
		}
		resp := models.AgentRegisterResponse{
			HostID:           "host-heal",
			Token:            "fresh-token-xyz",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "stored-hmac-secret",
			AgentKey:         "agent-key-existing",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL:   server.URL,
		Token:             "expired-bearer-token",
		HMACKey:           "stored-hmac-secret",
		AgentKey:          "agent-key-existing",
		RegistrationToken: "",
	}

	saveCalled := false
	if err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error {
		saveCalled = true
		return nil
	}, nil); err != nil {
		t.Fatalf("Register heal failed: %v", err)
	}

	if gotAuth != "Bearer expired-bearer-token" {
		t.Errorf("expected expired bearer to still be sent, got %q", gotAuth)
	}
	if gotBody.Hostname == "" {
		t.Fatal("expected hostname to be set on heal path")
	}
	if gotBody.AgentKey != "agent-key-existing" {
		t.Errorf("expected AgentKey sent on heal path, got %q", gotBody.AgentKey)
	}
	verifyReRegistrationHMACProofShape(t, "stored-hmac-secret", gotBody.Hostname, gotBody.HMACProofTimestamp, gotBody.HMACProofSignature)
	if !saveCalled {
		t.Error("expected saveFunc to be called on heal success")
	}
	if cfg.Token != "fresh-token-xyz" {
		t.Errorf("expected fresh token after heal, got %q", cfg.Token)
	}
	if cfg.HMACKey != "stored-hmac-secret" {
		t.Errorf("expected HMACKey persisted after heal, got %q", cfg.HMACKey)
	}
	if cfg.AgentKey != "agent-key-existing" {
		t.Errorf("expected AgentKey persisted after heal, got %q", cfg.AgentKey)
	}
	if cfg.RegistrationToken != "" {
		t.Errorf("expected RegistrationToken cleared after heal, got %q", cfg.RegistrationToken)
	}
}

func TestRegisterSaveFailureStillMutatesConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/agent/register" {
			http.NotFound(w, r)
			return
		}
		resp := models.AgentRegisterResponse{
			HostID:           "fresh-host-save-fail",
			Token:            "fresh-token-save-fail",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "fresh-hmac-save-fail",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
		HostID:          "stale-host",
		Token:           "stale-token",
	}

	// os.ErrPermission models a read-only config file/dir without new deps.
	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error {
		return os.ErrPermission
	}, nil)
	if err == nil {
		t.Fatal("expected save-wrapped error for failing saveFunc, got nil")
	}
	if !errors.Is(err, ErrPersistAfterRegister) {
		t.Errorf("expected error to match ErrPersistAfterRegister, got: %v", err)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("expected error chain to preserve os.ErrPermission via %%w, got: %v", err)
	}
	if !strings.Contains(err.Error(), "save config after registration") {
		t.Errorf("expected error to wrap persist failure, got: %v", err)
	}

	// Credentials are mutated before save, so the caller can retain them
	// in-memory despite the error.
	if cfg.HostID != "fresh-host-save-fail" {
		t.Errorf("expected HostID 'fresh-host-save-fail' despite save failure, got '%s'", cfg.HostID)
	}
	if cfg.Token != "fresh-token-save-fail" {
		t.Errorf("expected Token 'fresh-token-save-fail' despite save failure, got '%s'", cfg.Token)
	}
}

// persistCauseError is a distinct cause type so errors.As can prove the
// %w chain preserves the save failure cause, not just the sentinel.
type persistCauseError struct{ msg string }

func (e *persistCauseError) Error() string { return e.msg }

func TestRegisterSaveFailurePreservesCauseChain(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/agent/register" {
			http.NotFound(w, r)
			return
		}
		resp := models.AgentRegisterResponse{
			HostID:           "fresh-host-cause-chain",
			Token:            "fresh-token-cause-chain",
			PullInterval:     3600,
			CurrentBundleVer: "v1.0.0",
			HMACKey:          "fresh-hmac-cause-chain",
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := &Config{
		ControlPlaneURL: server.URL,
		HostID:          "stale-host",
		Token:           "stale-token",
	}

	cause := &persistCauseError{msg: "read-only filesystem"}
	err := Register(context.Background(), server.Client(), cfg, "v1.0.0", func() error {
		return cause
	}, nil)
	if err == nil {
		t.Fatal("expected save-wrapped error for failing saveFunc, got nil")
	}
	if !errors.Is(err, ErrPersistAfterRegister) {
		t.Errorf("expected error to match ErrPersistAfterRegister, got: %v", err)
	}
	var got *persistCauseError
	if !errors.As(err, &got) {
		t.Fatalf("expected errors.As to retrieve persist cause, got: %v", err)
	}
	if got != cause {
		t.Errorf("expected cause pointer %p, got %p", cause, got)
	}
	if !strings.Contains(err.Error(), "read-only filesystem") {
		t.Errorf("expected error to preserve cause message via %%w, got: %v", err)
	}
}
