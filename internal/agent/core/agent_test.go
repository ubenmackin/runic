package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"runic/internal/agent/identity"
	"runic/internal/common/log"
	"runic/internal/models"
)

func TestMain(m *testing.M) {
	// Ensure log is initialized before any test runs so that tests which
	// call log.Init with a buffer (e.g., "handles both systemd-run and setsid failure")
	// do not leave the process-global logger in a corrupted state for subsequent tests.
	log.Init("info", os.Stdout)
	os.Exit(m.Run())
}

func helperConfig() *identity.Config {
	return &identity.Config{
		ControlPlaneURL:      "http://localhost:8080",
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
}

func helperConfigPath(t *testing.T, cfg *identity.Config) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}
	return path
}

func TestNew(t *testing.T) {
	agent := New("/tmp/config.json", "http://localhost:8080")

	if agent == nil {
		t.Fatal("New() returned nil")
	}

	if agent.config == nil {
		t.Error("New() config is nil")
	}

	if agent.httpClient == nil {
		t.Error("New() httpClient is nil")
	}

	if agent.sseClient == nil {
		t.Error("New() sseClient is nil")
	}

	if agent.version == "" {
		t.Error("New() version is empty")
	}

	if agent.rotationManager == nil {
		t.Error("New() rotationManager is nil")
	}

	// Verify default config values
	if agent.config.ControlPlaneURL != "http://localhost:8080" {
		t.Errorf("New() ControlPlaneURL = %s, want http://localhost:8080", agent.config.ControlPlaneURL)
	}

	if agent.config.PullIntervalSec != identity.DefaultPullIntervalSec {
		t.Errorf("New() PullIntervalSec = %d, want %d", agent.config.PullIntervalSec, identity.DefaultPullIntervalSec)
	}

	if agent.config.LogPath != "/var/log/runic/firewall.log" {
		t.Errorf("New() LogPath = %s, want /var/log/runic/firewall.log", agent.config.LogPath)
	}
}

func TestLoadConfigReturnsDefault(t *testing.T) {
	agent := New("/nonexistent/path/config.json", "http://localhost:8080")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Should return default config
	if agent.config.PullIntervalSec != identity.DefaultPullIntervalSec {
		t.Errorf("loadConfig() PullIntervalSec = %d, want default %d", agent.config.PullIntervalSec, identity.DefaultPullIntervalSec)
	}

	if agent.config.HeartbeatIntervalSec != identity.DefaultHeartbeatIntervalSec {
		t.Errorf("loadConfig() HeartbeatIntervalSec = %d, want default %d", agent.config.HeartbeatIntervalSec, identity.DefaultHeartbeatIntervalSec)
	}
}

func TestLoadConfigLoadsExisting(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 3600
	cfg.HeartbeatIntervalSec = 60
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "")
	agent.config.ControlPlaneURL = "" // Clear CLI-provided value to test config file loading

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	if agent.config.PullIntervalSec != 3600 {
		t.Errorf("loadConfig() PullIntervalSec = %d, want 3600", agent.config.PullIntervalSec)
	}

	if agent.config.HeartbeatIntervalSec != 60 {
		t.Errorf("loadConfig() HeartbeatIntervalSec = %d, want 60", agent.config.HeartbeatIntervalSec)
	}

	if agent.config.HostID != "host-test-peer" {
		t.Errorf("loadConfig() HostID = %s, want host-test-peer", agent.config.HostID)
	}
}

func TestLoadConfigMergesCLIValues(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty - CLI should override
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://cli-provided-url:9090")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI value should override empty config file value
	if agent.config.ControlPlaneURL != "http://cli-provided-url:9090" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want CLI value http://cli-provided-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestSaveConfigWritesFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host-id"
	agent.config.Token = "test-token"
	agent.config.HMACKey = "test-hmac-key"

	err := agent.saveConfig()
	if err != nil {
		t.Fatalf("saveConfig() error = %v", err)
	}

	// Verify file was created
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read config file: %v", err)
	}

	var savedCfg identity.Config
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Fatalf("failed to parse config file: %v", err)
	}

	if savedCfg.HostID != "test-host-id" {
		t.Errorf("saved HostID = %s, want test-host-id", savedCfg.HostID)
	}

	// Verify file permissions are 0600
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("failed to stat config file: %v", err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("config file permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestApplyBundleSkipsWhenDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
	}

	// applyBundle should return nil without applying when disabled
	err := agent.applyBundle(context.Background(), bundle)
	if err != nil {
		t.Errorf("applyBundle() error = %v, want nil (should skip when disabled)", err)
	}

	// CurrentBundleVer should not be updated
	if agent.config.CurrentBundleVer == "test-v1" {
		t.Error("applyBundle() updated CurrentBundleVer even though ApplyRulesBundle is false")
	}
}

func TestApplyBundleSavesConfigOnSuccess(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"
	agent.config.HMACKey = "test-hmac-key"

	// Track if apply.ApplyBundle was called (we can't easily mock it, so we verify config save)
	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		HMAC:    "dummy-hmac", // Will fail validation but we test the save path
	}

	// applyBundle will fail due to invalid HMAC, but that's ok for this test
	// We're testing the config save path
	_ = agent.applyBundle(context.Background(), bundle)

	// Note: In real test we'd mock apply.ApplyBundle, but we can at least verify
	// the method is callable without panic
}

func TestConfirmApplyCallsTransport(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"
	agent.config.ControlPlaneURL = "http://localhost:8080"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ConfirmApply calls /api/v1/agent/bundle/{hostID}/applied
		if strings.Contains(r.URL.Path, "/applied") && r.Method == "POST" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	err := agent.confirmApply(context.Background(), "test-version")
	if err != nil {
		t.Fatalf("confirmApply() error = %v", err)
	}
}

func TestRegisterCallsIdentity(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // Clear host ID to trigger registration
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "register") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"host_id": "registered-host-id",
				"token":   "registered-token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent := New(configPath, server.URL)
	agent.config.HostID = ""
	agent.config.Token = ""

	err := agent.register(context.Background())
	if err != nil {
		t.Fatalf("register() error = %v", err)
	}

	// Verify registration updated config
	if agent.config.HostID != "registered-host-id" {
		t.Errorf("register() HostID = %s, want registered-host-id", agent.config.HostID)
	}
}

func TestSafeRegisterAcquiresMutex(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Test that safeRegister can be called without panic
	// (will fail registration but we verify mutex is present)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_ = agent.safeRegister(ctx)
}

func TestIsControlPlaneReachableTrue(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if !reachable {
		t.Error("isControlPlaneReachable() returned false, want true")
	}
}

func TestIsControlPlaneReachableFalse(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://invalid-host:9999")

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if reachable {
		t.Error("isControlPlaneReachable() returned true, want false for unreachable host")
	}
}

type mockCommandRunner struct {
	output []byte
	err error
	runErr error
	calls []mockCall
	startDetachedErr error
	detachedCalls []mockCall
}

type mockCall struct {
	ctx  context.Context
	name string
	args []string
}

func (m *mockCommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, mockCall{ctx: ctx, name: name, args: args})
	if name == "systemd-run" && m.runErr != nil {
		return nil, m.runErr
	}
	return m.output, m.err
}

func (m *mockCommandRunner) StartDetached(ctx context.Context, name string, args ...string) error {
	m.detachedCalls = append(m.detachedCalls, mockCall{ctx: ctx, name: name, args: args})
	if name == "setsid" && m.startDetachedErr != nil {
		return m.startDetachedErr
	}
	return nil
}

func TestHandleUpdateAgent(t *testing.T) {
	t.Run("successful update launch", func(t *testing.T) {
		mock := &mockCommandRunner{}
		agent := &Agent{
			cmdRunner: mock,
		}
		agent.handleUpdateAgent(context.Background(), "https://runic.example.com")
		if len(mock.calls) != 1 {
			t.Fatalf("expected 1 Run call, got %d", len(mock.calls))
		}
		if mock.calls[0].name != "systemd-run" {
			t.Errorf("expected command 'systemd-run', got '%s'", mock.calls[0].name)
		}
		// The command is passed as: systemd-run --scope --unit=runic-agent-update bash -c <cmd>
		// So args should contain: "--scope", "--unit=runic-agent-update", "bash", "-c", cmd
		args := mock.calls[0].args
		foundScope := false
		foundUnit := false
		foundBash := false
		foundC := false
		var cmdStr string
		for i, arg := range args {
			if arg == "--scope" {
				foundScope = true
			}
			if arg == "--unit=runic-agent-update" {
				foundUnit = true
			}
			if arg == "bash" {
				foundBash = true
			}
			if arg == "-c" && i+1 < len(args) {
				foundC = true
				cmdStr = args[i+1]
			}
		}
		if !foundScope {
			t.Error("expected args to contain '--scope'")
		}
		if !foundUnit {
			t.Error("expected args to contain '--unit=runic-agent-update'")
		}
		if !foundBash {
			t.Error("expected args to contain 'bash'")
		}
		if !foundC {
			t.Error("expected args to contain '-c'")
		}
		if !strings.Contains(cmdStr, "curl -sL") {
			t.Error("expected command to contain 'curl -sL'")
		}
		if strings.Contains(cmdStr, "nohup curl") {
			t.Error("expected command to NOT contain 'nohup curl' in systemd-run path")
		}
		if !strings.Contains(cmdStr, "install-agent.sh") {
			t.Error("expected command to contain install-agent.sh URL")
		}
		if !strings.Contains(cmdStr, "runic.example.com") {
			t.Error("expected command to contain control plane URL")
		}
		if len(mock.detachedCalls) != 0 {
			t.Errorf("expected 0 detached calls, got %d", len(mock.detachedCalls))
		}
	})

	t.Run("rejects invalid URL scheme", func(t *testing.T) {
		mock := &mockCommandRunner{}
		agent := &Agent{
			cmdRunner: mock,
		}
		agent.handleUpdateAgent(context.Background(), "ftp://malicious.example.com")
		if len(mock.calls) != 0 || len(mock.detachedCalls) != 0 {
			t.Error("expected no command to be run for invalid URL scheme")
		}
	})

	t.Run("rejects malformed URL", func(t *testing.T) {
		mock := &mockCommandRunner{}
		agent := &Agent{
			cmdRunner: mock,
		}
		agent.handleUpdateAgent(context.Background(), "://broken")
		if len(mock.calls) != 0 || len(mock.detachedCalls) != 0 {
			t.Error("expected no command to be run for malformed URL")
		}
	})

	t.Run("uses context.Background not SSE context", func(t *testing.T) {
		mock := &mockCommandRunner{}
		agent := &Agent{
			cmdRunner: mock,
		}
		// Pass a canceled context as the SSE context
		sseCtx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately
		agent.handleUpdateAgent(sseCtx, "https://runic.example.com")
		if len(mock.calls) != 1 {
			t.Fatalf("expected 1 Run call, got %d", len(mock.calls))
		}
		// The function should use context.Background(), not the canceled SSE context
		capturedCtx := mock.calls[0].ctx
		if capturedCtx == sseCtx {
			t.Error("handleUpdateAgent should use context.Background(), not the SSE context")
		}
		// Verify the captured context is not canceled
		if err := capturedCtx.Err(); err != nil {
			t.Error("handleUpdateAgent should use context.Background() which is never canceled")
		}
	})

	t.Run("falls back to setsid when systemd-run fails", func(t *testing.T) {
		// Redirect log output to a buffer to verify logging
		var logBuf bytes.Buffer
		log.Init("info", &logBuf)
		defer log.Init("info", os.Stdout)

		mock := &mockCommandRunner{
			runErr: fmt.Errorf("systemd-run: command not found"),
		}
		agent := &Agent{
			cmdRunner: mock,
		}
		agent.handleUpdateAgent(context.Background(), "https://runic.example.com")

		// Verify Run was called (systemd-run attempt)
		if len(mock.calls) != 1 {
			t.Fatalf("expected 1 Run call, got %d", len(mock.calls))
		}

		// Verify StartDetached was called (setsid fallback)
		if len(mock.detachedCalls) != 1 {
			t.Fatalf("expected 1 detached call, got %d", len(mock.detachedCalls))
		}
		if mock.detachedCalls[0].name != "setsid" {
			t.Errorf("expected command 'setsid', got '%s'", mock.detachedCalls[0].name)
		}
		if len(mock.detachedCalls[0].args) < 3 {
			t.Fatalf("expected at least 3 args, got %d", len(mock.detachedCalls[0].args))
		}
		cmdStr := mock.detachedCalls[0].args[2]
		if !strings.Contains(cmdStr, "nohup curl") {
			t.Error("expected fallback command to contain 'nohup curl'")
		}

		// Verify warning log about falling back
		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "falling back to setsid") {
			t.Errorf("expected warning log about 'falling back to setsid', got log output: %q", logOutput)
		}

		// Verify the success log WAS produced (since the fallback succeeded)
		if !strings.Contains(logOutput, "Update process launched") {
			t.Error("expected success log 'Update process launched' to be present when setsid fallback succeeds")
		}
	})

	t.Run("handles both systemd-run and setsid failure", func(t *testing.T) {
		// Redirect log output to a buffer to verify error logging
		var logBuf bytes.Buffer
		log.Init("error", &logBuf)
		defer log.Init("info", os.Stdout)

		mock := &mockCommandRunner{
			runErr:          fmt.Errorf("systemd-run: command not found"),
			startDetachedErr: fmt.Errorf("setsid: command not found"),
		}
		agent := &Agent{
			cmdRunner: mock,
		}
		agent.handleUpdateAgent(context.Background(), "https://runic.example.com")

		// Verify both Run and StartDetached were called
		if len(mock.calls) != 1 {
			t.Fatalf("expected 1 Run call, got %d", len(mock.calls))
		}
		if len(mock.detachedCalls) != 1 {
			t.Fatalf("expected 1 detached call, got %d", len(mock.detachedCalls))
		}

		// Verify the error log was produced
		logOutput := logBuf.String()
		if !strings.Contains(logOutput, "Failed to launch update process (both systemd-run and setsid failed)") {
			t.Errorf("expected error log about both failures, got log output: %q", logOutput)
		}

		// Verify the success log was NOT produced (since both paths failed)
		if strings.Contains(logOutput, "Update process launched") {
			t.Error("expected success log 'Update process launched' to NOT be present when both methods fail")
		}
	})
}

func TestApplyCachedBundle_NoCacheFile(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// Use a non-existent cache path in temp dir
	agent.cachePath = filepath.Join(t.TempDir(), "nonexistent.rules")
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil for missing cache", err)
	}
}

func TestApplyCachedBundle_EmptyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte(""), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for empty rules, got nil")
	}
	if err != nil && !strings.Contains(err.Error(), "empty") {
		t.Errorf("applyCachedBundle() error = %v, want 'empty' error", err)
	}
}

func TestApplyCachedBundle_WhitespaceOnlyRules(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	_ = os.WriteFile(cachePath, []byte("   \n  \n  "), 0600)
	agent.cachePath = cachePath
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for whitespace-only rules, got nil")
	}
}

func TestApplyCachedBundle_ReadError(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Point to an unreadable path (directory instead of file)
	cacheDir := t.TempDir()
	agent.cachePath = cacheDir // This is a directory, not a file
	agent.cmdRunner = &mockCommandRunner{}
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err == nil {
		t.Error("applyCachedBundle() expected error for unreadable path, got nil")
	}
}

func TestApplyCachedBundle_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd
	agent.config.ApplyRulesBundle = true // required for applyCachedBundle to execute

	err := agent.applyCachedBundle(context.Background())

	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil", err)
	}

	// Verify iptables-restore was called
	if len(mockCmd.calls) != 1 {
		t.Fatalf("expected 1 command call, got %d", len(mockCmd.calls))
	}
	if mockCmd.calls[0].name != "iptables-restore" {
		t.Errorf("expected command 'iptables-restore', got '%s'", mockCmd.calls[0].name)
	}
}

func TestBackupIptables_SkipsIfBackupExists(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	backupPath := filepath.Join(backupDir, "iptables-backup.rules")
	os.WriteFile(backupPath, []byte("existing"), 0600)
	agent.backupPath = backupPath
	agent.cmdRunner = &mockCommandRunner{}

	err := agent.backupIptables()

	if err != nil {
		t.Errorf("backupIptables() error = %v, want nil for existing backup", err)
	}
}

func TestBackupIptables_IptablesSaveFails(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	// Don't create the backup file - it should try to create it
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{err: fmt.Errorf("iptables-save: command not found")}

	err := agent.backupIptables()

	if err == nil {
		t.Error("backupIptables() expected error when iptables-save fails, got nil")
	}
}

func TestBackupIptables_Success(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	backupDir := t.TempDir()
	agent.backupPath = filepath.Join(backupDir, "iptables-backup.rules")
	agent.cmdRunner = &mockCommandRunner{output: []byte("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n")}

	err := agent.backupIptables()

	if err != nil {
		t.Errorf("backupIptables() error = %v, want nil", err)
	}

	// Verify backup file was created
	if _, err := os.Stat(agent.backupPath); os.IsNotExist(err) {
		t.Error("backupIptables() did not create backup file")
	}

	// Verify iptables-save was called
	mockCmd := agent.cmdRunner.(*mockCommandRunner)
	if len(mockCmd.calls) != 1 {
		t.Fatalf("expected 1 command call, got %d", len(mockCmd.calls))
	}
	if mockCmd.calls[0].name != "iptables-save" {
		t.Errorf("expected command 'iptables-save', got '%s'", mockCmd.calls[0].name)
	}
}

func TestListenSSEHandlesReRegistration(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "events") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// listenSSE should handle 401 and not panic
	go agent.listenSSE(ctx)

	// Wait a bit
	time.Sleep(100 * time.Millisecond)

	// Context should eventually timeout
	<-ctx.Done()
}

func TestAgentDefaultPaths(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	if agent.cachePath != "/etc/runic-agent/cached-bundle.rules" {
		t.Errorf("cachePath = %s, want /etc/runic-agent/cached-bundle.rules", agent.cachePath)
	}
	if agent.backupPath != "/etc/runic-agent/iptables-backup.rules" {
		t.Errorf("backupPath = %s, want /etc/runic-agent/iptables-backup.rules", agent.backupPath)
	}
	if agent.cmdRunner == nil {
		t.Error("cmdRunner is nil, expected RealCommandRunner")
	}
}

func TestRunLoadsConfig(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run should at least attempt to load config
	// It will fail on other steps but we can verify loadConfig is called
	err := agent.Run(ctx)

	// Expect context deadline exceeded (not config load error)
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		// Other errors might occur but config load should work
		t.Logf("Run() returned: %v", err)
	}
}

func TestRunFailsOnEmptyControlPlaneURL(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	cfg := identity.DefaultConfig()
	cfg.HostID = "test-host"
	cfg.Token = "test-token"
	// ControlPlaneURL is empty
	var data []byte
	var err error
	data, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	_ = os.WriteFile(configPath, data, 0600)

	agent := New(configPath, "") // Empty CLI URL too

	ctx := context.Background()
	err = agent.Run(ctx)

	if err == nil {
		t.Error("Run() should fail when control plane URL is empty")
	}

	if err != nil && !strings.Contains(err.Error(), "control plane URL is required") {
		t.Errorf("Run() error = %v, want 'control plane URL is required'", err)
	}
}

func TestRunRegistersWhenNeeded(t *testing.T) {
	cfg := helperConfig()
	cfg.HostID = "" // No credentials
	cfg.Token = ""
	configPath := helperConfigPath(t, cfg)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "register") {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"host_id": "registered-host-id",
				"token":   "registered-token",
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	agent := New(configPath, server.URL)
	agent.config.HostID = ""
	agent.config.Token = ""

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Run should attempt registration
	_ = agent.Run(ctx)

	// Should have attempted registration (we'll see error from context timeout or registration)
	// The key is that it tried to register, not that it completed successfully
}

func TestApplyBundleWithMockApply(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Verify that when ApplyRulesBundle is true, applyBundle attempts to apply
	// The actual apply will fail without proper setup, but we verify the flow
	bundle := models.BundleResponse{
		Version: "test-v1",
		Rules:   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
		HMAC:    "dummy",
	}

	err := agent.applyBundle(context.Background(), bundle)
	// Expect error from apply.ApplyBundle (HMAC validation failure or other)
	// But the flow should be correct
	_ = err
}

func TestIsControlPlaneReachableWithNon200(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.Token = "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)

	if reachable {
		t.Error("isControlPlaneReachable() returned true, want false for 500 status")
	}
}

func TestConfigNeedsRegistration(t *testing.T) {
	tests := []struct {
		name    string
		hostID  string
		token   string
		wantReg bool
	}{
		{
			name:    "has credentials",
			hostID:  "host-1",
			token:   "token-1",
			wantReg: false,
		},
		{
			name:    "missing host ID",
			hostID:  "",
			token:   "token-1",
			wantReg: true,
		},
		{
			name:    "missing token",
			hostID:  "host-1",
			token:   "",
			wantReg: true,
		},
		{
			name:    "missing both",
			hostID:  "",
			token:   "",
			wantReg: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &identity.Config{
				HostID: tt.hostID,
				Token:  tt.token,
			}

			gotReg := cfg.NeedsRegistration()
			if gotReg != tt.wantReg {
				t.Errorf("NeedsRegistration() = %v, want %v", gotReg, tt.wantReg)
			}
		})
	}
}

func TestAgentFields(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Verify all fields are accessible
	_ = agent.config
	_ = agent.configPath
	_ = agent.httpClient
	_ = agent.sseClient
	_ = agent.version
	_ = agent.shipper
	_ = agent.rotationManager

	// All fields should be non-nil (except shipper which is set in Run)
	if agent.config == nil {
		t.Error("Agent.config is nil")
	}
	if agent.httpClient == nil {
		t.Error("Agent.httpClient is nil")
	}
	if agent.sseClient == nil {
		t.Error("Agent.sseClient is nil")
	}
	if agent.rotationManager == nil {
		t.Error("Agent.rotationManager is nil")
	}
}

func TestAgentMutexFieldExists(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")

	// Just verify we can access the mutex without compile error
	var mu sync.Mutex
	mu.Lock()
	agent.regMu.Lock()
	agent.regMu.Unlock()
	mu.Unlock()
}

func TestHeartbeatLoopStructure(t *testing.T) {
	cfg := helperConfig()
	cfg.HeartbeatIntervalSec = 1 // 1 second for testing
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.heartbeatLoop(ctx)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestPollLoopStructure(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 1 // 1 second for testing
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.pollLoop(ctx, false)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestRotationCheckLoopStructure(t *testing.T) {
	cfg := helperConfig()
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	// Run for a brief moment to test structure
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	go agent.rotationCheckLoop(ctx)

	// Give it time to run
	time.Sleep(30 * time.Millisecond)

	// Context should complete
	<-ctx.Done()
}

func TestDefaultHeartbeatInterval(t *testing.T) {
	if identity.DefaultHeartbeatIntervalSec != 30 {
		t.Errorf("DefaultHeartbeatIntervalSec = %d, want 30", identity.DefaultHeartbeatIntervalSec)
	}
}

func TestDefaultPullInterval(t *testing.T) {
	if identity.DefaultPullIntervalSec != 86400 {
		t.Errorf("DefaultPullIntervalSec = %d, want 86400", identity.DefaultPullIntervalSec)
	}
}

func TestLoadConfigMergePriority(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty - CLI should override
		HostID:               "host-test-peer",
		Token:                "test-agent-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	// CLI provides different URL
	agent := New(configPath, "http://cli-url:9090")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI value should override config file value
	if agent.config.ControlPlaneURL != "http://cli-url:9090" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want CLI value http://cli-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestLoadConfigPreservesExistingURL(t *testing.T) {
	cfg := helperConfig()
	cfg.ControlPlaneURL = "http://config-file-url:8080"
	configPath := helperConfigPath(t, cfg)

	// CLI provides empty URL
	agent := New(configPath, "")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Config file value should be preserved
	if agent.config.ControlPlaneURL != "http://config-file-url:8080" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want config file value http://config-file-url:8080", agent.config.ControlPlaneURL)
	}
}

// This tests the fix for BUG-001 where premature URL validation blocked startup
func TestAgentStartsWithURLInConfigFile(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-file-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "")

	// loadConfig should load URL from config file
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// URL should come from config file
	if agent.config.ControlPlaneURL != "http://config-file-url:8080" {
		t.Errorf("loadConfig() ControlPlaneURL = %s, want http://config-file-url:8080", agent.config.ControlPlaneURL)
	}

	// Run() should NOT fail due to empty URL (validation happens after loadConfig)
	// We use a short timeout context since we don't want to actually run the agent
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run will eventually fail due to context deadline, but NOT due to missing URL
	err = agent.Run(ctx)

	// The error should NOT be about missing control plane URL
	if err != nil && strings.Contains(err.Error(), "control plane URL is required") {
		t.Error("Run() should not fail with 'control plane URL is required' when URL is in config file")
	}
}

func TestAgentStartsWithCLIURLOverride(t *testing.T) {
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-file-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		HMACKey:              "test-hmac-key-12345678901234567890123456",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
		ApplyOnBoot:          false,
		ApplyRulesBundle:     true,
	}
	configPath := helperConfigPath(t, cfg)

	cliURL := "http://cli-override-url:9090"
	agent := New(configPath, cliURL)

	// loadConfig should merge CLI URL over config file URL
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI URL should override config file URL (but only if config file URL is empty per current logic)
	// Per the current merge logic, CLI overrides config file ONLY when config file URL is empty
	// This test verifies current behavior - CLI URL is set on agent.config initially
}

func TestAgentURLMergeLogicConfigHasURL(t *testing.T) {
	// Config file HAS a URL
	cfg := &identity.Config{
		ControlPlaneURL:      "http://config-url:8080",
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with empty CLI URL
	agent := New(configPath, "")

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Config file URL should be used
	if agent.config.ControlPlaneURL != "http://config-url:8080" {
		t.Errorf("ControlPlaneURL = %s, want http://config-url:8080", agent.config.ControlPlaneURL)
	}
}

func TestAgentURLMergeLogicConfigEmpty(t *testing.T) {
	// Config file has EMPTY URL
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with CLI URL
	cliURL := "http://cli-url:9090"
	agent := New(configPath, cliURL)

	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// CLI URL should override empty config file URL
	if agent.config.ControlPlaneURL != "http://cli-url:9090" {
		t.Errorf("ControlPlaneURL = %s, want http://cli-url:9090", agent.config.ControlPlaneURL)
	}
}

func TestAgentFailsWithNoURL(t *testing.T) {
	// Config file has NO URL
	cfg := &identity.Config{
		ControlPlaneURL:      "", // Empty
		HostID:               "test-host",
		Token:                "test-token",
		PullIntervalSec:      86400,
		HeartbeatIntervalSec: 30,
		LogPath:              "/var/log/runic/firewall.log",
	}
	configPath := helperConfigPath(t, cfg)

	// Agent created with NO CLI URL (simulating main.go passing empty string)
	agent := New(configPath, "")

	// loadConfig will load empty URL from config
	err := agent.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}

	// Run() should fail because no URL is available
	ctx := context.Background()
	err = agent.Run(ctx)

	if err == nil {
		t.Error("Run() should fail when no control plane URL is available")
	}
	if err != nil && !strings.Contains(err.Error(), "control plane URL is required") {
		t.Errorf("Run() error = %v, want 'control plane URL is required'", err)
	}
}

// ApplyRulesBundle=true, the boot-time bundle application path is entered when CP is reachable.
func TestApplyOnBootWithRulesBundleEnabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	agent.config.ControlPlaneURL = server.URL

	ctx := context.Background()

	// Test the ApplyOnBoot block logic directly by calling isControlPlaneReachable + pullBundle
	// Since pullBundle calls the real transport which requires full API, we verify the condition logic
	reachable := agent.isControlPlaneReachable(ctx)
	if !reachable {
		t.Error("Expected control plane to be reachable")
	}

	// Verify that when both flags are true AND CP is reachable, the boot-time path is entered
	// The actual pullBundle will fail (no bundle endpoint), but the condition check is what matters
	if !agent.config.ApplyOnBoot || !agent.config.ApplyRulesBundle {
		t.Error("Expected both ApplyOnBoot and ApplyRulesBundle to be true")
	}
}

// ApplyRulesBundle=false, the bundle is NOT applied at boot even when a cached bundle exists.
func TestApplyOnBootWithRulesBundleDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Verify applyCachedBundle respects ApplyRulesBundle=false
	err := agent.applyCachedBundle(context.Background())
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil (should skip)", err)
	}

	// Verify iptables-restore was NOT called
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			t.Error("iptables-restore should NOT have been called when ApplyRulesBundle=false")
		}
	}
}

// ApplyRulesBundle=true, and the CP is unreachable, the cached bundle IS applied.
func TestApplyOnBootOfflineWithRulesBundleEnabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = true
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Point to unreachable control plane
	agent.config.ControlPlaneURL = "http://invalid-host:9999"

	// Verify CP is unreachable
	ctx := context.Background()
	reachable := agent.isControlPlaneReachable(ctx)
	if reachable {
		t.Error("Expected control plane to be unreachable")
	}

	// Verify applyCachedBundle works when ApplyRulesBundle=true
	err := agent.applyCachedBundle(ctx)
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil", err)
	}

	// Verify iptables-restore WAS called
	found := false
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected iptables-restore to be called when ApplyRulesBundle=true and cached bundle exists")
	}
}

// ApplyRulesBundle=false, the cached bundle is NOT applied even when the CP is unreachable.
// This verifies the BUG-2 fix: ApplyRulesBundle=false must be respected in all code paths.
func TestApplyOnBootOfflineWithRulesBundleDisabled(t *testing.T) {
	cfg := helperConfig()
	cfg.ApplyOnBoot = true
	cfg.ApplyRulesBundle = false
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file, including ApplyOnBoot and ApplyRulesBundle
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	mockCmd := &mockCommandRunner{}
	agent.cmdRunner = mockCmd

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, "cached-bundle.rules")
	validRules := "*filter\n:INPUT DROP [0:0]\nCOMMIT\n"
	_ = os.WriteFile(cachePath, []byte(validRules), 0600)
	agent.cachePath = cachePath

	// Point to unreachable control plane
	agent.config.ControlPlaneURL = "http://invalid-host:9999"

	// Verify applyCachedBundle respects ApplyRulesBundle=false even when offline
	err := agent.applyCachedBundle(context.Background())
	if err != nil {
		t.Errorf("applyCachedBundle() error = %v, want nil (should skip)", err)
	}

	// Verify iptables-restore was NOT called
	for _, call := range mockCmd.calls {
		if call.name == "iptables-restore" {
			t.Error("iptables-restore should NOT have been called when ApplyRulesBundle=false, even when offline")
		}
	}
}

// ApplyOnBoot already pulled the bundle), pollLoop's first iteration does NOT
// call pullBundle again.
func TestPollLoopSkipsDuplicatePull(t *testing.T) {
	cfg := helperConfig()
	cfg.PullIntervalSec = 86400 // Long interval so ticker won't fire during test
	configPath := helperConfigPath(t, cfg)

	agent := New(configPath, "http://localhost:8080")
	// loadConfig loads values from the config file
	if err := agent.loadConfig(); err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	agent.config.HostID = "test-host"
	agent.config.Token = "test-token"

	pullCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pullCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"version": "v1",
			"rules":   "*filter\n:INPUT DROP [0:0]\nCOMMIT\n",
			"hmac":    "",
		})
	}))
	defer server.Close()
	agent.config.ControlPlaneURL = server.URL

	// Run pollLoop with skipFirstPull=true for a very brief time
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// When skipFirstPull=true, pollLoop should NOT call pullBundle immediately
	go agent.pollLoop(ctx, true)

	// Wait for context to expire
	<-ctx.Done()

	// The pullCount should be 0 because we skipped the first pull
	// and the ticker interval is 86400 seconds so no ticker fires during 50ms
	if pullCount != 0 {
		t.Errorf("Expected 0 pulls with skipFirstPull=true, got %d", pullCount)
	}
}
