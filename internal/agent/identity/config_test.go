package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.PullIntervalSec != DefaultPullIntervalSec {
		t.Errorf("expected PullIntervalSec=%d, got %d", DefaultPullIntervalSec, cfg.PullIntervalSec)
	}

	if cfg.HeartbeatIntervalSec != DefaultHeartbeatIntervalSec {
		t.Errorf("expected HeartbeatIntervalSec=%d, got %d", DefaultHeartbeatIntervalSec, cfg.HeartbeatIntervalSec)
	}

	if cfg.LogPath != "/var/log/runic/firewall.log" {
		t.Errorf("expected LogPath=%s, got %s", "/var/log/runic/firewall.log", cfg.LogPath)
	}

	if cfg.ApplyOnBoot != false {
		t.Errorf("expected ApplyOnBoot=false, got %v", cfg.ApplyOnBoot)
	}

	if cfg.ApplyRulesBundle != false {
		t.Errorf("expected ApplyRulesBundle=false, got %v", cfg.ApplyRulesBundle)
	}
}

func TestLoadConfigFileNotExist(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.json")

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if cfg == nil {
		t.Fatal("expected default config, got nil")
	}

	if cfg.PullIntervalSec != DefaultPullIntervalSec {
		t.Errorf("expected default PullIntervalSec=%d, got %d", DefaultPullIntervalSec, cfg.PullIntervalSec)
	}
}

func TestLoadConfigValidFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	testCfg := &Config{
		ControlPlaneURL:      "https://control.example.com",
		HostID:               "host-123",
		Token:                "secret-token",
		PullIntervalSec:      3600,
		HeartbeatIntervalSec: 15,
		LogPath:              "/tmp/test.log",
		CurrentBundleVer:     "v1.0.0",
		HMACKey:              "hmac-secret",
		ApplyOnBoot:          true,
		ApplyRulesBundle:     true,
	}

	data, err := json.Marshal(testCfg)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}

	if _, err := tmpFile.Write(data); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	cfg, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if cfg.ControlPlaneURL != testCfg.ControlPlaneURL {
		t.Errorf("expected ControlPlaneURL=%s, got %s", testCfg.ControlPlaneURL, cfg.ControlPlaneURL)
	}

	if cfg.HostID != testCfg.HostID {
		t.Errorf("expected HostID=%s, got %s", testCfg.HostID, cfg.HostID)
	}

	if cfg.Token != testCfg.Token {
		t.Errorf("expected Token=%s, got %s", testCfg.Token, cfg.Token)
	}

	if cfg.PullIntervalSec != testCfg.PullIntervalSec {
		t.Errorf("expected PullIntervalSec=%d, got %d", testCfg.PullIntervalSec, cfg.PullIntervalSec)
	}

	if cfg.HeartbeatIntervalSec != testCfg.HeartbeatIntervalSec {
		t.Errorf("expected HeartbeatIntervalSec=%d, got %d", testCfg.HeartbeatIntervalSec, cfg.HeartbeatIntervalSec)
	}
}

func TestLoadConfigInvalidJSON(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "config-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.WriteString("not valid json{{{"); err != nil {
		t.Fatalf("failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	_, err = LoadConfig(tmpFile.Name())
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

func TestLoadConfigUnreadableFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tmpFile := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(tmpFile, []byte("{}"), 0644); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	// Remove read permissions
	if err := os.Chmod(tmpFile, 0000); err != nil {
		t.Fatalf("failed to change permissions: %v", err)
	}
	defer func() { _ = os.Chmod(tmpFile, 0644) }()

	_, err = LoadConfig(tmpFile)
	if err == nil {
		t.Error("expected error for unreadable file, got nil")
	}
}

func TestSaveConfigCreatesDirectory(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "subdir", "nested")
	configPath := filepath.Join(subDir, "config.json")

	cfg := DefaultConfig()
	cfg.HostID = "test-host"
	cfg.Token = "test-token"

	err = SaveConfig(configPath, cfg)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(subDir)
	if err != nil {
		t.Errorf("expected directory to exist, got error: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected path to be a directory")
	}

	// Verify file was created
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Errorf("expected file to exist, got error: %v", err)
	}

	var savedCfg Config
	if err := json.Unmarshal(data, &savedCfg); err != nil {
		t.Errorf("failed to unmarshal saved config: %v", err)
	}

	if savedCfg.HostID != cfg.HostID {
		t.Errorf("expected HostID=%s, got %s", cfg.HostID, savedCfg.HostID)
	}
}

func TestSaveConfigFilePermissions(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test-config-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	configPath := filepath.Join(tmpDir, "config.json")

	cfg := DefaultConfig()

	err = SaveConfig(configPath, cfg)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	info, err := os.Stat(configPath)
	if err != nil {
		t.Errorf("expected file to exist, got error: %v", err)
	}

	// File should have 0600 permissions
	expectedPerm := os.FileMode(0600)
	if info.Mode().Perm() != expectedPerm {
		t.Errorf("expected file permissions %o, got %o", expectedPerm, info.Mode().Perm())
	}
}

func TestSaveConfigInvalidPath(t *testing.T) {
	// Try to save to a path where the parent is a file, not a directory
	tmpFile, err := os.CreateTemp("", "test-")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	configPath := tmpFile.Name() + "/config.json"

	cfg := DefaultConfig()

	err = SaveConfig(configPath, cfg)
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestHasCredentials(t *testing.T) {
	tests := []struct {
		name   string
		hostID string
		token  string
		want   bool
	}{
		{
			name:   "both set",
			hostID: "host-123",
			token:  "token-abc",
			want:   true,
		},
		{
			name:   "only hostID set",
			hostID: "host-123",
			token:  "",
			want:   false,
		},
		{
			name:   "only token set",
			hostID: "",
			token:  "token-abc",
			want:   false,
		},
		{
			name:   "neither set",
			hostID: "",
			token:  "",
			want:   false,
		},
		{
			name:   "both empty strings",
			hostID: "",
			token:  "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				HostID: tt.hostID,
				Token:  tt.token,
			}

			got := cfg.HasCredentials()
			if got != tt.want {
				t.Errorf("HasCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNeedsRegistration(t *testing.T) {
	tests := []struct {
		name   string
		hostID string
		token  string
		want   bool
	}{
		{
			name:   "no credentials - needs registration",
			hostID: "",
			token:  "",
			want:   true,
		},
		{
			name:   "only hostID - needs registration",
			hostID: "host-123",
			token:  "",
			want:   true,
		},
		{
			name:   "only token - needs registration",
			hostID: "",
			token:  "token-abc",
			want:   true,
		},
		{
			name:   "has credentials - does not need registration",
			hostID: "host-123",
			token:  "token-abc",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				HostID: tt.hostID,
				Token:  tt.token,
			}

			got := cfg.NeedsRegistration()
			if got != tt.want {
				t.Errorf("NeedsRegistration() = %v, want %v", got, tt.want)
			}
		})
	}
}
