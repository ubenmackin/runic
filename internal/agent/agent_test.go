// Package agent provides core device functionality.
package agent

import (
	"testing"

	"runic/internal/agent/core"
	"runic/internal/agent/identity"
)

// TestNewReturnsNonNil tests that New() returns a non-nil Agent.
func TestNewReturnsNonNil(t *testing.T) {
	agent := New("/nonexistent/config.json", "http://localhost:8080")
	if agent == nil {
		t.Error("New() returned nil, expected non-nil agent")
	}
}

// TestNewReturnsProperlyInitializedAgent tests that New() returns a properly initialized Agent.
func TestNewReturnsProperlyInitializedAgent(t *testing.T) {
	agent := New("/tmp/test-config.json", "http://localhost:8080")
	if agent == nil {
		t.Fatal("New() returned nil")
	}

	// We can't directly access internal fields, but we can verify
	// the agent was created without panic and is usable.
	// The actual behavior is tested by core package tests.
}

// TestNewWithEmptyURL tests that New() works with empty control plane URL.
func TestNewWithEmptyURL(t *testing.T) {
	agent := New("/tmp/test-config.json", "")
	if agent == nil {
		t.Error("New() returned nil for empty URL")
	}
}

// TestAgentTypeAlias tests that Agent type alias works correctly.
func TestAgentTypeAlias(t *testing.T) {
	// Create an agent via the agent package
	agent := New("/tmp/test-config.json", "http://localhost:8080")

	// The Agent type should be assignable to core.Agent
	// This tests the type alias works correctly
	var coreAgent *core.Agent = agent

	if coreAgent == nil {
		t.Error("Agent type alias assignment failed")
	}

	// Verify that the agent is the same instance
	if coreAgent != agent {
		t.Error("Type alias should reference the same underlying object")
	}
}

// TestConfigTypeAlias tests that Config type alias works correctly.
func TestConfigTypeAlias(t *testing.T) {
	// Create a config via the agent package
	cfg := &Config{
		ControlPlaneURL: "http://localhost:8080",
		HostID:          "test-host",
		Token:           "test-token",
	}

	// The Config type should be assignable to identity.Config
	// This tests the type alias works correctly
	var identityCfg *identity.Config = cfg

	if identityCfg == nil {
		t.Error("Config type alias assignment failed")
	}

	// Verify that the config is the same instance
	if identityCfg != cfg {
		t.Error("Type alias should reference the same underlying object")
	}

	// Verify fields are accessible
	if identityCfg.ControlPlaneURL != "http://localhost:8080" {
		t.Errorf("Config.ControlPlaneURL = %s, want http://localhost:8080", identityCfg.ControlPlaneURL)
	}
	if identityCfg.HostID != "test-host" {
		t.Errorf("Config.HostID = %s, want test-host", identityCfg.HostID)
	}
	if identityCfg.Token != "test-token" {
		t.Errorf("Config.Token = %s, want test-token", identityCfg.Token)
	}
}

// TestConfigTypeAliasFields tests that Config type alias has all expected fields.
func TestConfigTypeAliasFields(t *testing.T) {
	cfg := &Config{
		ControlPlaneURL:              "http://localhost:8080",
		HostID:                       "host-123",
		Token:                        "token-abc",
		PullIntervalSec:              3600,
		HeartbeatIntervalSec:         30,
		LogPath:                      "/var/log/runic/firewall.log",
		CurrentBundleVer:             "v1.0.0",
		HMACKey:                      "test-hmac-key",
		ApplyOnBoot:                  true,
		ApplyRulesBundle:             true,
		DisableSystemManagedIPTables: true,
	}

	// Verify all fields are accessible via the alias
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"ControlPlaneURL", cfg.ControlPlaneURL, "http://localhost:8080"},
		{"HostID", cfg.HostID, "host-123"},
		{"Token", cfg.Token, "token-abc"},
		{"PullIntervalSec", cfg.PullIntervalSec, 3600},
		{"HeartbeatIntervalSec", cfg.HeartbeatIntervalSec, 30},
		{"LogPath", cfg.LogPath, "/var/log/runic/firewall.log"},
		{"CurrentBundleVer", cfg.CurrentBundleVer, "v1.0.0"},
		{"HMACKey", cfg.HMACKey, "test-hmac-key"},
		{"ApplyOnBoot", cfg.ApplyOnBoot, true},
		{"ApplyRulesBundle", cfg.ApplyRulesBundle, true},
		{"DisableSystemManagedIPTables", cfg.DisableSystemManagedIPTables, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("Config.%s = %v, want %v", tt.name, tt.got, tt.expected)
			}
		})
	}
}

// TestNewWrapperDelegatesToCore tests that New() delegates to core.New().
func TestNewWrapperDelegatesToCore(t *testing.T) {
	configPath := "/tmp/test-config.json"
	controlPlaneURL := "http://localhost:9090"

	// Create agent via agent package
	agentPkgAgent := New(configPath, controlPlaneURL)

	// Create agent via core package
	coreAgent := core.New(configPath, controlPlaneURL)

	// Both should return non-nil
	if agentPkgAgent == nil {
		t.Fatal("agent.New() returned nil")
	}
	if coreAgent == nil {
		t.Fatal("core.New() returned nil")
	}

	// Both should be of the same type (type alias)
	// They should be assignable to each other's type
	var _ *core.Agent = agentPkgAgent
	var _ *Agent = coreAgent
}

// TestNewWithDifferentURLs tests that New() handles various URL formats.
func TestNewWithDifferentURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"localhost http", "http://localhost:8080"},
		{"localhost https", "https://localhost:8443"},
		{"IP address", "http://192.168.1.1:8080"},
		{"domain", "https://control.example.com"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agent := New("/tmp/config.json", tt.url)
			if agent == nil {
				t.Errorf("New() returned nil for URL %q", tt.url)
			}
		})
	}
}

// TestConfigDefaultsFromIdentity tests that Config uses identity package defaults.
func TestConfigDefaultsFromIdentity(t *testing.T) {
	// Verify that default values from identity package are accessible
	// via the type alias
	cfg := &Config{}

	// Test setting defaults like identity.DefaultConfig() would
	cfg.PullIntervalSec = identity.DefaultPullIntervalSec
	cfg.HeartbeatIntervalSec = identity.DefaultHeartbeatIntervalSec

	if cfg.PullIntervalSec != 86400 {
		t.Errorf("DefaultPullIntervalSec = %d, want 86400", cfg.PullIntervalSec)
	}
	if cfg.HeartbeatIntervalSec != 30 {
		t.Errorf("DefaultHeartbeatIntervalSec = %d, want 30", cfg.HeartbeatIntervalSec)
	}
}

// TestConfigMethodsWork tests that Config type alias methods work correctly.
func TestConfigMethodsWork(t *testing.T) {
	tests := []struct {
		name           string
		hostID         string
		token          string
		expectHasCreds bool
		expectNeedReg  bool
	}{
		{
			name:           "has credentials",
			hostID:         "host-123",
			token:          "token-abc",
			expectHasCreds: true,
			expectNeedReg:  false,
		},
		{
			name:           "missing host ID",
			hostID:         "",
			token:          "token-abc",
			expectHasCreds: false,
			expectNeedReg:  true,
		},
		{
			name:           "missing token",
			hostID:         "host-123",
			token:          "",
			expectHasCreds: false,
			expectNeedReg:  true,
		},
		{
			name:           "missing both",
			hostID:         "",
			token:          "",
			expectHasCreds: false,
			expectNeedReg:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				HostID: tt.hostID,
				Token:  tt.token,
			}

			// Test HasCredentials method (inherited from identity.Config)
			hasCreds := cfg.HasCredentials()
			if hasCreds != tt.expectHasCreds {
				t.Errorf("HasCredentials() = %v, want %v", hasCreds, tt.expectHasCreds)
			}

			// Test NeedsRegistration method (inherited from identity.Config)
			needReg := cfg.NeedsRegistration()
			if needReg != tt.expectNeedReg {
				t.Errorf("NeedsRegistration() = %v, want %v", needReg, tt.expectNeedReg)
			}
		})
	}
}
