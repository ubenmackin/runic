package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Config holds the agent configuration.
type Config struct {
	ControlPlaneURL  string `json:"control_plane_url"`
	HostID           string `json:"host_id"`
	Token            string `json:"token"`
	PullIntervalSec  int    `json:"pull_interval_seconds"`
	LogPath          string `json:"log_path"`
	CurrentBundleVer string `json:"current_bundle_version"`
	HMACKey          string `json:"hmac_key"`
	ApplyOnBoot      bool   `json:"apply_on_boot"`
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		PullIntervalSec: 30,
		LogPath:         "/var/log/runic/firewall.log",
	}
}

// LoadConfig reads config from the given path.
// If the file does not exist, returns a default config.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the config to disk with 0600 permissions.
// Creates the directory if needed.
func SaveConfig(path string, cfg *Config) error {
	dir := filepath.Dir(path)

	// Ensure directory exists with 0700 permissions
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

// HasCredentials returns true if the config has both host_id and token.
func (c *Config) HasCredentials() bool {
	return c.HostID != "" && c.Token != ""
}

// NeedsRegistration returns true if the agent needs to register.
func (c *Config) NeedsRegistration() bool {
	return !c.HasCredentials()
}
