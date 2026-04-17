// Package rotation handles HMAC key rotation.
package rotation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"runic/internal/agent/identity"
	"runic/internal/common"
	"runic/internal/common/log"
)

// RotationState tracks the current rotation status.
type RotationState string

const (
	StateIdle      RotationState = "idle"
	StateRotating  RotationState = "rotating"
	StateTesting   RotationState = "testing"
	StateConfirmed RotationState = "confirmed"
	StateFailed    RotationState = "failed"
	StateFallback  RotationState = "fallback"
)

// Manager handles HMAC key rotation for the agent.
type Manager struct {
	mu              sync.RWMutex
	config          *identity.Config
	configPath      string
	httpClient      *http.Client
	controlPlaneURL string
	hostID          string
	state           RotationState
	oldKey          string
	newKey          string
	lastRotation    time.Time
}

// NewManager creates a new rotation manager.
func NewManager(config *identity.Config, configPath string, httpClient *http.Client, controlPlaneURL string, hostID string) *Manager {
	return &Manager{
		config:          config,
		configPath:      configPath,
		httpClient:      httpClient,
		controlPlaneURL: controlPlaneURL,
		hostID:          hostID,
		state:           StateIdle,
	}
}

// GetState returns the current rotation state.
func (m *Manager) GetState() RotationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

// GetLastRotation returns the time of the last successful rotation.
func (m *Manager) GetLastRotation() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRotation
}

// CheckAndRotate checks if a rotation is pending and performs it if so.
// This method uses fine-grained locking to avoid holding the mutex during HTTP calls.
func (m *Manager) CheckAndRotate(ctx context.Context) error {
	m.mu.Lock()
	if m.state == StateRotating || m.state == StateTesting {
		m.mu.Unlock()
		log.Info("Rotation already in progress, skipping")
		return nil
	}
	m.state = StateRotating
	m.oldKey = m.config.HMACKey
	m.mu.Unlock()

	rotationToken, err := m.checkRotationPending(ctx)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		return fmt.Errorf("check rotation pending: %w", err)
	}

	if rotationToken == "" {
		m.mu.Lock()
		m.state = StateIdle
		m.mu.Unlock()
		return nil
	}

	log.Info("Key rotation detected, starting rotation process")

	newKey, err := m.retrieveNewKey(ctx, rotationToken)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		log.Error("Failed to retrieve new key, keeping old key", "error", err)
		return fmt.Errorf("retrieve new key: %w", err)
	}

	m.mu.Lock()
	m.newKey = newKey
	m.state = StateTesting
	m.mu.Unlock()

	if err := m.testNewKey(ctx, newKey); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		m.mu.Unlock()
		log.Error("New key test failed, falling back to old key", "error", err)
		return fmt.Errorf("test new key: %w", err)
	}

	if err := m.updateConfigKey(newKey); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		m.mu.Unlock()
		log.Error("Failed to update config with new key, falling back", "error", err)
		return fmt.Errorf("update config: %w", err)
	}

	m.mu.Lock()
	m.config.HMACKey = newKey
	m.mu.Unlock()

	if err := m.confirmRotation(ctx); err != nil {
		log.Warn("Failed to confirm rotation with control plane", "error", err)
		// Don't fail here - the key is already updated locally
	}

	m.mu.Lock()
	m.state = StateConfirmed
	m.lastRotation = time.Now()
	m.mu.Unlock()

	log.Info("Key rotation completed successfully")
	return nil
}

// checkRotationPending checks if a rotation token is available.
func (m *Manager) checkRotationPending(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/check-rotation", m.controlPlaneURL)
	resp, err := common.DoJSONRequest(ctx, m.httpClient, "GET", url, nil, m.config.Token, "runic-agent")
	if err != nil {
		var httpErr *common.HTTPStatusError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusNotFound {
				return "", nil
			}
		}
		return "", err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode == http.StatusNoContent {
		return "", nil
	}

	var result struct {
		RotationToken string `json:"rotation_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	return result.RotationToken, nil
}

// retrieveNewKey retrieves the new HMAC key using the rotation token.
func (m *Manager) retrieveNewKey(ctx context.Context, token string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/rotate-key", m.controlPlaneURL)

	body := map[string]string{
		"host_id":        m.hostID,
		"rotation_token": token,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, "", "runic-agent")
	if err != nil {
		return "", fmt.Errorf("retrieve new key: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			fmt.Printf("close err: %v\n", cErr)
		}
	}()

	var result struct {
		NewHMACKey string `json:"new_hmac_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	if result.NewHMACKey == "" {
		return "", fmt.Errorf("received empty HMAC key")
	}

	return result.NewHMACKey, nil
}

// testNewKey verifies the new key works by making a test request.
func (m *Manager) testNewKey(ctx context.Context, key string) error {
	testMessage := fmt.Sprintf("test-%d", time.Now().UnixNano())
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(testMessage))
	signature := hex.EncodeToString(mac.Sum(nil))

	url := fmt.Sprintf("%s/api/v1/agent/test-key", m.controlPlaneURL)

	body := map[string]string{
		"host_id":   m.hostID,
		"message":   testMessage,
		"signature": signature,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, m.config.Token, "runic-agent")
	if err != nil {
		return fmt.Errorf("key test failed: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			fmt.Printf("close err: %v\n", cErr)
		}
	}()

	return nil
}

// updateConfigKey atomically updates the HMAC key in the config file.
func (m *Manager) updateConfigKey(newKey string) error {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg identity.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	cfg.HMACKey = newKey

	dir := filepath.Dir(m.configPath)
	tmpFile, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cfg); err != nil {
		if cErr := tmpFile.Close(); cErr != nil {
			log.Warn("Failed to close file", "error", cErr)
		}
		if rErr := os.Remove(tmpPath); rErr != nil {
			log.Warn("Failed to remove file", "error", rErr)
		}
		return fmt.Errorf("write config: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		if cErr := tmpFile.Close(); cErr != nil {
			log.Warn("Failed to close file", "error", cErr)
		}
		if rErr := os.Remove(tmpPath); rErr != nil {
			log.Warn("Failed to remove file", "error", rErr)
		}
		return fmt.Errorf("sync config: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		if rErr := os.Remove(tmpPath); rErr != nil {
			log.Warn("Failed to remove file", "error", rErr)
		}
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, m.configPath); err != nil {
		if rErr := os.Remove(tmpPath); rErr != nil {
			log.Warn("Failed to remove file", "error", rErr)
		}
		return fmt.Errorf("rename config: %w", err)
	}

	if err := os.Chmod(m.configPath, 0600); err != nil {
		return fmt.Errorf("chmod config: %w", err)
	}

	return nil
}

// confirmRotation notifies the control plane that rotation is complete.
func (m *Manager) confirmRotation(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/v1/agent/confirm-rotation", m.controlPlaneURL)

	body := map[string]string{
		"host_id": m.hostID,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, "", "runic-agent")
	if err != nil {
		return fmt.Errorf("confirm rotation failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	return nil
}
