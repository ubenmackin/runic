package rotation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"runic/internal/agent/identity"
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

// CheckAndRotate checks if a rotation is pending and performs it if so.
// This method uses fine-grained locking to avoid holding the mutex during HTTP calls.
func (m *Manager) CheckAndRotate() error {
	// Phase 1: Check if we should start a rotation (under lock)
	m.mu.Lock()
	if m.state == StateRotating || m.state == StateTesting {
		m.mu.Unlock()
		log.Info("Rotation already in progress, skipping")
		return nil
	}
	m.state = StateRotating
	m.oldKey = m.config.HMACKey
	m.mu.Unlock()

	// Phase 2: Check for pending rotation (HTTP call - no lock held)
	rotationToken, err := m.checkRotationPending()
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		return fmt.Errorf("check rotation pending: %w", err)
	}

	if rotationToken == "" {
		// No rotation pending, revert state
		m.mu.Lock()
		m.state = StateIdle
		m.mu.Unlock()
		return nil
	}

	log.Info("Key rotation detected, starting rotation process")

	// Phase 3: Retrieve new key (HTTP call - no lock held)
	newKey, err := m.retrieveNewKey(rotationToken)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		log.Error("Failed to retrieve new key, keeping old key", "error", err)
		return fmt.Errorf("retrieve new key: %w", err)
	}

	// Phase 4: Test the new key (HTTP call - no lock held)
	m.mu.Lock()
	m.newKey = newKey
	m.state = StateTesting
	m.mu.Unlock()

	if err := m.testNewKey(newKey); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		m.mu.Unlock()
		log.Error("New key test failed, falling back to old key", "error", err)
		return fmt.Errorf("test new key: %w", err)
	}

	// Phase 5: Update config file (I/O - no lock held)
	if err := m.updateConfigKey(newKey); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		m.mu.Unlock()
		log.Error("Failed to update config with new key, falling back", "error", err)
		return fmt.Errorf("update config: %w", err)
	}

	// Phase 6: Update in-memory config and confirm (under lock briefly)
	m.mu.Lock()
	m.config.HMACKey = newKey
	m.mu.Unlock()

	// Phase 7: Confirm rotation (HTTP call - no lock held)
	if err := m.confirmRotation(); err != nil {
		log.Warn("Failed to confirm rotation with control plane", "error", err)
		// Don't fail here - the key is already updated locally
	}

	// Phase 8: Mark as confirmed (under lock briefly)
	m.mu.Lock()
	m.state = StateConfirmed
	m.lastRotation = time.Now()
	m.mu.Unlock()

	log.Info("Key rotation completed successfully")
	return nil
}

// checkRotationPending checks if a rotation token is available.
func (m *Manager) checkRotationPending() (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/check-rotation", m.controlPlaneURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+m.config.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		// No rotation pending
		return "", nil
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
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
func (m *Manager) retrieveNewKey(token string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/rotate-key", m.controlPlaneURL)

	body := map[string]string{
		"host_id":        m.hostID,
		"rotation_token": token,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

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
func (m *Manager) testNewKey(key string) error {
	// Create a test message and sign it with the new key
	testMessage := fmt.Sprintf("test-%d", time.Now().UnixNano())
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(testMessage))
	signature := hex.EncodeToString(mac.Sum(nil))

	// Send test request to control plane to verify key
	url := fmt.Sprintf("%s/api/v1/agent/test-key", m.controlPlaneURL)

	body := map[string]string{
		"host_id":   m.hostID,
		"message":   testMessage,
		"signature": signature,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.config.Token)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("key test failed with status: %d", resp.StatusCode)
	}

	return nil
}

// updateConfigKey atomically updates the HMAC key in the config file.
func (m *Manager) updateConfigKey(newKey string) error {
	// Read current config
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfg identity.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	// Update HMAC key
	cfg.HMACKey = newKey

	// Write to temp file first (atomic write pattern)
	dir := filepath.Dir(m.configPath)
	tmpFile, err := os.CreateTemp(dir, "config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	encoder := json.NewEncoder(tmpFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(cfg); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write config: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, m.configPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename config: %w", err)
	}

	// Set permissions
	if err := os.Chmod(m.configPath, 0600); err != nil {
		return fmt.Errorf("chmod config: %w", err)
	}

	return nil
}

// confirmRotation notifies the control plane that rotation is complete.
func (m *Manager) confirmRotation() error {
	url := fmt.Sprintf("%s/api/v1/agent/confirm-rotation", m.controlPlaneURL)

	body := map[string]string{
		"host_id": m.hostID,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("confirm rotation failed with status: %d", resp.StatusCode)
	}

	return nil
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
