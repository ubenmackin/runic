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
	"sync"
	"time"

	"runic/internal/common"
	"runic/internal/common/log"
)

type RotationState string

const (
	StateIdle      RotationState = "idle"
	StateRotating  RotationState = "rotating"
	StateTesting   RotationState = "testing"
	StateConfirmed RotationState = "confirmed"
	StateFailed    RotationState = "failed"
	StateFallback  RotationState = "fallback"
)

type Manager struct {
	mu              sync.RWMutex
	configPath      string
	httpClient      *http.Client
	controlPlaneURL string
	hostID          string
	state           RotationState
	oldKey          string
	newKey          string
	lastRotation    time.Time
}

func NewManager(configPath string, httpClient *http.Client, controlPlaneURL string, hostID string) *Manager {
	return &Manager{
		configPath:      configPath,
		httpClient:      httpClient,
		controlPlaneURL: controlPlaneURL,
		hostID:          hostID,
		state:           StateIdle,
	}
}

func (m *Manager) GetState() RotationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.state
}

func (m *Manager) GetLastRotation() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRotation
}

// CheckAndRotate checks for pending key rotation and rotates the HMAC key if needed.
// The currentHMACKey and currentToken are passed in by the caller (Agent) so that
// the Manager does not hold an aliased pointer to the Agent's config, avoiding
// data races between the two components. The new key is returned to the caller
// for atomic persistence under the Agent's own configMu.
func (m *Manager) CheckAndRotate(ctx context.Context, currentHMACKey, currentToken string) (newKey string, err error) {
	m.mu.Lock()
	if m.state == StateRotating || m.state == StateTesting {
		m.mu.Unlock()
		log.Info("Rotation already in progress, skipping")
		return "", nil
	}
	m.state = StateRotating
	m.oldKey = currentHMACKey
	m.mu.Unlock()

	rotationToken, err := m.checkRotationPending(ctx, currentToken)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		return "", fmt.Errorf("check rotation pending: %w", err)
	}

	if rotationToken == "" {
		m.mu.Lock()
		m.state = StateIdle
		m.mu.Unlock()
		return "", nil
	}

	log.Info("Key rotation detected, starting rotation process")

	newKey, err = m.retrieveNewKey(ctx, rotationToken, currentToken)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		log.Error("Failed to retrieve new key, keeping old key", "error", err)
		return "", fmt.Errorf("retrieve new key: %w", err)
	}

	m.mu.Lock()
	m.newKey = newKey
	m.state = StateTesting
	m.mu.Unlock()

	if err := m.testNewKey(ctx, newKey, currentToken); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		m.mu.Unlock()
		log.Error("New key test failed, falling back to old key", "error", err)
		return "", fmt.Errorf("test new key: %w", err)
	}

	if err := m.confirmRotation(ctx, currentToken); err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.mu.Unlock()
		log.Error("Failed to confirm rotation with control plane", "error", err)
		return "", fmt.Errorf("confirm rotation: %w", err)
	}

	m.mu.Lock()
	m.state = StateConfirmed
	m.lastRotation = time.Now()
	m.mu.Unlock()

	log.Info("Key rotation completed successfully")
	return newKey, nil
}

func (m *Manager) checkRotationPending(ctx context.Context, token string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/check-rotation", m.controlPlaneURL)
	resp, err := common.DoJSONRequest(ctx, m.httpClient, "GET", url, nil, token, "runic-agent")
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

func (m *Manager) retrieveNewKey(ctx context.Context, rotationToken string, authToken string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/rotate-key", m.controlPlaneURL)

	body := map[string]string{
		"host_id":        m.hostID,
		"rotation_token": rotationToken,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, authToken, "runic-agent")
	if err != nil {
		return "", fmt.Errorf("retrieve new key: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close body failed", "error", cErr)
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

func (m *Manager) testNewKey(ctx context.Context, key string, token string) error {
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

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, token, "runic-agent")
	if err != nil {
		return fmt.Errorf("key test failed: %w", err)
	}
	defer func() {
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("close body failed", "error", cErr)
		}
	}()

	return nil
}

func (m *Manager) confirmRotation(ctx context.Context, token string) error {
	url := fmt.Sprintf("%s/api/v1/agent/confirm-rotation", m.controlPlaneURL)

	body := map[string]string{
		"host_id": m.hostID,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, token, "runic-agent")
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
