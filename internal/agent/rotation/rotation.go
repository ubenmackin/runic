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
	"io"
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
	mu           sync.RWMutex
	httpClient   *http.Client
	state        RotationState
	oldKey       string
	newKey       string
	lastRotation time.Time
}

func NewManager(httpClient *http.Client) *Manager {
	return &Manager{
		httpClient: httpClient,
		state:      StateIdle,
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
// The currentHMACKey, currentToken, controlPlaneURL, and hostID are passed in
// by the caller (Agent) from a single getConfig snapshot so all credentials
// come from the same generation; the Manager must not mix a caller-supplied
// token with URL/hostID snapshotted separately under mu, which would tear
// across a concurrent re-registration. The Manager does not hold an aliased
// pointer to the Agent's config, avoiding data races between the two
// components. The new key is returned to the caller for atomic persistence
// under the Agent's own configMu.
func (m *Manager) CheckAndRotate(ctx context.Context, currentHMACKey, currentToken, controlPlaneURL, hostID string) (newKey string, err error) {
	m.mu.Lock()
	if m.state == StateRotating || m.state == StateTesting {
		m.mu.Unlock()
		log.Info("Rotation already in progress, skipping")
		return "", nil
	}
	m.state = StateRotating
	m.oldKey = currentHMACKey
	m.mu.Unlock()

	rotationToken, err := m.checkRotationPending(ctx, currentToken, controlPlaneURL)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.oldKey = ""
		m.newKey = ""
		m.mu.Unlock()
		return "", fmt.Errorf("check rotation pending: %w", err)
	}

	if rotationToken == "" {
		m.mu.Lock()
		m.state = StateIdle
		m.oldKey = ""
		m.newKey = ""
		m.mu.Unlock()
		return "", nil
	}

	log.Info("Key rotation detected, starting rotation process")

	newKey, err = m.retrieveNewKey(ctx, rotationToken, currentToken, controlPlaneURL, hostID)
	if err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.oldKey = ""
		m.newKey = ""
		m.mu.Unlock()
		log.Error("Failed to retrieve new key, keeping old key", "error", err)
		return "", fmt.Errorf("retrieve new key: %w", err)
	}

	m.mu.Lock()
	m.newKey = newKey
	m.state = StateTesting
	m.mu.Unlock()

	if err := m.testNewKey(ctx, newKey, currentToken, controlPlaneURL, hostID); err != nil {
		m.mu.Lock()
		m.state = StateFallback
		// Drop the untested key; oldKey remains the fallback key.
		m.newKey = ""
		m.mu.Unlock()
		log.Error("New key test failed, falling back to old key", "error", err)
		return "", fmt.Errorf("test new key: %w", err)
	}

	if err := m.confirmRotation(ctx, currentToken, controlPlaneURL, hostID); err != nil {
		m.mu.Lock()
		m.state = StateFailed
		m.oldKey = ""
		m.newKey = ""
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

func (m *Manager) checkRotationPending(ctx context.Context, token, controlPlaneURL string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/check-rotation", controlPlaneURL)
	resp, err := common.DoJSONRequest(ctx, m.httpClient, "GET", url, nil, token, "runic-agent")
	if err != nil {
		var httpErr *common.HTTPStatusError
		if errors.As(err, &httpErr) {
			if httpErr.StatusCode == http.StatusNotFound {
				return "", nil
			}
		}
		return "", fmt.Errorf("check rotation pending: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
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
		return "", fmt.Errorf("decode rotation check response: %w", err)
	}

	return result.RotationToken, nil
}

func (m *Manager) retrieveNewKey(ctx context.Context, rotationToken string, authToken string, controlPlaneURL, hostID string) (string, error) {
	url := fmt.Sprintf("%s/api/v1/agent/rotate-key", controlPlaneURL)

	body := map[string]string{
		"host_id":        hostID,
		"rotation_token": rotationToken,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, authToken, "runic-agent")
	if err != nil {
		return "", fmt.Errorf("retrieve new key: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("Failed to close response body", "error", cErr)
		}
	}()

	var result struct {
		NewHMACKey string `json:"new_hmac_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode rotate key response: %w", err)
	}

	if result.NewHMACKey == "" {
		return "", fmt.Errorf("received empty HMAC key")
	}

	return result.NewHMACKey, nil
}

func (m *Manager) testNewKey(ctx context.Context, key string, token string, controlPlaneURL, hostID string) error {
	testMessage := fmt.Sprintf("test-%d", time.Now().UnixNano())
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(testMessage))
	signature := hex.EncodeToString(mac.Sum(nil))

	url := fmt.Sprintf("%s/api/v1/agent/test-key", controlPlaneURL)

	body := map[string]string{
		"host_id":   hostID,
		"message":   testMessage,
		"signature": signature,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, token, "runic-agent")
	if err != nil {
		return fmt.Errorf("key test failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if cErr := resp.Body.Close(); cErr != nil {
			log.Warn("Failed to close response body", "error", cErr)
		}
	}()

	return nil
}

func (m *Manager) confirmRotation(ctx context.Context, token string, controlPlaneURL, hostID string) error {
	url := fmt.Sprintf("%s/api/v1/agent/confirm-rotation", controlPlaneURL)

	body := map[string]string{
		"host_id": hostID,
	}

	resp, err := common.DoJSONRequest(ctx, m.httpClient, "POST", url, body, token, "runic-agent")
	if err != nil {
		return fmt.Errorf("confirm rotation failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	return nil
}
