package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/models"
)

// PullBundle fetches the latest bundle from the control plane.
func PullBundle(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, currentBundleVer, version string, applyFunc func(context.Context, models.BundleResponse) error) error {
	url := fmt.Sprintf("%s/api/v1/agent/bundle/%s", controlPlaneURL, hostID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)
	if currentBundleVer != "" {
		req.Header.Set("If-None-Match", currentBundleVer)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("bundle fetch: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// No change — nothing to do
		return nil
	case http.StatusOK:
		// Continue to process bundle
	default:
		return fmt.Errorf("bundle fetch returned %d", resp.StatusCode)
	}

	var bundle models.BundleResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}

	return applyFunc(ctx, bundle)
}

// ConfirmApply notifies the control plane that a bundle was applied.
func ConfirmApply(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, bundleVersion string) error {
	body := map[string]string{
		"version":    bundleVersion,
		"applied_at": time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal confirm request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/agent/bundle/%s/applied", controlPlaneURL, hostID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("confirm apply: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("confirm apply returned %d", resp.StatusCode)
	}

	return nil
}

// ListenSSE maintains a persistent SSE connection to receive push notifications.
func ListenSSE(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, onBundleUpdate func(context.Context)) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := connectSSE(ctx, client, controlPlaneURL, hostID, token, version, onBundleUpdate); err != nil {
			log.Warn("SSE connection lost, reconnecting", "error", err, "delay", "15s")
			select {
			case <-ctx.Done():
				return
			case <-time.After(constants.SSEReconnectDelay):
				// Continue to reconnect
			}
		}
	}
}

// connectSSE establishes a single SSE connection.
func connectSSE(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, onBundleUpdate func(context.Context)) error {
	url := fmt.Sprintf("%s/api/v1/agent/events/%s", controlPlaneURL, hostID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create SSE request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("User-Agent", "runic-agent/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("SSE connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SSE returned status %d", resp.StatusCode)
	}

	reader := resp.Body
	scanner := bufio.NewScanner(reader)

	// Increase scanner buffer size for SSE
	const maxScanTokenSize = 1024 * 1024
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	for scanner.Scan() {
		line := scanner.Text()

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if strings.HasPrefix(line, "event: bundle_updated") {
			log.Info("SSE: bundle_updated received, pulling immediately")
			go onBundleUpdate(ctx)
		}

		// Keepalive comments: ": keepalive" or similar
		if strings.HasPrefix(line, ":") {
			continue
		}
	}

	return scanner.Err()
}
