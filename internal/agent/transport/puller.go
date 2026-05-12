// Package transport handles agent communication.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"runic/internal/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/models"
)

// sseCallbackGuard prevents concurrent execution of SSE callback goroutines.
// When the SSE connection dies and reconnects, a new set of goroutines may be
// spawned before the old ones finish. The guard ensures at most one invocation
// of each callback is running at a time, skipping additional launches and
// canceling any in-flight work via context cancellation.
type sseCallbackGuard struct {
	running  atomic.Bool
	cancelMu sync.Mutex
	cancel   context.CancelFunc
}

// tryStart attempts to start a guarded goroutine. It returns false (and does
// nothing) if a previous invocation is still running.
func (g *sseCallbackGuard) tryStart(ctx context.Context, fn func(context.Context)) bool {
	if g.running.Load() {
		log.Warn("SSE callback already running, skipping duplicate launch")
		return false
	}

	// Cancel any previous invocation's derived context before starting a new one.
	g.cancelMu.Lock()
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	g.cancelMu.Unlock()

	childCtx, childCancel := context.WithCancel(ctx)
	g.cancelMu.Lock()
	g.cancel = childCancel
	g.cancelMu.Unlock()

	g.running.Store(true)
	go func() {
		defer g.running.Store(false)
		fn(childCtx)
		childCancel()
	}()
	return true
}

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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusOK:
	default:
		return &common.HTTPStatusError{StatusCode: resp.StatusCode, Method: "GET", URL: url}
	}

	var bundle models.BundleResponse
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		return fmt.Errorf("decode bundle: %w", err)
	}

	return applyFunc(ctx, bundle)
}

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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return &common.HTTPStatusError{StatusCode: resp.StatusCode, Method: "POST", URL: url}
	}

	return nil
}

// ListenSSE listens for SSE events from the control plane. Returns ErrUnauthorized if a 401 response is received, allowing the caller to trigger re-registration.
func ListenSSE(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, onBundleUpdate func(context.Context), onFetchBackup func(context.Context), onUpdateAgent func(context.Context, string)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := connectSSE(ctx, client, controlPlaneURL, hostID, token, version, onBundleUpdate, onFetchBackup, onUpdateAgent); err != nil {
			log.Warn("SSE connection lost, reconnecting", "error", err, "delay", "15s")
			if errors.Is(err, common.ErrUnauthorized) {
				log.Warn("Received 401 on SSE connection, signaling for re-registration")
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(constants.SSEReconnectDelay):
			}
		}
	}
}

func connectSSE(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, onBundleUpdate func(context.Context), onFetchBackup func(context.Context), onUpdateAgent func(context.Context, string)) error {
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return &common.HTTPStatusError{StatusCode: resp.StatusCode, Method: "GET", URL: url}
	}

	reader := resp.Body
	scanner := bufio.NewScanner(reader)

	const maxScanTokenSize = 1024 * 1024
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)

	// Guards to prevent goroutine leaks on SSE reconnect.
	var bundleGuard, backupGuard sseCallbackGuard

	var prevEvent string
	for scanner.Scan() {
		line := scanner.Text()
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Track event type across lines since SSE sends event: and data: separately
		switch {
		case strings.HasPrefix(line, "event: bundle_updated"):
			log.Info("SSE: bundle_updated received, pulling immediately")
			prevEvent = "bundle_updated"
			bundleGuard.tryStart(ctx, onBundleUpdate)
		case strings.HasPrefix(line, "event: fetch_backup"):
			log.Info("SSE: fetch_backup received, reading backup")
			prevEvent = "fetch_backup"
			backupGuard.tryStart(ctx, onFetchBackup)
		case strings.HasPrefix(line, "event: update_agent"):
			log.Info("SSE: update_agent received, starting self-update")
			prevEvent = "update_agent"
		case strings.HasPrefix(line, "data:") && prevEvent == "update_agent":
			var data struct {
				ControlPlaneURL string `json:"control_plane_url"`
			}
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &data); err == nil {
				go onUpdateAgent(ctx, data.ControlPlaneURL)
			}
			prevEvent = "" // Reset after processing data
		case strings.HasPrefix(line, "data:"):
			// Data line for other events - just reset prevEvent
			prevEvent = ""
		}

		if len(line) > 0 && line[0] == ':' {
			continue
		}
	}

	return scanner.Err()
}
