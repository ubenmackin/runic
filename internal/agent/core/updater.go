package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"

	"github.com/minio/selfupdate"

	"runic/internal/common/log"
)

// UpdateBinaryPath is the default agent binary location.
// It is a var (not const) so tests can override it to a temp path.
var UpdateBinaryPath = "/usr/local/bin/runic-agent"

// downloadBinary fetches the new agent binary from the control plane.
// The URL pattern is: ${controlPlaneURL}/downloads/runic-agent-${arch}
func downloadBinary(ctx context.Context, client *http.Client, controlPlaneURL, arch string) (io.ReadCloser, error) {
	downloadURL := fmt.Sprintf("%s/downloads/runic-agent-%s", controlPlaneURL, arch)
	req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	req.Header.Set("User-Agent", "runic-agent/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download binary: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", "error", closeErr)
		}
		return nil, fmt.Errorf("download returned status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// performUpdate downloads the new binary and applies it in-place using
// atomic rename swap. After this function returns successfully, the caller
// MUST exit the process so that systemd can restart with the new binary.
func performUpdate(ctx context.Context, client *http.Client, controlPlaneURL string) error {
	log.Info("Downloading agent update", "url", controlPlaneURL, "arch", runtime.GOARCH)

	reader, err := downloadBinary(ctx, client, controlPlaneURL, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			log.Warn("Failed to close download stream", "error", closeErr)
		}
	}()

	opts := selfupdate.Options{
		TargetPath: UpdateBinaryPath,
		// Keep the old binary for rollback if the new version fails to start
		OldSavePath: UpdateBinaryPath + ".old",
	}

	// Check we can write to the target directory
	if err := opts.CheckPermissions(); err != nil {
		return fmt.Errorf("insufficient permissions to update binary (check ReadWritePaths in service file): %w", err)
	}

	log.Info("Applying agent update")
	if err := selfupdate.Apply(reader, opts); err != nil {
		// Try to rollback on failure
		if rollbackErr := selfupdate.RollbackError(err); rollbackErr != nil {
			log.Error("Update failed AND rollback failed", "error", err, "rollback_error", rollbackErr)
			return fmt.Errorf("update failed: %w (rollback also failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("apply update: %w", err)
	}

	log.Info("Agent update applied successfully, exiting for restart")
	return nil
}
