package core

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/minio/selfupdate"

	sharedarch "runic/internal/common/arch"
	"runic/internal/common/log"
	"runic/internal/common/version"
)

// UpdateBinaryPath is the default agent binary location.
// It is a var (not const) so tests can override it to a temp path.
var UpdateBinaryPath = "/usr/local/bin/runic-agent"

// updateDownloadAttempts is the total number of download attempts including
// the initial try. It is a var so tests can override it to avoid long waits.
var updateDownloadAttempts = 4

// updateRetryDelays holds the backoff between download attempts. Entry i is
// used before retry i+1; when more retries are needed than entries, the last
// entry repeats. Vars so tests can shorten the waits.
var updateRetryDelays = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// archDownloadFilename maps a runtime GOARCH to the whitelisted download
// filename served under the public /downloads path. The canonical arch set
// lives in internal/common/arch (shared with the server-side staged-dir
// freshness check and peer arch validation) so the updater can never drift
// from what the server stages.
func archDownloadFilename(goarch string) (string, error) {
	if filename, ok := sharedarch.FilenameForArch(goarch); ok {
		return filename, nil
	}
	return "", fmt.Errorf("unsupported architecture %q", goarch)
}

// isRetryableUpdateStatus reports whether a download status warrants a retry
// with backoff. Only 429 and 5xx are retried; other 4xx fail fast.
func isRetryableUpdateStatus(code int) bool {
	if code == http.StatusTooManyRequests {
		return true
	}
	return code >= 500 && code <= 599
}

// parseUpdateRetryAfter parses a Retry-After header value, which is either
// delta-seconds or an HTTP date. It returns 0 when the header is missing,
// unparseable, or in the past.
func parseUpdateRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if secs, err := strconv.Atoi(header); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := time.Parse(http.TimeFormat, header); err == nil {
		d := time.Until(t)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}

// parseUpdateRetryAfterPresent parses a Retry-After header value and reports
// whether the header was present and parseable. A present header with value
// "0" or a past date yields (0, true) so callers can honor it as an immediate
// retry instead of falling back to exponential backoff. Missing or
// unparseable headers yield (0, false).
func parseUpdateRetryAfterPresent(header string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return 0, false
	}
	d := parseUpdateRetryAfter(trimmed)
	if d != 0 {
		return d, true
	}
	// d == 0: distinguish present-zero ("0", negative delta, past date)
	// from unparseable input.
	if _, err := strconv.Atoi(trimmed); err == nil {
		return 0, true
	}
	if _, err := time.Parse(http.TimeFormat, trimmed); err == nil {
		return 0, true
	}
	return 0, false
}

// sleepWithUpdateContext sleeps for d or returns early when ctx is done.
func sleepWithUpdateContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// countingReader wraps a download stream and counts bytes read so the update
// path can log the downloaded size after apply without buffering the binary.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// downloadBinary fetches the new agent binary from the control plane.
// The URL pattern is: ${controlPlaneURL}/downloads/${filename} where filename
// is the whitelisted per-arch binary. Retryable statuses (429/5xx) and
// transport errors are retried with backoff, honoring Retry-After when
// present on status retries.
func downloadBinary(ctx context.Context, client *http.Client, controlPlaneURL, arch string) (io.ReadCloser, error) {
	filename, err := archDownloadFilename(arch)
	if err != nil {
		return nil, err
	}
	downloadURL := fmt.Sprintf("%s/downloads/%s", strings.TrimSuffix(controlPlaneURL, "/"), filename)

	attempts := updateDownloadAttempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
		if err != nil {
			return nil, fmt.Errorf("create download request: %w", err)
		}
		req.Header.Set("User-Agent", "runic-agent/"+version.AgentVersion)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("download binary: %w", err)
			if attempt == attempts {
				return nil, lastErr
			}
			if ctx.Err() != nil {
				return nil, lastErr
			}
			delay := updateBackoffDelay(attempt)
			log.Warn("Agent update download retryable, backing off", "attempt", attempt, "error", err, "delay", delay.String())
			if err := sleepWithUpdateContext(ctx, delay); err != nil {
				return nil, fmt.Errorf("download backoff interrupted: %w", err)
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			return resp.Body, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		retryAfter, haveRetryAfter := parseUpdateRetryAfterPresent(resp.Header.Get("Retry-After"))
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn("Failed to close response body", "error", closeErr)
		}
		lastErr = fmt.Errorf("download returned status %d", resp.StatusCode)
		if !isRetryableUpdateStatus(resp.StatusCode) || attempt == attempts {
			return nil, lastErr
		}
		delay := retryAfter
		if !haveRetryAfter {
			delay = updateBackoffDelay(attempt)
		}
		log.Warn("Agent update download retryable, backing off", "attempt", attempt, "status", resp.StatusCode, "delay", delay.String())
		if err := sleepWithUpdateContext(ctx, delay); err != nil {
			return nil, fmt.Errorf("download backoff interrupted: %w", err)
		}
	}
	return nil, lastErr
}

// updateBackoffDelay returns the backoff delay before the next download
// attempt. Entry attempt-1 of updateRetryDelays is used; when more retries
// are needed than entries, the last entry repeats.
func updateBackoffDelay(attempt int) time.Duration {
	idx := attempt - 1
	if idx >= len(updateRetryDelays) {
		idx = len(updateRetryDelays) - 1
	}
	if idx >= 0 && idx < len(updateRetryDelays) {
		return updateRetryDelays[idx]
	}
	return 0
}

// performUpdate downloads the new binary and applies it in-place using
// atomic rename swap. After this function returns successfully, the caller
// MUST exit the process so that systemd can restart with the new binary.
func performUpdate(ctx context.Context, client *http.Client, controlPlaneURL string) error {
	beforeVersion := version.AgentVersion
	arch := runtime.GOARCH
	log.Info("Downloading agent update", "url", controlPlaneURL, "arch", arch, "current_version", beforeVersion)

	reader, err := downloadBinary(ctx, client, controlPlaneURL, arch)
	if err != nil {
		return fmt.Errorf("download update: %w", err)
	}
	defer func() {
		if closeErr := reader.Close(); closeErr != nil {
			log.Warn("Failed to close download stream", "error", closeErr)
		}
	}()
	counting := &countingReader{r: reader}

	opts := selfupdate.Options{
		TargetPath: UpdateBinaryPath,
		// Keep the old binary for rollback if the new version fails to start
		OldSavePath: UpdateBinaryPath + ".old",
	}

	// Check we can write to the target directory
	if err := opts.CheckPermissions(); err != nil {
		return fmt.Errorf("insufficient permissions to update binary (check ReadWritePaths in service file): %w", err)
	}

	log.Info("Applying agent update", "current_version", beforeVersion, "arch", arch)
	if err := selfupdate.Apply(counting, opts); err != nil {
		log.Error("Agent update apply failed", "error", err, "bytes", counting.n, "current_version", beforeVersion)
		// Try to rollback on failure
		if rollbackErr := selfupdate.RollbackError(err); rollbackErr != nil {
			log.Error("Update failed AND rollback failed", "error", err, "rollback_error", rollbackErr)
			return fmt.Errorf("update failed: %w (rollback also failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("apply update: %w", err)
	}

	log.Info("Agent update applied successfully, exiting for restart", "bytes", counting.n, "previous_version", beforeVersion, "arch", arch)
	return nil
}
