// Package apply provides the application applier.
package apply

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/engine"
	"runic/internal/models"
)

const (
	// LocalBackupPath is the persistent path where pre-apply firewall rules
	// are written so that a crash mid-apply does not lose the backup.
	LocalBackupPath = "/etc/runic-agent/pre-apply-backup.rules"
)

// IsNftFormat returns true when the content looks like nftables ruleset
// (starts with "table" rather than containing "*filter").
func IsNftFormat(content string) bool {
	return strings.Contains(content, "table ") && !strings.Contains(content, "*filter")
}

// ApplyBundle uses the confirmFunc callback to notify the control plane after successful apply.
func ApplyBundle(ctx context.Context, bundle models.BundleResponse, hmacKey, controlPlaneURL, token, version string, confirmFunc func(context.Context, string) error) error {
	log.Info("Received bundle version, verifying HMAC", "version", bundle.Version)

	if !engine.VerifyWithVersion(bundle.Rules, hmacKey, bundle.HMAC, bundle.VersionNumber) {
		return fmt.Errorf("HMAC verification failed — refusing to apply bundle %s", bundle.Version)
	}

	if err := validateRules(bundle.Rules); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	backup, err := dumpCurrentRules()
	if err != nil {
		return fmt.Errorf("could not dump current rules for backup: %w", err)
	}

	// Persist backup to disk BEFORE any state modification so crash mid-apply
	// does not lose the ability to restore.
	if err := persistBackup(backup); err != nil {
		log.Warn("Failed to persist backup to disk", "error", err)
	}

	revertCancel := scheduleRevert(backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// Write bundle to temp file BEFORE flushing so the restore payload is ready
	// and the unprotected window between flush and restore is minimized.
	tmpPath, err := writeTempFile("runic-bundle-*.rules", stripIpsetSection(bundle.Rules))
	if err != nil {
		revertCancel()
		return fmt.Errorf("write bundle: %w", err)
	}
	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("Failed to remove temp file", "path", tmpPath, "error", err)
		}
	}()

	// Flush iptables FIRST to release ipset references before destroying ipsets
	// This prevents "ipset in use" errors during ipset recreate
	if err := flushIPTables(ctx); err != nil {
		revertCancel()
		return fmt.Errorf("flush firewall: %w", err)
	}

	// Apply ipset definitions if present (after iptables flushed - can now destroy safely)
	if strings.Contains(bundle.Rules, "# --- Ipset Definitions ---") {
		if err := applyIpsets(ctx, bundle.Rules); err != nil {
			revertCancel()
			if revertErr := revertRules(backup); revertErr != nil {
				log.Error("Revert failed", "error", revertErr)
			}
			return fmt.Errorf("ipset apply failed: %w", err)
		}
	}

	// Use detached context for the critical restore operation so that a watchdog
	// or parent cancellation does not kill iptables-restore mid-flight, which
	// could leave the system in a broken state.
	// --noflush flag ensures atomic replacement without an intermediate empty state.
	restoreCtx := context.WithoutCancel(ctx)
	if err := restoreFromFile(restoreCtx, tmpPath, stripIpsetSection(bundle.Rules)); err != nil {
		revertCancel()
		return fmt.Errorf("rule restore failed: %w", err)
	}

	if hasDocker() {
		log.Info("Restarting Docker to reset internal chains")
		if err := restartDocker(ctx); err != nil {
			log.Warn("Docker restart failed (rules still applied)", "error", err)
		}
	}

	if err := smokeTest(ctx, controlPlaneURL, token, version); err != nil {
		log.Warn("Smoke test failed after apply, reverting", "error", err)
		if revertErr := revertRules(backup); revertErr != nil {
			log.Error("Revert failed", "error", revertErr)
		} else {
			log.Info("Rules reverted successfully")
		}
		revertCancel()
		return fmt.Errorf("smoke test failed, reverted: %w", err)
	}

	revertCancel()

	// Remove persisted backup on success so a subsequent crash does not restore
	// stale rules.
	if err := os.Remove(LocalBackupPath); err != nil && !os.IsNotExist(err) {
		log.Warn("Failed to remove persisted backup", "error", err)
	}

	if confirmFunc != nil {
		confirmCtx, confirmCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := confirmFunc(confirmCtx, bundle.Version); err != nil {
			log.Warn("Failed to confirm apply to control plane", "error", err)
		}
		confirmCancel()
	}

	if err := CacheBundle(bundle.Rules); err != nil {
		log.Warn("Failed to cache bundle", "error", err)
	}

	log.Info("Applied bundle successfully", "version", bundle.Version)
	return nil
}

func CacheBundle(rules string) error {
	const cachePath = "/etc/runic-agent/cached-bundle.rules"

	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	if err := os.WriteFile(cachePath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	log.Info("Bundle cached for apply-on-boot", "path", cachePath)
	return nil
}

func smokeTest(ctx context.Context, controlPlaneURL, token, version string) error {
	client := &http.Client{
		Timeout: constants.SmokeTestTimeout,
	}

	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", controlPlaneURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("create smoke test request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("smoke test request failed: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("smoke test returned status %d", resp.StatusCode)
	}

	return nil
}
