package apply

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/engine"
	"runic/internal/models"
)

// ApplyBundle applies a new bundle with auto-revert protection.
// The confirmFunc callback is used to notify the control plane after successful apply.
func ApplyBundle(ctx context.Context, bundle models.BundleResponse, hmacKey, controlPlaneURL, token, version string, confirmFunc func(context.Context, string) error) error {
	log.Info("Received bundle version, verifying HMAC", "version", bundle.Version)

	// 1. Verify HMAC
	if !engine.Verify(bundle.Rules, hmacKey, bundle.HMAC) {
		return fmt.Errorf("HMAC verification failed — refusing to apply bundle %s", bundle.Version)
	}

	// 2. Validate the rules are parseable (basic sanity check)
	if err := validateRules(bundle.Rules); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	// 3. Save current rules as backup
	backup, err := dumpCurrentRules()
	if err != nil {
		return fmt.Errorf("could not dump current rules for backup: %w", err)
	}

	// 4. Schedule auto-revert watchdog (90 seconds)
	revertCancel := scheduleRevert(backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// 5. Write new rules to temp file
	tmpFile, err := os.CreateTemp("", "runic-bundle-*.rules")
	if err != nil {
		revertCancel()
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		os.Remove(tmpPath)
	}()

	if _, err := tmpFile.WriteString(bundle.Rules); err != nil {
		revertCancel()
		return fmt.Errorf("write bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		revertCancel()
		return fmt.Errorf("close temp file: %w", err)
	}

	// 6. Apply via iptables-restore
	cmd := exec.CommandContext(ctx, "iptables-restore", "--noflush", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		revertCancel()
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}

	// 7. Verify apply worked (smoke test)
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

	// 8. Cancel revert — we're good
	revertCancel()

	// 9. Confirm to control plane
	if confirmFunc != nil {
		if err := confirmFunc(ctx, bundle.Version); err != nil {
			log.Warn("Failed to confirm apply to control plane", "error", err)
		}
	}

	// Cache bundle for apply-on-boot
	if err := CacheBundle(bundle.Rules); err != nil {
		log.Warn("Failed to cache bundle", "error", err)
	}

	log.Info("Applied bundle successfully", "version", bundle.Version)
	return nil
}

// CacheBundle saves the bundle rules to disk for apply-on-boot.
func CacheBundle(rules string) error {
	const cachePath = "/etc/runic-agent/cached-bundle.rules"

	// Create directory
	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	// Write to cache file
	if err := os.WriteFile(cachePath, []byte(rules), 0600); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}

	log.Info("Bundle cached for apply-on-boot", "path", cachePath)
	return nil
}

// scheduleRevert sets up a delayed revert that can be cancelled.
func scheduleRevert(backup string, delay time.Duration, controlPlaneURL, token, version string) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		select {
		case <-time.After(delay):
			log.Warn("Auto-revert triggered, restoring previous rules", "delay", delay)
			if err := revertRules(backup); err != nil {
				log.Error("Auto-revert failed", "error", err)
			} else {
				log.Info("Rules reverted successfully")
			}
		case <-ctx.Done():
			// Cancelled — apply was confirmed
		}
	}()

	return cancel
}

// dumpCurrentRules saves the current iptables rules.
func dumpCurrentRules() (string, error) {
	out, err := exec.Command("iptables-save").Output()
	if err != nil {
		return "", fmt.Errorf("iptables-save: %w", err)
	}
	return string(out), nil
}

// revertRules restores rules from a backup.
func revertRules(backup string) error {
	tmp, err := os.CreateTemp("", "runic-revert-*.rules")
	if err != nil {
		return fmt.Errorf("create revert temp file: %w", err)
	}
	tmpPath := tmp.Name()

	defer os.Remove(tmpPath)

	if _, err := tmp.WriteString(backup); err != nil {
		tmp.Close()
		return fmt.Errorf("write backup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close revert temp file: %w", err)
	}

	cmd := exec.Command("iptables-restore", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore revert: %s: %w", string(output), err)
	}

	return nil
}

// validateRules performs basic sanity checks on rules before applying.
func validateRules(content string) error {
	// Content is not empty
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("rules content is empty")
	}

	// Contains *filter and COMMIT
	if !strings.Contains(content, "*filter") {
		return fmt.Errorf("missing *filter table")
	}
	if !strings.Contains(content, "COMMIT") {
		return fmt.Errorf("missing COMMIT")
	}

	// Contains :INPUT DROP and :OUTPUT DROP (default deny chains)
	if !strings.Contains(content, ":INPUT DROP") {
		return fmt.Errorf("missing :INPUT DROP chain")
	}
	if !strings.Contains(content, ":OUTPUT DROP") {
		return fmt.Errorf("missing :OUTPUT DROP chain")
	}

	// Total rule count is reasonable (>0 and <10000)
	lines := strings.Split(content, "\n")
	validLineCount := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Valid lines: -A (rule), : (chain definition), * (table), COMMIT
		if strings.HasPrefix(trimmed, "-A") ||
			strings.HasPrefix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "COMMIT") ||
			strings.HasPrefix(trimmed, "-") { // other iptables options like -X, -N, etc.
			validLineCount++
		} else if len(trimmed) > 0 {
			// Contains obviously malformed line
			matched, _ := regexp.MatchString(`^[A-Z].*`, trimmed)
			if !matched {
				return fmt.Errorf("possibly malformed line: %s", trimmed[:min(50, len(trimmed))])
			}
			validLineCount++
		}
	}

	if validLineCount == 0 {
		return fmt.Errorf("no valid iptables rules found")
	}
	if validLineCount > 10000 {
		return fmt.Errorf("too many rules (%d), refusing to apply", validLineCount)
	}

	return nil
}

// smokeTest verifies the control plane is reachable after applying rules.
func smokeTest(ctx context.Context, controlPlaneURL, token, version string) error {
	// Create a client with a 10 second timeout
	client := &http.Client{
		Timeout: constants.SmokeTestTimeout,
	}

	url := fmt.Sprintf("%s/api/v1/agent/heartbeat", controlPlaneURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("smoke test request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("smoke test returned status %d", resp.StatusCode)
	}

	return nil
}
