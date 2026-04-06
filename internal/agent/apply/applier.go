// Package apply provides the application applier.
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
	revertCancel := scheduleRevert(ctx, backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// 5. Write new rules to temp file
	tmpFile, err := os.CreateTemp("", "runic-bundle-*.rules")
	if err != nil {
		revertCancel()
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("remove err", "err", err)
		}
	}()

	if _, err := tmpFile.WriteString(bundle.Rules); err != nil {
		revertCancel()
		return fmt.Errorf("write bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		revertCancel()
		return fmt.Errorf("close temp file: %w", err)
	}

	// 5b. Apply ipset definitions if present (before iptables-restore)
	if strings.Contains(bundle.Rules, "# --- Ipset Definitions ---") {
		if err := applyIpsets(ctx, bundle.Rules); err != nil {
			revertCancel()
			return fmt.Errorf("ipset apply failed: %w", err)
		}
	}

	// 6. Apply via iptables-restore (flushes existing rules for clean slate)
	cmd := exec.CommandContext(ctx, "iptables-restore", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		revertCancel()
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}

	// 6b. Restart Docker if running (resets DOCKER chains)
	if hasDocker() {
		log.Info("Restarting Docker to reset internal chains")
		if err := restartDocker(ctx); err != nil {
			log.Warn("Docker restart failed (rules still applied)", "error", err)
		}
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

// scheduleRevert sets up a delayed revert that can be canceled.
// Uses time.AfterFunc to avoid launching a bare goroutine.
func scheduleRevert(ctx context.Context, backup string, delay time.Duration, controlPlaneURL, token, version string) context.CancelFunc {
	ctx, cancel := context.WithCancel(ctx)

	timer := time.AfterFunc(delay, func() {
		select {
		case <-ctx.Done():
			// Canceled — apply was confirmed
			return
		default:
			log.Warn("Auto-revert triggered, restoring previous rules", "delay", delay)
			if err := revertRules(backup); err != nil {
				log.Error("Auto-revert failed", "error", err)
			} else {
				log.Info("Rules reverted successfully")
			}
		}
	})

	// Return a cancel func that also stops the timer
	return func() {
		cancel()
		timer.Stop()
	}
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

	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("remove err", "err", err)
		}
	}()

	if _, err := tmp.WriteString(backup); err != nil {
		if err := tmp.Close(); err != nil {
			log.Warn("Failed to close temporary script file", "error", err)
		}
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
	malformedRegex := regexp.MustCompile(`^[A-Z].*`)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Valid lines: -A (rule), : (chain definition), * (table), COMMIT
		// Also valid: ipset commands (create, add) in ipset section
		if strings.HasPrefix(trimmed, "-A") ||
			strings.HasPrefix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "COMMIT") ||
			strings.HasPrefix(trimmed, "-") || // other iptables options like -X, -N, etc.
			strings.HasPrefix(trimmed, "create ") || // ipset create command
			strings.HasPrefix(trimmed, "add ") { // ipset add command
			validLineCount++
		} else if len(trimmed) > 0 {
			// Contains obviously malformed line
			if !malformedRegex.MatchString(trimmed) {
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
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("close err", "err", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("smoke test returned status %d", resp.StatusCode)
	}

	return nil
}

// applyIpsets parses and applies ipset definitions from a bundle.
// It flushes all existing runic_group_* ipsets, creates new ones, and populates them.
func applyIpsets(ctx context.Context, rulesContent string) error {
	// 1. Extract ipset section (between "# --- Ipset Definitions ---" and "*filter")
	ipsetSection, err := extractIpsetSection(rulesContent)
	if err != nil {
		return fmt.Errorf("extract ipset section: %w", err)
	}
	if ipsetSection == "" {
		return nil // No ipset definitions to apply
	}

	// 2. Parse create and add commands
	ipsetDefs, err := parseIpsetDefs(ipsetSection)
	if err != nil {
		return fmt.Errorf("parse ipset definitions: %w", err)
	}

	if len(ipsetDefs) == 0 {
		log.Info("No ipset definitions found in ipset section")
		return nil
	}

	log.Info("Applying ipset definitions", "count", len(ipsetDefs))

	// 3. Flush all existing runic_group_* ipsets
	if err := flushRunicIpsets(ctx); err != nil {
		return fmt.Errorf("flush runic ipsets: %w", err)
	}

	// 4. Create new ipsets and add members
	for _, def := range ipsetDefs {
		createCmd := fmt.Sprintf("ipset create %s %s family inet", def.Name, def.Type)
		log.Info("Creating ipset", "name", def.Name, "type", def.Type, "command", createCmd)
		if err := runIpset(ctx, def.Name, def.Type, "inet"); err != nil {
			return fmt.Errorf("create ipset %s: %w", def.Name, err)
		}

		for _, member := range def.Members {
			addCmd := fmt.Sprintf("ipset add %s %s", def.Name, member)
			log.Debug("Adding to ipset", "name", def.Name, "member", member, "command", addCmd)
			if err := addIpsetMember(ctx, def.Name, member); err != nil {
				return fmt.Errorf("add member %s to ipset %s: %w", member, def.Name, err)
			}
		}
	}

	log.Info("Ipset definitions applied successfully", "count", len(ipsetDefs))
	return nil
}

// ipsetDef represents a parsed ipset definition.
type ipsetDef struct {
	Name    string
	Type    string
	Members []string
}

// extractIpsetSection extracts the ipset definition section from bundle content.
// Returns the text between "# --- Ipset Definitions ---" and "*filter".
func extractIpsetSection(content string) (string, error) {
	startMarker := "# --- Ipset Definitions ---"
	startIdx := strings.Index(content, startMarker)
	if startIdx == -1 {
		return "", nil // No ipset section
	}

	// Find the *filter line after the start marker
	filterIdx := strings.Index(content[startIdx:], "*filter")
	if filterIdx == -1 {
		return "", fmt.Errorf("ipset section found but no *filter marker after it")
	}

	// Extract section between start marker and *filter
	section := content[startIdx : startIdx+filterIdx]
	return strings.TrimSpace(section), nil
}

// parseIpsetDefs parses ipset create and add commands from the ipset section.
func parseIpsetDefs(section string) ([]ipsetDef, error) {
	lines := strings.Split(section, "\n")
	defs := make(map[string]*ipsetDef)
	var order []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "create":
			// Format: create <name> <type> [family inet]
			if len(fields) < 3 {
				return nil, fmt.Errorf("malformed create line: %s", trimmed)
			}
			name := fields[1]
			ipsetType := fields[2]
			defs[name] = &ipsetDef{
				Name:    name,
				Type:    ipsetType,
				Members: []string{},
			}
			order = append(order, name)

		case "add":
			// Format: add <name> <ip/cidr>
			if len(fields) < 3 {
				return nil, fmt.Errorf("malformed add line: %s", trimmed)
			}
			name := fields[1]
			member := fields[2]
			if def, ok := defs[name]; ok {
				def.Members = append(def.Members, member)
			} else {
				return nil, fmt.Errorf("add for unknown ipset %s: %s", name, trimmed)
			}
		}
	}

	// Convert to slice preserving order
	result := make([]ipsetDef, 0, len(order))
	for _, name := range order {
		result = append(result, *defs[name])
	}

	return result, nil
}

// flushRunicIpsets destroys all ipsets with names starting with "runic_group_".
func flushRunicIpsets(ctx context.Context) error {
	// List all ipsets
	cmd := exec.CommandContext(ctx, "ipset", "list", "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// ipset command might fail if no ipsets exist, which is fine
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() != 0 {
			log.Info("ipset list returned non-zero, possibly no ipsets exist", "output", string(output))
			return nil
		}
		return fmt.Errorf("ipset list: %w", err)
	}

	names := strings.Split(strings.TrimSpace(string(output)), "\n")
	flushed := 0

	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || !strings.HasPrefix(name, "runic_group_") {
			continue
		}

		// Flush the ipset
		flushCmd := exec.CommandContext(ctx, "ipset", "flush", name)
		if out, err := flushCmd.CombinedOutput(); err != nil {
			log.Warn("Failed to flush ipset", "name", name, "output", string(out))
		}

		// Destroy the ipset
		destroyCmd := exec.CommandContext(ctx, "ipset", "destroy", name)
		if out, err := destroyCmd.CombinedOutput(); err != nil {
			log.Warn("Failed to destroy ipset", "name", name, "output", string(out))
		}

		flushed++
	}

	if flushed > 0 {
		log.Info("Flushed old runic ipsets", "count", flushed)
	}

	return nil
}

// runIpset creates a new ipset with the given name, type, and family.
func runIpset(ctx context.Context, name, ipsetType, family string) error {
	cmd := exec.CommandContext(ctx, "ipset", "create", name, ipsetType, "family", family)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s %s: %s: %w", name, ipsetType, string(output), err)
	}
	return nil
}

// addIpsetMember adds a member (IP or CIDR) to an ipset.
func addIpsetMember(ctx context.Context, name, member string) error {
	cmd := exec.CommandContext(ctx, "ipset", "add", name, member)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset add %s %s: %s: %w", name, member, string(output), err)
	}
	return nil
}

// hasDocker checks if Docker is installed and running.
func hasDocker() bool {
	_, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "is-active", "docker").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

// restartDocker restarts the Docker service.
func restartDocker(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "docker")
	return cmd.Run()
}
