// Package apply provides the application applier.
package apply

import (
	"context"
	"fmt"
	"math"
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

	if !engine.Verify(bundle.Rules, hmacKey, bundle.HMAC) {
		return fmt.Errorf("HMAC verification failed — refusing to apply bundle %s", bundle.Version)
	}

	if err := validateRules(bundle.Rules); err != nil {
		return fmt.Errorf("rule validation failed: %w", err)
	}

	backup, err := dumpCurrentRules()
	if err != nil {
		return fmt.Errorf("could not dump current rules for backup: %w", err)
	}

	revertCancel := scheduleRevert(ctx, backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// Flush iptables FIRST to release ipset references before destroying ipsets
	// This prevents "ipset in use" errors during ipset recreate
	if err := flushIPTables(ctx); err != nil {
		revertCancel()
		return fmt.Errorf("flush iptables: %w", err)
	}

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

	if _, err := tmpFile.WriteString(stripIpsetSection(bundle.Rules)); err != nil {
		revertCancel()
		return fmt.Errorf("write bundle to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		revertCancel()
		return fmt.Errorf("close temp file: %w", err)
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

	cmd := exec.CommandContext(ctx, "iptables-restore", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		revertCancel()
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
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

	if confirmFunc != nil {
		if err := confirmFunc(ctx, bundle.Version); err != nil {
			log.Warn("Failed to confirm apply to control plane", "error", err)
		}
	}

	if err := CacheBundle(bundle.Rules); err != nil {
		log.Warn("Failed to cache bundle", "error", err)
	}

	log.Info("Applied bundle successfully", "version", bundle.Version)
	return nil
}

// CacheBundle saves the bundle rules to disk for apply-on-boot.
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
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("rules content is empty")
	}

	if !strings.Contains(content, "*filter") {
		return fmt.Errorf("missing *filter table")
	}
	if !strings.Contains(content, "COMMIT") {
		return fmt.Errorf("missing COMMIT")
	}

	if !strings.Contains(content, ":INPUT DROP") {
		return fmt.Errorf("missing :INPUT DROP chain")
	}
	if !strings.Contains(content, ":OUTPUT DROP") {
		return fmt.Errorf("missing :OUTPUT DROP chain")
	}

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
			strings.HasPrefix(trimmed, "-") ||
			strings.HasPrefix(trimmed, "create ") ||
			strings.HasPrefix(trimmed, "add ") {
			validLineCount++
		} else if len(trimmed) > 0 {
			if !malformedRegex.MatchString(trimmed) {
				return fmt.Errorf("possibly malformed line: %s", trimmed[:int(math.Min(50, float64(len(trimmed))))])
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
	ipsetSection, err := extractIpsetSection(rulesContent)
	if err != nil {
		return fmt.Errorf("extract ipset section: %w", err)
	}
	if ipsetSection == "" {
		return nil // No ipset definitions to apply
	}

	ipsetDefs, err := parseIpsetDefs(ipsetSection)
	if err != nil {
		return fmt.Errorf("parse ipset definitions: %w", err)
	}

	if len(ipsetDefs) == 0 {
		log.Info("No ipset definitions found in ipset section")
		return nil
	}

	log.Info("Applying ipset definitions", "count", len(ipsetDefs))

	if err := flushRunicIpsets(ctx); err != nil {
		return fmt.Errorf("flush runic ipsets: %w", err)
	}

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
		return "", nil
	}

	filterIdx := strings.Index(content[startIdx:], "*filter")
	if filterIdx == -1 {
		return "", fmt.Errorf("ipset section found but no *filter marker after it")
	}

	section := content[startIdx : startIdx+filterIdx]
	return strings.TrimSpace(section), nil
}

// stripIpsetSection removes the ipset definition section from bundle content.
// It strips everything from "# --- Ipset Definitions ---" up to (but not including) "*filter".
// If no ipset section is found, the original string is returned unchanged.
// If an ipset section is found but no "*filter" follows it, the original string is returned (safe fallback).
func stripIpsetSection(content string) string {
	startMarker := "# --- Ipset Definitions ---"
	startIdx := strings.Index(content, startMarker)
	if startIdx == -1 {
		return content
	}

	filterIdx := strings.Index(content[startIdx:], "*filter")
	if filterIdx == -1 {
		return content // Safe fallback: no *filter after ipset section
	}

	before := content[:startIdx]
	after := content[startIdx+filterIdx:]

	before = strings.TrimRight(before, "\n")
	if before != "" {
		before += "\n"
	}

	return before + after
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

	result := make([]ipsetDef, 0, len(order))
	for _, name := range order {
		result = append(result, *defs[name])
	}

	return result, nil
}

// flushRunicIpsets destroys all ipsets with names starting with "runic_group_" and the "runic_private_ranges" ipset.
func flushRunicIpsets(ctx context.Context) error {
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
		if name == "" || (!strings.HasPrefix(name, "runic_group_") && name != "runic_private_ranges") {
			continue
		}

		flushCmd := exec.CommandContext(ctx, "ipset", "flush", name)
		if out, err := flushCmd.CombinedOutput(); err != nil {
			log.Warn("Failed to flush ipset", "name", name, "output", string(out))
		}

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

// flushIPTables flushes all iptables rules in the filter table.
// This is done before destroying ipsets to release references to them.
// The order is: flush rules (-F) first, then delete custom chains (-X).
func flushIPTables(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-F")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("flush iptables filter: %w", err)
	}

	delCmd := exec.CommandContext(ctx, "iptables", "-t", "filter", "-X")
	if err := delCmd.Run(); err != nil {
		log.Warn("Failed to delete custom filter chains, continuing", "error", err)
	}

	natCmd := exec.CommandContext(ctx, "iptables", "-t", "nat", "-F")
	if err := natCmd.Run(); err != nil {
		log.Warn("Failed to flush NAT table, continuing", "error", err)
	}

	natDelCmd := exec.CommandContext(ctx, "iptables", "-t", "nat", "-X")
	if err := natDelCmd.Run(); err != nil {
		log.Warn("Failed to delete custom NAT chains, continuing", "error", err)
	}

	log.Info("Flushed iptables rules and deleted custom chains to release ipset references")
	return nil
}
