// Package apply provides the application applier.
package apply

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
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

// ApplyBundle uses the confirmFunc callback to notify the control plane after successful apply.
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

	// Persist backup to disk BEFORE any state modification so crash mid-apply
	// does not lose the ability to restore.
	if err := persistBackup(backup); err != nil {
		log.Warn("Failed to persist backup to disk", "error", err)
	}

	revertCancel := scheduleRevert(ctx, backup, constants.AutoRevertDelay, controlPlaneURL, token, version)

	// Flush iptables FIRST to release ipset references before destroying ipsets
	// This prevents "ipset in use" errors during ipset recreate
	if err := flushIPTables(ctx); err != nil {
		revertCancel()
		return fmt.Errorf("flush firewall: %w", err)
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

	// Use detached context for the critical restore operation so that a watchdog
	// or parent cancellation does not kill iptables-restore mid-flight, which
	// could leave the system in a broken state.
	restoreCtx := context.WithoutCancel(ctx)
	if err := restoreRulesFromContent(restoreCtx, stripIpsetSection(bundle.Rules)); err != nil {
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

// restoreRulesFromContent writes the given rules to a temp file and applies
// them using the appropriate firewall backend (iptables-restore or nft -f).
func restoreRulesFromContent(ctx context.Context, rules string) error {
	tmpFile, err := os.CreateTemp("", "runic-restore-*.rules")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	defer func() {
		if err := os.Remove(tmpPath); err != nil {
			log.Warn("remove err", "err", err)
		}
	}()

	if _, err := tmpFile.WriteString(rules); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			log.Warn("Failed to close temp file", "error", closeErr)
		}
		return fmt.Errorf("write rules: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	return restoreFromFile(ctx, tmpPath, rules)
}

// restoreFromFile applies firewall rules from a file using the appropriate
// backend based on the content format.
func restoreFromFile(ctx context.Context, path, content string) error {
	if IsNftFormat(content) {
		cmd := exec.CommandContext(ctx, "nft", "-f", path)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f restore failed: %s: %w", string(output), err)
		}
		return nil
	}

	cmd := exec.CommandContext(ctx, "iptables-restore", path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore failed: %s: %w", string(output), err)
	}
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

// Uses time.AfterFunc with sync.Once to guarantee exactly one of the
// two paths executes: either the auto-revert fires, or the caller
// cancels it on success. This eliminates the race between cancel() and
// the timer callback that existed with the previous select/default pattern.
func scheduleRevert(ctx context.Context, backup string, delay time.Duration, controlPlaneURL, token, version string) context.CancelFunc {
	var once sync.Once

	revertFn := func() {
		log.Warn("Auto-revert triggered, restoring previous rules", "delay", delay)
		if err := revertRules(backup); err != nil {
			log.Error("Auto-revert failed", "error", err)
		} else {
			log.Info("Rules reverted successfully")
		}
	}

	timer := time.AfterFunc(delay, func() {
		once.Do(revertFn)
	})

	return func() {
		// Consume the once so the timer callback becomes a no-op if it
		// has not fired yet, then stop the timer to prevent a spurious
		// callback invocation.
		once.Do(func() {})
		timer.Stop()
	}
}

func dumpCurrentRules() (string, error) {
	out, err := exec.Command("iptables-save").Output()
	if err == nil {
		return string(out), nil
	}
	log.Info("iptables-save unavailable, trying nft list ruleset")
	out, err = exec.Command("nft", "list", "ruleset").Output()
	if err != nil {
		return "", fmt.Errorf("firewall dump failed (tried iptables-save and nft list ruleset): %w", err)
	}
	return string(out), nil
}

// persistBackup writes the backup content to a persistent file so crash
// recovery can still restore rules.
func persistBackup(content string) error {
	dir := filepath.Dir(LocalBackupPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	if err := os.WriteFile(LocalBackupPath, []byte(content), 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	log.Info("Backup persisted for crash recovery", "path", LocalBackupPath)
	return nil
}

// readPersistedBackup reads the backup file from disk; returns empty string
// and nil error if no backup exists.
func readPersistedBackup() (string, error) {
	data, err := os.ReadFile(LocalBackupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read persisted backup: %w", err)
	}
	return string(data), nil
}

// IsNftFormat returns true when the content looks like nftables ruleset
// (starts with "table" rather than containing "*filter").
func IsNftFormat(content string) bool {
	return strings.Contains(content, "table ") && !strings.Contains(content, "*filter")
}

func revertRules(backup string) error {
	// If the in-memory backup is empty, try reading the persistent backup.
	if strings.TrimSpace(backup) == "" {
		var err error
		backup, err = readPersistedBackup()
		if err != nil {
			return fmt.Errorf("read persisted backup: %w", err)
		}
		if strings.TrimSpace(backup) == "" {
			return fmt.Errorf("no backup available to revert (in-memory empty and no persisted backup)")
		}
		log.Info("Using persisted backup for revert", "path", LocalBackupPath)
	}

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

	// Use detached context so watchdog cancellation does not kill the restore.
	ctx := context.WithoutCancel(context.Background())

	if IsNftFormat(backup) {
		cmd := exec.CommandContext(ctx, "nft", "-f", tmpPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft -f revert: %s: %w", string(output), err)
		}
		return nil
	}

	cmd := exec.CommandContext(ctx, "iptables-restore", tmpPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables-restore revert: %s: %w", string(output), err)
	}

	return nil
}

func validateRules(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("rules content is empty")
	}

	// Nftables-format rules use "table ip filter" syntax rather than
	// iptables "*filter" markers. The detailed iptables-specific checks
	// (e.g. *filter, COMMIT, :INPUT DROP) do not apply to nft format, so
	// skip them. A full nftables schema validator is not trivial to
	// implement, so we only verify the content is non-empty and contains
	// a recognizable nft marker.
	if IsNftFormat(content) {
		if !strings.Contains(content, "table ip filter") {
			return fmt.Errorf("nft-format rules missing 'table ip filter' declaration")
		}
		if strings.Count(content, "\n") > 10000 {
			return fmt.Errorf("too many lines in nft rules, refusing to apply")
		}
		return nil
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
		log.Info("Creating ipset", "name", def.Name, "type", def.Type, "family", "inet")
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

type ipsetDef struct {
	Name    string
	Type    string
	Members []string
}

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

func flushRunicIpsets(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "ipset", "list", "-n")
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If ipset is not installed (command not found), there is nothing to flush.
		if errors.Is(err, exec.ErrNotFound) {
			log.Info("ipset command not found, skipping ipset flush")
			return nil
		}
		// If ipset list failed with a non-zero exit code, distinguish between
		// "no ipsets exist" (which is fine) and real errors like permission
		// denied or missing kernel module.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			stderr := strings.TrimSpace(string(exitErr.Stderr))
			// Exit code 127 typically means command not found in the shell.
			if exitErr.ExitCode() == 127 {
				log.Info("ipset command not found (exit 127), skipping ipset flush")
				return nil
			}
			// ipset returns exit code 1 with specific messages when the
			// kernel module is not loaded or no sets exist.
			if strings.Contains(stderr, "No such file") ||
				strings.Contains(stderr, "Kernel module not loaded") ||
				strings.Contains(stderr, "No set found") {
				log.Info("ipset list indicates no ipsets or kernel support, skipping flush", "stderr", stderr)
				return nil
			}
			return fmt.Errorf("ipset list: %s: %w", stderr, err)
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

func runIpset(ctx context.Context, name, ipsetType, family string) error {
	cmd := exec.CommandContext(ctx, "ipset", "create", name, ipsetType, "family", family)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset create %s %s: %s: %w", name, ipsetType, string(output), err)
	}
	return nil
}

func addIpsetMember(ctx context.Context, name, member string) error {
	cmd := exec.CommandContext(ctx, "ipset", "add", name, member)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset add %s %s: %s: %w", name, member, string(output), err)
	}
	return nil
}

func hasDocker() bool {
	_, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	out, err := exec.Command("systemctl", "is-active", "docker").Output()
	return err == nil && strings.TrimSpace(string(out)) == "active"
}

func restartDocker(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "docker")
	return cmd.Run()
}

// This is done before destroying ipsets to release references to them.
// The order is: flush rules (-F) first, then delete custom chains (-X).
// Falls back to nft flush ruleset when iptables is unavailable.
func flushIPTables(ctx context.Context) error {
	// Check if iptables is available; if not, fall back to nft.
	if _, err := exec.LookPath("iptables"); err != nil {
		log.Info("iptables not found, using nft flush ruleset")
		flushCtx := context.WithoutCancel(ctx)
		cmd := exec.CommandContext(flushCtx, "nft", "flush", "ruleset")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("nft flush ruleset: %s: %w", string(output), err)
		}
		log.Info("Flushed nftables ruleset")
		return nil
	}

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
