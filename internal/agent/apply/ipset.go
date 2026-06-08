package apply

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"runic/internal/common/log"
)

type ipsetDef struct {
	Name    string
	Type    string
	Members []string
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
			errStr := string(out)
			if !strings.Contains(errStr, "The set with the given name does not exist") &&
				!strings.Contains(errStr, "not found") {
				return fmt.Errorf("flush ipset %s: %s: %w", name, errStr, err)
			}
			log.Warn("Ipset not found during flush, continuing", "name", name, "output", errStr)
		}

		destroyCmd := exec.CommandContext(ctx, "ipset", "destroy", name)
		if out, err := destroyCmd.CombinedOutput(); err != nil {
			errStr := string(out)
			if !strings.Contains(errStr, "The set with the given name does not exist") &&
				!strings.Contains(errStr, "not found") {
				return fmt.Errorf("destroy ipset %s: %s: %w", name, errStr, err)
			}
			log.Warn("Ipset not found during destroy, continuing", "name", name, "output", errStr)
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
		errStr := string(output)
		if strings.Contains(errStr, "already exists") {
			log.Info("Ipset already exists, treating as success", "name", name)
			return nil
		}
		return fmt.Errorf("ipset create %s %s: %s: %w", name, ipsetType, errStr, err)
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
