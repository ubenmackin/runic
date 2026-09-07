package apply

import (
	"fmt"
	"regexp"
	"strings"
)

var malformedLineRe = regexp.MustCompile(`^[A-Z].*`)

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
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Valid lines: -A (rule), : (chain definition), * (table), COMMIT
		// Also valid: ipset commands (create, add) in ipset section
		// Only accept known iptables flag prefixes, not arbitrary lines starting with '-'.
		if strings.HasPrefix(trimmed, "-A") ||
			strings.HasPrefix(trimmed, "-P") ||
			strings.HasPrefix(trimmed, "-N") ||
			strings.HasPrefix(trimmed, "-X") ||
			strings.HasPrefix(trimmed, "-F") ||
			strings.HasPrefix(trimmed, "-Z") ||
			strings.HasPrefix(trimmed, "-I") ||
			strings.HasPrefix(trimmed, "-D") ||
			strings.HasPrefix(trimmed, "-R") ||
			strings.HasPrefix(trimmed, "-L") ||
			strings.HasPrefix(trimmed, "-S") ||
			strings.HasPrefix(trimmed, "-E") ||
			strings.HasPrefix(trimmed, ":") ||
			strings.HasPrefix(trimmed, "*") ||
			strings.HasPrefix(trimmed, "COMMIT") ||
			strings.HasPrefix(trimmed, "create ") ||
			strings.HasPrefix(trimmed, "add ") {
			validLineCount++
		} else if len(trimmed) > 0 {
			if !malformedLineRe.MatchString(trimmed) {
				maxLen := 50
				if len(trimmed) < maxLen {
					maxLen = len(trimmed)
				}
				return fmt.Errorf("possibly malformed line: %s", trimmed[:maxLen])
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
