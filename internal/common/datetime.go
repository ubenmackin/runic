package common

import (
	"fmt"
	"strings"
	"time"

	"runic/internal/common/log"
)

// FirewallTimestampLayout is the canonical firewall_logs.timestamp format.
// SQLite compares TEXT bytewise, so stored values and query bounds must share
// this exact layout for minute-scale alert windows and retention deletes to be
// correct.
const FirewallTimestampLayout = "2006-01-02 15:04:05"

// maxFirewallTimestampLen bounds parsing work on untrusted log input.
const maxFirewallTimestampLen = 64

// legacySyslogTimestampLayout is the traditional syslog prefix, which carries
// no year.
const legacySyslogTimestampLayout = "Jan _2 15:04:05"

// FormatSQLiteDatetime converts a SQLite datetime string
// to RFC 3339 format (YYYY-MM-DDTHH:MM:SSZ). SQLite's CURRENT_TIMESTAMP and
// datetime('now') produce UTC times without timezone info, so the parsed time
// is treated as UTC. If the string is empty, it returns an empty string.
// If the input is already in RFC 3339 format, it is returned unchanged.
// If parsing fails for both formats, the original string is returned unchanged
// (and a warning is logged so the bad data is visible during investigation).
func FormatSQLiteDatetime(s string) string {
	if s == "" {
		return ""
	}
	// Try SQLite datetime format first (YYYY-MM-DD HH:MM:SS)
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t.UTC().Format(time.RFC3339)
	}
	// Already in RFC 3339 format — return as-is
	if _, err := time.Parse(time.RFC3339, s); err == nil {
		return s
	}
	// Unable to parse — log a warning and return the original string
	// unchanged so callers downstream don't lose data.
	log.Warn("FormatSQLiteDatetime: unable to parse timestamp, returning as-is", "input", s)
	return s
}

// NormalizeFirewallTimestamp converts a raw firewall log timestamp into the
// canonical UTC form defined by FirewallTimestampLayout. SQLite compares TEXT
// bytewise, so stored values and query bounds must share this exact layout for
// minute-scale alert windows and retention deletes to be correct.
//
// RFC3339, SQLite datetime, and date-only inputs are absolute instants;
// zone-less layouts are interpreted as UTC. Traditional syslog timestamps omit
// the year, which is inferred from now and rolled back one year when the result
// would land more than a day in the future. Fractional seconds are dropped.
// Raw inputs longer than maxFirewallTimestampLen are rejected before trimming,
// so oversized whitespace padding cannot bypass the bound.
func NormalizeFirewallTimestamp(raw string, now time.Time) (string, error) {
	if len(raw) > maxFirewallTimestampLen {
		return "", fmt.Errorf("firewall log timestamp exceeds %d bytes", maxFirewallTimestampLen)
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("firewall log timestamp is empty")
	}

	layouts := [...]string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.ParseInLocation(layout, trimmed, time.UTC); err == nil {
			return parsed.UTC().Format(FirewallTimestampLayout), nil
		}
	}

	if parsed, err := time.ParseInLocation(legacySyslogTimestampLayout, trimmed, time.UTC); err == nil {
		nowUTC := now.UTC()
		inferred := time.Date(
			nowUTC.Year(), parsed.Month(), parsed.Day(),
			parsed.Hour(), parsed.Minute(), parsed.Second(), parsed.Nanosecond(),
			time.UTC,
		)
		if inferred.After(nowUTC.Add(24 * time.Hour)) {
			inferred = inferred.AddDate(-1, 0, 0)
		}
		return inferred.UTC().Format(FirewallTimestampLayout), nil
	}

	return "", fmt.Errorf("unrecognized firewall log timestamp %q", raw)
}

// FirewallTimestampCutoff formats a SQL comparison bound in
// FirewallTimestampLayout. SQLite compares TEXT bytewise, so bounds must use the
// same layout as stored values for minute-scale alert windows and retention
// deletes to be correct.
func FirewallTimestampCutoff(t time.Time) string {
	return t.UTC().Format(FirewallTimestampLayout)
}
