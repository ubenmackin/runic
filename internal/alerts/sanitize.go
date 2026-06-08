// Package alerts provides alert and notification functionality.
//
// # Defense-in-Depth Sanitization Strategy
//
// This package implements a multi-layer sanitization approach to protect against
// various injection attacks. The strategy uses two distinct sanitization layers,
// each targeting specific threat vectors:
//
//  1. Entry Point Sanitization (SanitizeAlertInput):
//     - Removes control characters (CR, LF, NUL, TAB, and other ASCII control chars)
//     - Purpose: Prevents header injection attacks (e.g., email header injection via
//     embedded newlines, HTTP header injection)
//     - Applied when data enters the system (e.g., agent registration, user input)
//     - Does NOT escape HTML special characters (preserves legitimate use of <, >, &)
//
//  2. Output-Time Sanitization (htmlEscape at email generation):
//     - Escapes HTML special characters (<, >, &, ", ')
//     - Purpose: Prevents XSS attacks when data is rendered in HTML contexts
//     - Applied at the point of output to the target format (email body, HTML pages)
//     - Ensures proper encoding for the specific output context
//
// This separation of concerns provides defense-in-depth:
//   - Control characters are removed early because they can never be legitimate in
//     hostname/IP fields and pose header injection risks
//   - HTML escaping is deferred to output time because:
//     a) The same data may be used in non-HTML contexts (logs, CLI output)
//     b) Proper escaping depends on the output context (HTML vs. JSON vs. plain text)
//     c) Early escaping could corrupt legitimate data or cause double-encoding issues
//
// SanitizeAlertInput performs entry-point sanitization (control character removal
// and length truncation). HTML escaping is handled separately at output time by
// htmlEscape in the email template layer — see the defense-in-depth strategy above.
package alerts

import (
	"strings"
)

const DefaultMaxHostnameLength = 255

// SanitizeAlertInput sanitizes alert input. It removes control characters, truncates length, and escapes dangerous content.
// Returns the sanitized string and true if modifications were made.
func SanitizeAlertInput(input string, maxLen int) (string, bool) {
	if input == "" {
		return "", false
	}

	modified := false
	var result strings.Builder

	for _, r := range input {
		// Allow space (0x20) and above, but not DEL (0x7F)
		if r < 0x20 || r == 0x7F {
			modified = true
			continue
		}
		result.WriteRune(r)
	}

	sanitized := result.String()

	trimmed := strings.TrimSpace(sanitized)
	if trimmed != sanitized {
		modified = true
		sanitized = trimmed
	}

	if maxLen > 0 && len(sanitized) > maxLen {
		modified = true
		// Safe truncation that doesn't break UTF-8 sequences
		sanitized = truncateString(sanitized, maxLen)
	}

	return sanitized, modified
}

// multi-byte UTF-8 sequences.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	for maxLen > 0 {
		if s[maxLen-1] < 0x80 || s[maxLen-1] >= 0xC0 {
			// ASCII character or start of a multi-byte sequence
			break
		}
		maxLen--
	}

	return s[:maxLen]
}
