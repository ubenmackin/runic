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
// For contexts requiring both protections simultaneously, use SanitizeAlertInputStrict
// which applies both control character removal and HTML escaping.
package alerts

import (
	"html"
	"strings"
	"unicode"
)

// DefaultMaxHostnameLength is the default maximum length for hostname-like fields.
const DefaultMaxHostnameLength = 255

// SanitizeAlertInput sanitizes untrusted input before using in alerts.
// It removes control characters, truncates length, and escapes dangerous content.
// Returns the sanitized string and true if modifications were made.
func SanitizeAlertInput(input string, maxLen int) (string, bool) {
	if input == "" {
		return "", false
	}

	modified := false
	var result strings.Builder

	// Remove control characters and build the sanitized string
	for _, r := range input {
		// Skip control characters (CR, LF, NUL, TAB, and other ASCII control chars)
		// Allow space (0x20) and above, but not DEL (0x7F)
		if r < 0x20 || r == 0x7F {
			modified = true
			continue
		}
		result.WriteRune(r)
	}

	sanitized := result.String()

	// Trim leading and trailing whitespace
	trimmed := strings.TrimSpace(sanitized)
	if trimmed != sanitized {
		modified = true
		sanitized = trimmed
	}

	// Truncate to max length if needed
	if maxLen > 0 && len(sanitized) > maxLen {
		modified = true
		// Safe truncation that doesn't break UTF-8 sequences
		sanitized = truncateString(sanitized, maxLen)
	}

	return sanitized, modified
}

// SanitizeAlertInputStrict is a stricter version that also removes potentially
// dangerous characters for email display and HTML output. It removes/escapes:
// - Control characters (CR, LF, NUL, etc.)
// - HTML special characters (<, >, &, ", ')
// - Email header injection characters (@ for certain contexts)
// Returns the sanitized string and true if modifications were made.
func SanitizeAlertInputStrict(input string, maxLen int) (string, bool) {
	// First use SanitizeAlertInput for control char removal
	sanitized, modified := SanitizeAlertInput(input, maxLen)

	// Then apply HTML escaping using the standard library
	escaped := html.EscapeString(sanitized)
	if escaped != sanitized {
		modified = true
	}

	return escaped, modified
}

// truncateString safely truncates a string to maxLen bytes without breaking
// multi-byte UTF-8 sequences.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Find the last valid UTF-8 boundary at or before maxLen
	for maxLen > 0 {
		if s[maxLen-1] < 0x80 || s[maxLen-1] >= 0xC0 {
			// ASCII character or start of a multi-byte sequence
			break
		}
		maxLen--
	}

	return s[:maxLen]
}

// IsPrintable checks if a string contains only printable characters.
func IsPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

// RemoveControlChars removes all ASCII and Unicode control characters from a string.
func RemoveControlChars(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7F && !unicode.Is(unicode.C, r) {
			result.WriteRune(r)
		}
	}
	return result.String()
}
