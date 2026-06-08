// Package common provides structural / format validators. The functions here
// answer questions of the form "does this string look like a hostname?",
// "is this a valid IP or CIDR?", "is this a valid resource name?" — they
// are pure syntactic checks with no knowledge of the application's domain
// enums. For domain-specific checks (e.g. "is this a valid entity type
// like 'peer' / 'group' / 'special'?"), see validation.go.
package common

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// must start and end with alphanumeric; no consecutive dots allowed.
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$`)

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,100}$`)

// ValidateHostname validates that a hostname conforms to RFC standards:
// - 1-253 characters
// - alphanumeric with hyphens and dots
// - must start and end with alphanumeric
func ValidateHostname(h string) error {
	if h == "" {
		return fmt.Errorf("hostname is required")
	}
	if len(h) > 253 {
		return fmt.Errorf("hostname must be 1-253 characters")
	}
	if !hostnameRegex.MatchString(h) {
		return fmt.Errorf("hostname must be alphanumeric with hyphens and dots only, and must start and end with alphanumeric")
	}
	return nil
}

// ValidateIPAddress validates that the input is a valid IP address or CIDR notation.
// Returns an error if the input is neither a valid IP nor a valid CIDR.
func ValidateIPAddress(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address is required")
	}
	// Try to parse as plain IP first
	if net.ParseIP(ip) != nil {
		return nil
	}
	// Try to parse as CIDR
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return fmt.Errorf("invalid IP address or CIDR notation")
	}
	return nil
}

// ValidateName validates that a name conforms to the application's naming rules:
// - 1-100 characters
// - alphanumeric with underscores, hyphens, and spaces
func ValidateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > 100 {
		return fmt.Errorf("name must be 1-100 characters")
	}
	if !nameRegex.MatchString(name) {
		return fmt.Errorf("name must be alphanumeric with underscores, hyphens, and spaces only")
	}
	return nil
}
