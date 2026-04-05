package common

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// hostnameRegex validates hostnames: 1-253 chars, alphanumeric with hyphens and dots,
// must start and end with alphanumeric (single-char hostnames allowed).
var hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$`)

// nameRegex validates names: alphanumeric with underscores, hyphens, and spaces.
var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,100}$`)

// ValidateHostname validates a hostname per RFC 1123 requirements:
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

// ValidateIPAddress validates an IP address or CIDR notation.
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

// ValidateName validates a name field:
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
