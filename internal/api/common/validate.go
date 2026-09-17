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

	"runic/internal/resolve"
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
// It delegates to resolve.ValidateIPOrCIDR so the two validators cannot diverge;
// error strings and fail-closed semantics are defined once in internal/resolve.
//
// Contract note: this is the generic IP-or-CIDR check (accepts /0 for the
// __any_ip__ path). Peer address fields (peers.ip_address, peer_ips,
// policy overrides) must use ValidatePeerCIDR instead, which additionally
// rejects /0 allow-all CIDRs. Agent interface addresses and telemetry must
// use ValidatePlainIP (CIDR rejected).
func ValidateIPAddress(ip string) error {
	return resolve.ValidateIPOrCIDR(ip)
}

// ValidatePeerCIDR validates peer address fields: peers.ip_address,
// peer_ips.ip_address, and policy source_ip/target_ip overrides. Plain IPs
// and CIDR ranges are accepted (bare IPs normalize to /32 or /128 at
// compile time), but /0 allow-all CIDRs are rejected — use the explicit
// __any_ip__ special target for allow-all semantics. It delegates to
// resolve.ValidatePeerCIDR so store, resolver, and API layers share one
// definition and cannot diverge.
func ValidatePeerCIDR(ip string) error {
	return resolve.ValidatePeerCIDR(ip)
}

// ValidatePlainIP validates that the input is a plain IP address without CIDR
// notation. Packet telemetry fields (log src_ip/dst_ip, agent-reported
// interface addresses) must be plain IPs; CIDR ranges are rejected. Use
// ValidatePeerCIDR for CIDR-capable peer fields (peers.ip_address,
// peer_ips, policy overrides) and ValidateIPAddress only for generic
// IP-or-CIDR checks where /0 is explicitly allowed.
func ValidatePlainIP(ip string) error {
	if ip == "" {
		return fmt.Errorf("IP address is required")
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address")
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
