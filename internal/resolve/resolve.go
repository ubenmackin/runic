// Package resolve provides shared IP normalization and special target ID constants
// used by both the engine (compiler/resolver) and the importer.
package resolve

import (
	"fmt"
	"net"
)

// Special target IDs for multicast groups, broadcast, and other well-known addresses.
const (
	SpecialIDSubnetBroadcast  = 1 // __subnet_broadcast__
	SpecialIDLimitedBroadcast = 2 // __limited_broadcast__
	SpecialIDAllHosts         = 3 // __all_hosts__ (IGMP)
	SpecialIDmDNS             = 4 // __mdns__
	SpecialIDLoopback         = 5 // __loopback__
	SpecialIDAnyIP            = 6 // __any_ip__
	SpecialIDAllPeers         = 7 // __all_peers__
	SpecialIDIGMPv3           = 8 // __igmpv3__
	SpecialIDInternet         = 9 // __internet__
)

// InternetSentinel is the marker returned for the internet special target.
// It is NOT a valid iptables address. Callers must translate it via
// runic_private_ranges when hasIPSet else explicit 0.0.0.0/0 + four
// !-d/!-s fallback; fail closed only for ingress/IPv6/empty-IP/sentinel-leak,
// so the marker never reaches a "-d"/"-s" rule literal.
const InternetSentinel = "__internet__"

// IsValidDirection reports whether value is a known policy direction.
//
// These shared policy allowlists are the single source of truth for the
// policy domain enums (entity type, direction, target scope, action).
// Both internal/api/common (IsValidDirection, IsValidTargetScope,
// IsValidEntityType, IsValidAction) and internal/engine (policy preview
// validation) delegate to these functions so the two cannot diverge.
// They live here (rather than in api/common) because api/common imports
// engine (tracker/pushworker/recompile), so the engine cannot import it
// without creating an import cycle.
func IsValidDirection(value string) bool {
	return value == "both" || value == "forward" || value == "backward"
}

// IsValidTargetScope reports whether value is a known policy target scope.
func IsValidTargetScope(value string) bool {
	return value == "both" || value == "host" || value == "docker"
}

// IsValidEntityType reports whether value is a known policy entity type.
func IsValidEntityType(value string) bool {
	return value == "peer" || value == "group" || value == "special"
}

// IsValidAction reports whether value is a known policy action.
func IsValidAction(value string) bool {
	return value == "ACCEPT" || value == "DROP" || value == "LOG_DROP"
}

// ValidateIPOrCIDR validates that s is a valid IP address or CIDR notation.
// Validation is performed solely by net.ParseIP and net.ParseCIDR, which
// already reject whitespace, shell metacharacters, zone identifiers, and any
// other non-address input, so no separate denylist is maintained. Unknown or
// malformed input fails closed with an error.
//
// Contract: this is the generic validator. It accepts 0.0.0.0/0 and ::/0
// because the __any_ip__ special target legitimately compiles to 0.0.0.0/0.
// Peer address fields (peers.ip_address, peer_ips.ip_address, policy
// source_ip/target_ip overrides) must use ValidatePeerCIDR instead, which
// rejects /0 so a single misconfigured peer cannot generate an allow-all
// rule. Agent-reported interface addresses (register IP, all_ips, telemetry
// src_ip/dst_ip) must use plain-IP validation only (no CIDR at all).
func ValidateIPOrCIDR(s string) error {
	if s == "" {
		return fmt.Errorf("IP address is required")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(s); err != nil {
		return fmt.Errorf("invalid IP address or CIDR notation")
	}
	return nil
}

// ValidatePeerCIDR validates peer address fields: peers.ip_address,
// peer_ips.ip_address, and policy source_ip/target_ip overrides. These
// fields accept a plain IP or a CIDR range (unlike agent interface
// addresses, which are plain-IP-only), but must never accept an allow-all
// /0 CIDR: a single peer with 0.0.0.0/0 or ::/0 would compile to
// "-s 0.0.0.0/0"/"-d 0.0.0.0/0" (allow-all) fail-open. Callers needing
// allow-all semantics must use the explicit __any_ip__ special target
// instead. Bare IPs (no "/") normalize to a single host (/32 or /128) and
// are never allow-all, so only CIDR forms are checked for prefix length.
func ValidatePeerCIDR(s string) error {
	if err := ValidateIPOrCIDR(s); err != nil {
		return err
	}
	if containsByte(s, '/') {
		_, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("invalid IP address or CIDR notation")
		}
		if ones, _ := ipNet.Mask.Size(); ones == 0 {
			return fmt.Errorf("CIDR prefix length /0 (allow-all) is not allowed for peer addresses; use the __any_ip__ special target instead")
		}
	}
	return nil
}

// ValidateGroupCIDR validates group-member address fields: the ip_address of
// peers referenced via group_members. Unlike ValidatePeerCIDR it permits
// allow-all /0 CIDRs (0.0.0.0/0, ::/0): existing groups may contain a 0.0.0.0/0
// manual peer to represent "any", and rejecting it at compile time would break
// those policies. Peer address writes (peer_store Create/Update) and policy
// source_ip/target_ip overrides stay strict via ValidatePeerCIDR, so new
// allow-all peers must use the explicit __any_ip__ special target instead.
func ValidateGroupCIDR(s string) error {
	return ValidateIPOrCIDR(s)
}

// MaxLoggedIPLen caps the length of an IP value interpolated into errors or
// log fields so a malformed multi-KB string cannot bloat logs or error
// responses. Mirrors the agent handler's maxLoggedIPLen. Truncation itself
// lives in internal/common.TruncateString, the single rune-safe truncator;
// callers in engine and api truncate via that helper directly.
const MaxLoggedIPLen = 64

// NormalizeToCIDR ensures an IP string has a CIDR suffix.
// If the string already contains a "/", it is returned as-is.
// Bare IPv4 addresses get a "/32" suffix and bare IPv6 addresses get
// a "/128" suffix so a single host is represented, not a range.
// Callers that interpolate the result into iptables rule text must validate
// the input first (ValidatePeerCIDR for peer/override fields, ValidateIPOrCIDR
// for generic paths); this function performs no validation
// beyond distinguishing IPv4 from IPv6 (unparseable input gets "/32").
func NormalizeToCIDR(ip string) string {
	if ip == "" {
		return ip
	}
	if containsByte(ip, '/') {
		return ip
	}
	if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() == nil {
		return ip + "/128"
	}
	return ip + "/32"
}

// NormalizeIP strips a host CIDR suffix from an IP string, per address family.
// A "/32" suffix is stripped only for IPv4 hosts and a "/128" suffix only
// for IPv6 hosts. Other suffixes (e.g., /24, /16, or an IPv6 /32 subnet such
// as "2001:db8::/32") are preserved as they represent subnets, not hosts.
// The address family is determined via net.ParseIP on the address portion;
// unparseable input fails closed and is returned as-is so it never matches
// a broadcast comparison by accident.
func NormalizeIP(ip string) string {
	slash := -1
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '/' {
			slash = i
			break
		}
	}
	if slash == -1 {
		return ip
	}
	suffix := ip[slash:]
	addrPart := ip[:slash]
	switch suffix {
	case "/32":
		if parsed := net.ParseIP(addrPart); parsed != nil && parsed.To4() != nil {
			return addrPart
		}
		return ip
	case "/128":
		if parsed := net.ParseIP(addrPart); parsed != nil && parsed.To4() == nil {
			return addrPart
		}
		return ip
	default:
		return ip
	}
}

// ComputeSubnetBroadcast computes the subnet broadcast address for a peer IP.
// If the IP is a bare address (no CIDR), it assumes a /24 subnet and replaces
// the last octet with 255. If the IP includes a CIDR prefix, it computes the
// correct broadcast for any prefix length. Returns the broadcast address as a
// bare IP (no CIDR suffix). Returns an empty string on error.
func ComputeSubnetBroadcast(peerIP string) string {
	if peerIP == "" {
		return ""
	}
	if !containsByte(peerIP, '/') {
		// Bare IP — assume /24 subnet
		parts := splitIPv4(peerIP)
		if parts == nil {
			return ""
		}
		parts[3] = "255"
		return joinIPv4(parts)
	}
	// CIDR notation — compute broadcast from net.IPNet
	ip, ipNet, err := net.ParseCIDR(peerIP)
	if err != nil || ip.To4() == nil {
		return ""
	}
	mask := ipNet.Mask
	broadcast := net.IP(make([]byte, 4))
	for i := 0; i < 4; i++ {
		broadcast[i] = ip.To4()[i] | ^mask[i]
	}
	return broadcast.String()
}

// IsSubnetBroadcastDest checks whether destIP (after stripping /32) is the
// subnet broadcast address for any of the given peerIPs. Returns the matching
// special target ID (SpecialIDSubnetBroadcast) if it matches, or 0 if not.
// This handles both bare IPs (assuming /24) and CIDR-prefixed peer IPs.
func IsSubnetBroadcastDest(destIP string, peerIPs []string) int {
	if len(peerIPs) == 0 {
		return 0
	}
	cleanDest := NormalizeIP(destIP)
	if cleanDest == "" {
		return 0
	}
	for _, peerIP := range peerIPs {
		broadcast := ComputeSubnetBroadcast(peerIP)
		if broadcast != "" && cleanDest == broadcast {
			return SpecialIDSubnetBroadcast
		}
	}
	return 0
}

// IsLimitedBroadcastDest checks whether the given destination IP (after
// stripping /32) is 255.255.255.255 (the limited broadcast address).
func IsLimitedBroadcastDest(destIP string) bool {
	cleanDest := NormalizeIP(destIP)
	return cleanDest == "255.255.255.255"
}

// IsBroadcastDest is a convenience function that checks for both limited and
// subnet broadcast. Returns 0 if not a broadcast, SpecialIDLimitedBroadcast (2)
// for limited broadcast, or SpecialIDSubnetBroadcast (1) for subnet broadcast.
// Only INPUT and DOCKER-USER chains are considered broadcast candidates.
func IsBroadcastDest(destIP string, chain string, peerIPs []string) int {
	if chain != "INPUT" && chain != "DOCKER-USER" {
		return 0
	}
	destIP = NormalizeIP(destIP)
	if destIP == "" {
		return 0
	}
	if destIP == "255.255.255.255" {
		return SpecialIDLimitedBroadcast
	}
	return IsSubnetBroadcastDest(destIP, peerIPs)
}

// --- internal helpers ---

func containsByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}

func splitIPv4(ip string) []string {
	parts := make([]string, 0, 4)
	start := 0
	dotCount := 0
	for i := 0; i < len(ip); i++ {
		if ip[i] == '.' {
			parts = append(parts, ip[start:i])
			start = i + 1
			dotCount++
		}
	}
	if dotCount != 3 {
		return nil
	}
	parts = append(parts, ip[start:])
	if len(parts) != 4 {
		return nil
	}
	return parts
}

func joinIPv4(parts []string) string {
	return parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3]
}
