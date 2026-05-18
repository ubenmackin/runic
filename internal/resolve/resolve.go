// Package resolve provides shared IP normalization and special target ID constants
// used by both the engine (compiler/resolver) and the importer.
package resolve

import "net"

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

// NormalizeToCIDR ensures an IP string has a CIDR suffix.
// If the string already contains a "/", it is returned as-is.
func NormalizeToCIDR(ip string) string {
	if ip == "" {
		return ip
	}
	for i := 0; i < len(ip); i++ {
		if ip[i] == '/' {
			return ip
		}
	}
	return ip + "/32"
}

// NormalizeIP strips a "/32" CIDR suffix from an IP string.
// Other CIDR suffixes (e.g., /24, /16) are preserved as they represent subnets.
func NormalizeIP(ip string) string {
	n := len(ip)
	if n >= 3 && ip[n-3:] == "/32" {
		return ip[:n-3]
	}
	return ip
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

// --- internal helpers (no strings import needed at package level) ---

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
