package engine

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Resolver resolves groups into flat lists of CIDRs and expands port specifications.
type Resolver struct {
	db *sql.DB
}

// PortClause represents a single iptables port match clause.
type PortClause struct {
	Protocol     string // tcp|udp|icmp
	PortMatch    string // e.g. "--dport 22" or "-m multiport --dports 80,443"
	SrcPortMatch string // e.g. "--sport 67" or "-m multiport --sports 5353"
}

// ResolveEntity returns a deduplicated flat list of CIDRs for the given entity (peer or group).
func (r *Resolver) ResolveEntity(ctx context.Context, entityType string, entityID int) ([]string, error) {
	if entityType == "peer" {
		var ipAddress string
		if err := r.db.QueryRowContext(ctx, "SELECT ip_address FROM peers WHERE id = ?", entityID).Scan(&ipAddress); err != nil {
			return nil, fmt.Errorf("resolve peer %d: %w", entityID, err)
		}
		if strings.Contains(ipAddress, "/") {
			if _, _, err := net.ParseCIDR(ipAddress); err != nil {
				return nil, fmt.Errorf("invalid CIDR in peer %d: %s", entityID, ipAddress)
			}
			return []string{ipAddress}, nil
		}
		if net.ParseIP(ipAddress) == nil {
			return nil, fmt.Errorf("invalid IP in peer %d: %s", entityID, ipAddress)
		}
		return []string{ipAddress + "/32"}, nil
	}

	return r.ResolveGroup(ctx, entityID, nil)
}

// ResolveSpecialTarget returns the IP address for a special target.
// Special targets are predefined network addresses like broadcast and multicast.
// For subnet_broadcast (ID 1), the address is computed from the peer's IP.
func (r *Resolver) ResolveSpecialTarget(ctx context.Context, specialID int, peerIP string) ([]string, error) {
	switch specialID {
	case 1: // __subnet_broadcast__ - compute from peer IP
		// Extract subnet and replace last octet with 255
		// E.g., 10.100.5.36 -> 10.100.5.255
		parts := strings.Split(peerIP, ".")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid IPv4 address for subnet broadcast: %s", peerIP)
		}
		parts[3] = "255"
		broadcastAddr := strings.Join(parts, ".") + "/32"
		return []string{broadcastAddr}, nil
	case 2: // __limited_broadcast__
		return []string{"255.255.255.255/32"}, nil
	case 3: // __all_hosts__ (IGMP)
		return []string{"224.0.0.1/32"}, nil
	case 4: // __mdns__
		return []string{"224.0.0.251/32"}, nil
	case 5: // __loopback__
		return []string{"127.0.0.1/32"}, nil
	case 6: // __any_ip__
		return []string{"0.0.0.0/0"}, nil
	case 7: // __all_peers__
		rows, err := r.db.QueryContext(ctx, "SELECT ip_address FROM peers")
		if err != nil {
			return nil, fmt.Errorf("failed to query peers: %w", err)
		}
		defer func() {
			if cErr := rows.Close(); cErr != nil {
				fmt.Printf("close err: %v\n", cErr)
			}
		}()
		peers := make([]string, 0)
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				return nil, fmt.Errorf("failed to scan peer IP: %w", err)
			}
			peers = append(peers, ip)
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating peers: %w", err)
		}
		return peers, nil
	case 8: // __igmpv3__
		return []string{"224.0.0.22/32"}, nil
	case 9: // __internet__ - return marker for compiler to handle with ipset negation
		return []string{"__internet__"}, nil
	default:
		return nil, fmt.Errorf("unknown special target ID: %d", specialID)
	}
}

// ResolveGroup returns a deduplicated flat list of CIDRs for the given group.
// In the new schema, groups contain only peers. We look up each peer's IP address.
func (r *Resolver) ResolveGroup(ctx context.Context, groupID int, visited map[int]bool) ([]string, error) {
	// Note: visited is kept for API compatibility but not used since we no longer have nested groups

	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id, p.ip_address, p.is_manual
		FROM group_members gm
		JOIN peers p ON gm.peer_id = p.id
		WHERE gm.group_id = ?`, groupID)
	if err != nil {
		return nil, fmt.Errorf("query group members: %w", err)
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			fmt.Printf("close err: %v\n", cErr)
		}
	}()

	seen := map[string]bool{}
	var results []string

	for rows.Next() {
		var peerID int
		var ipAddress string
		var isManual bool
		if err := rows.Scan(&peerID, &ipAddress, &isManual); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}

		// The peer's ip_address is either a single IP or a CIDR notation
		// Validate and normalize it
		if strings.Contains(ipAddress, "/") {
			// CIDR notation
			if _, _, err := net.ParseCIDR(ipAddress); err != nil {
				return nil, fmt.Errorf("invalid CIDR in peer %d: %s", peerID, ipAddress)
			}
			if !seen[ipAddress] {
				seen[ipAddress] = true
				results = append(results, ipAddress)
			}
		} else {
			// Single IP - convert to /32 CIDR
			if net.ParseIP(ipAddress) == nil {
				return nil, fmt.Errorf("invalid IP in peer %d: %s", peerID, ipAddress)
			}
			cidr := ipAddress + "/32"
			if !seen[cidr] {
				seen[cidr] = true
				results = append(results, cidr)
			}
		}
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return results, nil
}

// ValidPortsRe matches comma/colon-separated port numbers (e.g. "22", "80,443", "8000:9000").
var ValidPortsRe = regexp.MustCompile(`^\d+([,:]\d+)*$`)

// ValidatePorts checks that a ports string contains only digits and separators.
func ValidatePorts(ports string) error {
	if ports == "" {
		return nil
	}
	if !ValidPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid ports %q: must be digits separated by commas or colons", ports)
	}
	return nil
}

// ExpandPorts returns iptables port match clauses for the given destination and source ports strings and protocol.
// Returns an error if the ports strings contain unsafe characters.
func ExpandPorts(dstPorts string, srcPorts string, protocol string) ([]PortClause, error) {
	// ICMP has no port concept
	if protocol == "icmp" {
		return []PortClause{{Protocol: "icmp", PortMatch: "", SrcPortMatch: ""}}, nil
	}

	// IGMP has no port concept
	if protocol == "igmp" {
		return []PortClause{{Protocol: "igmp", PortMatch: "", SrcPortMatch: ""}}, nil
	}

	// Validate both port strings
	if err := ValidatePorts(dstPorts); err != nil {
		return nil, fmt.Errorf("destination ports: %w", err)
	}
	if err := ValidatePorts(srcPorts); err != nil {
		return nil, fmt.Errorf("source ports: %w", err)
	}

	// Handle empty ports - at least one should be specified for non-ICMP
	if dstPorts == "" && srcPorts == "" {
		return nil, fmt.Errorf("at least one port type (destination or source) required for protocol %s", protocol)
	}

	if protocol == "both" {
		tcpClauses := expandPortsSingle(dstPorts, srcPorts, "tcp")
		udpClauses := expandPortsSingle(dstPorts, srcPorts, "udp")
		return append(tcpClauses, udpClauses...), nil
	}

	return expandPortsSingle(dstPorts, srcPorts, protocol), nil
}

// expandPortsSingle generates port clauses for a single protocol.
func expandPortsSingle(dstPorts string, srcPorts string, protocol string) []PortClause {
	var dstMatch, srcMatch string

	// Generate destination port match
	if dstPorts != "" {
		if strings.Contains(dstPorts, ",") || strings.Contains(dstPorts, ":") {
			dstMatch = fmt.Sprintf("-m multiport --dports %s", dstPorts)
		} else {
			dstMatch = fmt.Sprintf("--dport %s", dstPorts)
		}
	}

	// Generate source port match
	if srcPorts != "" {
		if strings.Contains(srcPorts, ",") || strings.Contains(srcPorts, ":") {
			srcMatch = fmt.Sprintf("-m multiport --sports %s", srcPorts)
		} else {
			srcMatch = fmt.Sprintf("--sport %s", srcPorts)
		}
	}

	return []PortClause{{Protocol: protocol, PortMatch: dstMatch, SrcPortMatch: srcMatch}}
}

// sanitizeForIpset converts a group name into a valid ipset name component.
// Rules: lowercase, replace all non-alphanumeric characters (except underscore) with underscore,
// collapse multiple underscores into one, trim leading/trailing underscores.
func sanitizeForIpset(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	prevUnderscore := false
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevUnderscore = false
		} else if !prevUnderscore {
			b.WriteRune('_')
			prevUnderscore = true
		}
	}
	result := b.String()
	result = strings.Trim(result, "_")
	return result
}

// IpsetMember represents a single member of an ipset.
type IpsetMember struct {
	Address string // IP or CIDR
	IsCIDR  bool   // true if Address contains a network prefix
}

// resolveGroupForIpset returns the members of a group suitable for ipset generation.
// It returns a slice of IpsetMember and a boolean indicating whether any member is a CIDR.
// CIDR members require hash:net ipset type, while pure IP members use hash:ip.
func (r *Resolver) resolveGroupForIpset(ctx context.Context, groupID int) ([]IpsetMember, bool, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.ip_address
		FROM group_members gm
		JOIN peers p ON gm.peer_id = p.id
		WHERE gm.group_id = ?`, groupID)
	if err != nil {
		return nil, false, fmt.Errorf("query group members for ipset: %w", err)
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			fmt.Printf("close err: %v\n", cErr)
		}
	}()

	var members []IpsetMember
	hasCIDR := false
	seen := map[string]bool{}

	for rows.Next() {
		var ipAddress string
		if err := rows.Scan(&ipAddress); err != nil {
			return nil, false, fmt.Errorf("scan group member: %w", err)
		}

		if seen[ipAddress] {
			continue
		}
		seen[ipAddress] = true

		isCIDR := strings.Contains(ipAddress, "/")
		if isCIDR {
			if _, _, err := net.ParseCIDR(ipAddress); err != nil {
				return nil, false, fmt.Errorf("invalid CIDR in peer %d: %s", groupID, ipAddress)
			}
			hasCIDR = true
		} else if net.ParseIP(ipAddress) == nil {
			return nil, false, fmt.Errorf("invalid IP in peer: %s", ipAddress)
		}

		members = append(members, IpsetMember{
			Address: ipAddress,
			IsCIDR:  isCIDR,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	return members, hasCIDR, nil
}
