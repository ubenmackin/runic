package engine

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"

	"runic/internal/db"
)

type Resolver struct {
	db db.Querier
}

type PortClause struct {
	Protocol     string // tcp|udp|icmp
	PortMatch    string // e.g. "--dport 22" or "-m multiport --dports 80,443"
	SrcPortMatch string // e.g. "--sport 67" or "-m multiport --sports 5353"
}

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

// ResolveSpecialTarget resolves a special target to IP addresses. Special targets are predefined network addresses like broadcast and multicast.
func (r *Resolver) ResolveSpecialTarget(ctx context.Context, specialID int, peerIP string) ([]string, error) {
	switch specialID {
	case 1: // __subnet_broadcast__ - compute from peer IP
		// Compute the subnet broadcast address from the peer IP.
		// If the peer IP is a CIDR (e.g., "10.100.5.0/24"), use net.IPNet to
		// calculate the correct broadcast for any prefix length (not just /24).
		// If it is a bare IP, fall back to setting the last octet to 255
		// (assumes /24, which is the common case for bare-IP peers).
		if strings.Contains(peerIP, "/") {
			ip, ipNet, err := net.ParseCIDR(peerIP)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR for subnet broadcast: %s: %w", peerIP, err)
			}
			if ip.To4() == nil {
				return nil, fmt.Errorf("non-IPv4 address for subnet broadcast: %s", peerIP)
			}
			// Compute broadcast: OR the network address with the inverted mask
			mask := ipNet.Mask
			broadcast := net.IP(make([]byte, 4))
			for i := 0; i < 4; i++ {
				broadcast[i] = ip.To4()[i] | ^mask[i]
			}
			broadcastAddr := broadcast.String() + "/32"
			return []string{broadcastAddr}, nil
		}
		// Bare IP — assume /24 subnet
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

// ResolveGroup resolves a group to IP addresses. In the new schema, groups contain only peers. We look up each peer's IP address.
func (r *Resolver) ResolveGroup(ctx context.Context, groupID int, visited map[int]bool) ([]string, error) {
	// Note: visited is kept for API compatibility but not used since we no longer have nested groups

	rows, err := r.db.QueryContext(ctx, `
		SELECT p.id, p.ip_address, p.is_manual
		FROM group_members gm
		JOIN peers p ON gm.peer_id = p.id
		JOIN groups g ON gm.group_id = g.id
		WHERE gm.group_id = ? AND g.is_pending_delete = 0`, groupID)
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

var ValidPortsRe = regexp.MustCompile(`^\d+([,:]\d+)*$`)

func ValidatePorts(ports string) error {
	if ports == "" {
		return nil
	}
	if !ValidPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid ports %q: must be digits separated by commas or colons", ports)
	}
	return nil
}

// ExpandPorts returns an error if the ports strings contain unsafe characters.
func ExpandPorts(dstPorts string, srcPorts string, protocol string) ([]PortClause, error) {
	// ICMP has no port concept
	if protocol == "icmp" {
		return []PortClause{{Protocol: "icmp", PortMatch: "", SrcPortMatch: ""}}, nil
	}

	// IGMP has no port concept
	if protocol == "igmp" {
		return []PortClause{{Protocol: "igmp", PortMatch: "", SrcPortMatch: ""}}, nil
	}

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

func expandPortsSingle(dstPorts string, srcPorts string, protocol string) []PortClause {
	var dstMatch, srcMatch string

	if dstPorts != "" {
		if strings.Contains(dstPorts, ",") || strings.Contains(dstPorts, ":") {
			dstMatch = fmt.Sprintf("-m multiport --dports %s", dstPorts)
		} else {
			dstMatch = fmt.Sprintf("--dport %s", dstPorts)
		}
	}

	if srcPorts != "" {
		if strings.Contains(srcPorts, ",") || strings.Contains(srcPorts, ":") {
			srcMatch = fmt.Sprintf("-m multiport --sports %s", srcPorts)
		} else {
			srcMatch = fmt.Sprintf("--sport %s", srcPorts)
		}
	}

	return []PortClause{{Protocol: protocol, PortMatch: dstMatch, SrcPortMatch: srcMatch}}
}

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

type IpsetMember struct {
	Address string // IP or CIDR
	IsCIDR  bool   // true if Address contains a network prefix
}

// It returns a slice of IpsetMember and a boolean indicating whether any member is a CIDR.
// CIDR members require hash:net ipset type, while pure IP members use hash:ip.
func (r *Resolver) resolveGroupForIpset(ctx context.Context, groupID int) ([]IpsetMember, bool, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.ip_address
		FROM group_members gm
		JOIN peers p ON gm.peer_id = p.id
		JOIN groups g ON gm.group_id = g.id
		WHERE gm.group_id = ? AND g.is_pending_delete = 0`, groupID)
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
