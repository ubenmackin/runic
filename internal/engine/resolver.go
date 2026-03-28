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
	Protocol  string // tcp|udp|icmp
	PortMatch string // e.g. "--dport 22" or "-m multiport --dports 80,443"
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
	defer rows.Close()

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

// validPortsRe matches comma/colon-separated port numbers (e.g. "22", "80,443", "8000:9000").
var validPortsRe = regexp.MustCompile(`^\d+([,:]\d+)*$`)

// ValidatePorts checks that a ports string contains only digits and separators.
func ValidatePorts(ports string) error {
	if ports == "" {
		return nil
	}
	if !validPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid ports %q: must be digits separated by commas or colons", ports)
	}
	return nil
}

// ExpandPorts returns iptables port match clauses for the given ports string and protocol.
// Returns an error if the ports string contains unsafe characters.
func ExpandPorts(ports string, protocol string) ([]PortClause, error) {
	if ports == "" || protocol == "icmp" {
		return []PortClause{{Protocol: "icmp", PortMatch: ""}}, nil
	}

	if err := ValidatePorts(ports); err != nil {
		return nil, err
	}

	if protocol == "both" {
		tcpClauses := expandPortsSingle(ports, "tcp")
		udpClauses := expandPortsSingle(ports, "udp")
		return append(tcpClauses, udpClauses...), nil
	}

	return expandPortsSingle(ports, protocol), nil
}

func expandPortsSingle(ports string, protocol string) []PortClause {
	if strings.Contains(ports, ",") || strings.Contains(ports, ":") {
		return []PortClause{{Protocol: protocol, PortMatch: fmt.Sprintf("-m multiport --dports %s", ports)}}
	}
	return []PortClause{{Protocol: protocol, PortMatch: fmt.Sprintf("--dport %s", ports)}}
}
