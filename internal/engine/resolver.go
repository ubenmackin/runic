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

// ResolveGroup returns a deduplicated flat list of CIDRs for the given group,
// recursively expanding group_ref members. Circular references detected via visited set.
func (r *Resolver) ResolveGroup(ctx context.Context, groupID int, visited map[int]bool) ([]string, error) {
	if visited[groupID] {
		return nil, fmt.Errorf("circular group reference detected at group %d", groupID)
	}
	visited[groupID] = true

	rows, err := r.db.QueryContext(ctx,
		"SELECT id, group_id, value, type FROM group_members WHERE group_id = ?", groupID)
	if err != nil {
		return nil, fmt.Errorf("query group members: %w", err)
	}
	defer rows.Close()

	type member struct {
		ID      int
		GroupID int
		Value   string
		Type    string
	}

	var members []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.ID, &m.GroupID, &m.Value, &m.Type); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var results []string

	for _, m := range members {
		switch m.Type {
		case "ip":
			if net.ParseIP(m.Value) == nil {
				return nil, fmt.Errorf("invalid IP in group member: %s", m.Value)
			}
			key := m.Value + "/32"
			if !seen[key] {
				seen[key] = true
				results = append(results, key)
			}
		case "cidr":
			if _, _, err := net.ParseCIDR(m.Value); err != nil {
				return nil, fmt.Errorf("invalid CIDR in group member: %s", m.Value)
			}
			if !seen[m.Value] {
				seen[m.Value] = true
				results = append(results, m.Value)
			}
		case "group_ref":
			var refGroupID int
			if _, err := fmt.Sscanf(m.Value, "%d", &refGroupID); err != nil {
				return nil, fmt.Errorf("invalid group_ref value: %s", m.Value)
			}
			nested, err := r.ResolveGroup(ctx, refGroupID, visited)
			if err != nil {
				return nil, err
			}
			for _, addr := range nested {
				if !seen[addr] {
					seen[addr] = true
					results = append(results, addr)
				}
			}
		default:
			return nil, fmt.Errorf("unknown member type: %s", m.Type)
		}
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

