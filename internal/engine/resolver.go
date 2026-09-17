package engine

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"runic/internal/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/resolve"
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
		cidr, err := normalizePeerCIDR(ipAddress, entityID)
		if err != nil {
			return nil, fmt.Errorf("normalize peer %d: %w", entityID, err)
		}
		return []string{cidr}, nil
	}

	return r.ResolveGroup(ctx, entityID)
}

// normalizeCIDR validates an IP or CIDR with the given validator and returns
// it in CIDR notation, appending /32 to bare IPv4 addresses and /128 to bare
// IPv6 addresses. It is the single implementation behind both peer and
// group-member normalization: callers pass resolve.ValidatePeerCIDR
// (plain-or-CIDR, /0 rejected) for direct peer entity resolution so malformed
// input and allow-all CIDRs fail closed, or resolve.ValidateGroupCIDR
// (plain-or-CIDR, /0 permitted) for group members so existing groups
// containing a 0.0.0.0/0 manual peer (any) still compile. Peer ip_address
// fields are CIDR-capable by contract (unlike agent interface addresses,
// which are plain-IP-only); see internal/api/common ValidatePlainIP vs
// ValidatePeerCIDR. The CIDR-vs-bare branch selects the host suffix via "/"
// presence and To4. Logged values are truncated via the shared
// common.TruncateString helper to resolve.MaxLoggedIPLen so unbounded input
// cannot bloat errors.
func normalizeCIDR(ipAddress string, peerID int, validate func(string) error) (string, error) {
	if err := validate(ipAddress); err != nil {
		logged := common.TruncateString(ipAddress, resolve.MaxLoggedIPLen)
		if strings.Contains(ipAddress, "/") {
			return "", fmt.Errorf("invalid CIDR in peer %d: %s: %w: %w", peerID, logged, err, ErrPreviewValidation)
		}
		return "", fmt.Errorf("invalid IP in peer %d: %s: %w: %w", peerID, logged, err, ErrPreviewValidation)
	}
	if strings.Contains(ipAddress, "/") {
		return ipAddress, nil
	}
	if parsed := net.ParseIP(ipAddress); parsed != nil && parsed.To4() == nil {
		return ipAddress + "/128", nil
	}
	return ipAddress + "/32", nil
}

// normalizePeerCIDR validates a peer IP or CIDR and returns it in CIDR
// notation. It delegates to normalizeCIDR with resolve.ValidatePeerCIDR
// (plain-or-CIDR, /0 rejected) so a single misconfigured peer cannot generate
// an allow-all rule; callers needing allow-all must use __any_ip__.
func normalizePeerCIDR(ipAddress string, peerID int) (string, error) {
	return normalizeCIDR(ipAddress, peerID, resolve.ValidatePeerCIDR)
}

// normalizeGroupCIDR validates a group-member IP or CIDR and returns it in
// CIDR notation. It delegates to normalizeCIDR with
// resolve.ValidateGroupCIDR (plain-or-CIDR, /0 permitted) so existing groups
// containing a 0.0.0.0/0 manual peer still compile; peer writes and policy
// overrides stay strict via normalizePeerCIDR.
func normalizeGroupCIDR(ipAddress string, peerID int) (string, error) {
	return normalizeCIDR(ipAddress, peerID, resolve.ValidateGroupCIDR)
}

// ResolveSpecialTarget resolves a special target to IP addresses. Special targets are predefined network addresses like broadcast and multicast.
func (r *Resolver) ResolveSpecialTarget(ctx context.Context, specialID int, peerIP string) ([]string, error) {
	switch specialID {
	case 1: // __subnet_broadcast__ - compute from peer IP via shared helper.
		// Broadcast math lives in resolve.ComputeSubnetBroadcast (bare IP
		// assumes /24, CIDR computes via net.IPNet for any prefix length) so
		// the mask math is not duplicated here. This path only validates
		// fail-closed (IPv4-only, malformed input rejected) and formats the
		// result as a /32 CIDR. Bare-IP garbage like "foo.bar.baz.qux" is
		// rejected by ValidatePeerCIDR before the helper is trusted, and
		// IPv6 (bare or CIDR) fails closed as non-IPv4. Logged values are
		// truncated via common.TruncateString so unbounded input cannot
		// bloat errors.
		if strings.Contains(peerIP, "/") {
			ip, _, err := net.ParseCIDR(peerIP)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR for subnet broadcast: %s: %w: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
			}
			if ip.To4() == nil {
				return nil, fmt.Errorf("non-IPv4 address for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
			}
			broadcast := resolve.ComputeSubnetBroadcast(peerIP)
			if broadcast == "" {
				return nil, fmt.Errorf("invalid CIDR for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
			}
			if parsed := net.ParseIP(broadcast); parsed == nil || parsed.To4() == nil {
				return nil, fmt.Errorf("non-IPv4 address for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
			}
			return []string{broadcast + "/32"}, nil
		}
		if err := resolve.ValidatePeerCIDR(peerIP); err != nil {
			return nil, fmt.Errorf("invalid IPv4 address for subnet broadcast: %s: %w: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
		}
		if parsed := net.ParseIP(peerIP); parsed == nil || parsed.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
		}
		broadcast := resolve.ComputeSubnetBroadcast(peerIP)
		if broadcast == "" {
			return nil, fmt.Errorf("invalid IPv4 address for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
		}
		if parsed := net.ParseIP(broadcast); parsed == nil || parsed.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address for subnet broadcast: %s: %w", common.TruncateString(peerIP, resolve.MaxLoggedIPLen), ErrPreviewValidation)
		}
		return []string{broadcast + "/32"}, nil
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
				log.WarnContext(ctx, "close rows", "error", cErr)
			}
		}()
		peers := make([]string, 0)
		for rows.Next() {
			var ip string
			if err := rows.Scan(&ip); err != nil {
				return nil, fmt.Errorf("failed to scan peer IP: %w", err)
			}
			// Validate before normalizing: NormalizeToCIDR appends "/32" to
			// unparseable input by design, so invalid DB values must fail
			// closed here rather than propagate as "<bad>/32". ValidatePeerCIDR
			// (not plain ValidateIPOrCIDR) so a stored /0 allow-all CIDR fails
			// closed instead of expanding to every peer. Logged values are
			// truncated so unbounded DB input cannot bloat errors.
			if err := resolve.ValidatePeerCIDR(ip); err != nil {
				return nil, fmt.Errorf("invalid peer IP %q for __all_peers__: %w: %w", common.TruncateString(ip, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
			}
			// Normalize to CIDR notation: append /32 to bare IPv4 and /128
			// to bare IPv6 so a single host is represented, not a range.
			peers = append(peers, resolve.NormalizeToCIDR(ip))
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("error iterating peers: %w", err)
		}
		return peers, nil
	case 8: // __igmpv3__
		return []string{"224.0.0.22/32"}, nil
	case 9: // __internet__ - return marker for compiler to handle with ipset negation.
		// The marker is NOT a valid iptables address. Callers must translate it
		// via the runic_private_ranges ipset path and must fail closed (return
		// an error) when the target host has no ipset support, so the marker
		// never reaches a "-d"/"-s" rule literal.
		return []string{resolve.InternetSentinel}, nil
	default:
		return nil, fmt.Errorf("unknown special target ID: %d: %w", specialID, ErrPreviewValidation)
	}
}

// ResolveGroup resolves a group to IP addresses. In the new schema, groups contain only peers. We look up each peer's IP address.
func (r *Resolver) ResolveGroup(ctx context.Context, groupID int) ([]string, error) {

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
			log.WarnContext(ctx, "close rows", "error", cErr)
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

		cidr, err := normalizeGroupCIDR(ipAddress, peerID)
		if err != nil {
			return nil, fmt.Errorf("normalize group member %d: %w", peerID, err)
		}
		if !seen[cidr] {
			seen[cidr] = true
			results = append(results, cidr)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group members: %w", err)
	}

	return results, nil
}

var ValidPortsRe = regexp.MustCompile(`^\d+([,:]\d+)*$`)

// ValidatePorts returns nil if ports is empty or a valid comma-separated
// list of ports and port ranges. Each port must be in 1-65535 and each
// range a:b must satisfy a <= b. The "1000:2000:3000" form (three colons)
// is rejected because iptables only supports a single start:end range per
// token; multi-colon strings would silently be treated as a literal port
// name and either fail to load or match nothing.
func ValidatePorts(ports string) error {
	if ports == "" {
		return nil
	}
	if !ValidPortsRe.MatchString(ports) {
		return fmt.Errorf("invalid ports %q: must be digits separated by commas or colons", ports)
	}
	// Reject malformed ranges: a colon token must contain exactly two
	// numeric parts. We split on "," and re-check each segment; a segment
	// with more than one colon is structurally invalid.
	for _, seg := range strings.Split(ports, ",") {
		if c := strings.Count(seg, ":"); c > 1 {
			return fmt.Errorf("invalid ports %q: port range %q has more than one colon", ports, seg)
		}
		if err := validatePortSegment(ports, seg); err != nil {
			return err
		}
	}
	return nil
}

// validatePortSegment checks a single comma-separated token: either a single
// port or an a:b range. Ports must be in 1-65535 and ranges must satisfy
// a <= b.
func validatePortSegment(ports, seg string) error {
	if strings.Contains(seg, ":") {
		parts := strings.SplitN(seg, ":", 2)
		lo, err := strconv.Atoi(parts[0])
		if err != nil {
			return fmt.Errorf("invalid ports %q: invalid port %q: %w", ports, parts[0], err)
		}
		hi, err := strconv.Atoi(parts[1])
		if err != nil {
			return fmt.Errorf("invalid ports %q: invalid port %q: %w", ports, parts[1], err)
		}
		if lo < 1 || lo > 65535 || hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid ports %q: port range %q out of range 1-65535", ports, seg)
		}
		if lo > hi {
			return fmt.Errorf("invalid ports %q: port range %q start greater than end", ports, seg)
		}
		return nil
	}
	p, err := strconv.Atoi(seg)
	if err != nil {
		return fmt.Errorf("invalid ports %q: invalid port %q: %w", ports, seg, err)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("invalid ports %q: port %q out of range 1-65535", ports, seg)
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

// ValidateIPSetName checks that the full ipset name (including any prefix like "runic_group_")
// does not exceed the Linux kernel limit of 32 characters.
func ValidateIPSetName(fullName string) error {
	if len(fullName) > 32 {
		return fmt.Errorf("ipset name %q is %d characters, exceeds Linux kernel limit of 32", fullName, len(fullName))
	}
	return nil
}

// Rules: lowercase, replace all non-alphanumeric characters (except underscore) with underscore,
// collapse multiple underscores into one, enforce the Linux 32-character ipset name limit
// (truncating from the right), then trim leading/trailing underscores so a cut on an underscore
// is cleaned up before the name is returned. The Linux kernel limits ipset names to 32
// characters including any prefix like "runic_group_".
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

	// Enforce 32-character Linux kernel ipset name limit.
	// The "runic_group_" prefix takes 12 characters, leaving 20 for the group name.
	// Truncate from the right to preserve the most meaningful part. Truncation is
	// applied BEFORE the final trim so that a cut on an underscore gets cleaned up.
	if len(result) > 20 {
		result = result[:20]
	}

	// Trim AFTER truncation so any trailing underscore introduced by the slice
	// is removed (e.g., "group_a_very_long_name" → "group_a_very_long" → "group_a_very_long").
	result = strings.Trim(result, "_")

	return result
}

type IpsetMember struct {
	Address string // normalized CIDR (bare IPv4 as /32, bare IPv6 as /128)
}

// resolveGroupForIpset resolves a group to ipset members. All members are
// normalized to CIDR notation (bare IPv4 as /32, bare IPv6 as /128), so every
// group ipset uses hash:net, which holds both host (/32, /128) and subnet
// entries. hash:ip is intentionally unused: a single set type avoids churn
// when a group gains its first subnet member.
func (r *Resolver) resolveGroupForIpset(ctx context.Context, groupID int) ([]IpsetMember, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT p.ip_address
		FROM group_members gm
		JOIN peers p ON gm.peer_id = p.id
		JOIN groups g ON gm.group_id = g.id
		WHERE gm.group_id = ? AND g.is_pending_delete = 0`, groupID)
	if err != nil {
		return nil, fmt.Errorf("query group members for ipset: %w", err)
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.WarnContext(ctx, "close rows", "error", cErr)
		}
	}()

	var members []IpsetMember
	seen := map[string]bool{}

	for rows.Next() {
		var ipAddress string
		if err := rows.Scan(&ipAddress); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}

		// Validate first (fail closed on corrupt DB values): NormalizeToCIDR
		// appends "/32" to unparseable input by design, so normalizing before
		// validation would let "<bad>/32" through. ValidateGroupCIDR relies on
		// net.ParseIP/net.ParseCIDR, which already reject malformed input,
		// and permits /0 allow-all CIDRs so existing groups containing a
		// 0.0.0.0/0 member still compile. Logged values are truncated so
		// unbounded DB input cannot bloat errors.
		if err := resolve.ValidateGroupCIDR(ipAddress); err != nil {
			return nil, fmt.Errorf("invalid IP in group %d: %s: %w: %w", groupID, common.TruncateString(ipAddress, resolve.MaxLoggedIPLen), err, ErrPreviewValidation)
		}

		// Dedup and store the normalized CIDR so textually distinct but
		// semantically identical members ("10.0.0.1" vs "10.0.0.1/32")
		// collapse to a single ipset member, matching ResolveGroup.
		// Bare IPv4 becomes /32 and bare IPv6 becomes /128.
		dedupKey := resolve.NormalizeToCIDR(ipAddress)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		members = append(members, IpsetMember{
			Address: dedupKey,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate group members for ipset: %w", err)
	}

	return members, nil
}
