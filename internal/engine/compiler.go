// Package engine provides policy compilation and resolution.
package engine

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

// Special target IDs for multicast groups
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

// isMulticastSpecialID returns true if the special target ID is a multicast group
func isMulticastSpecialID(id int) bool {
	return id == SpecialIDAllHosts || id == SpecialIDmDNS || id == SpecialIDIGMPv3
}

// isBroadcastSpecialID returns true if the special target ID is a broadcast address
func isBroadcastSpecialID(id int) bool {
	return id == SpecialIDSubnetBroadcast || id == SpecialIDLimitedBroadcast
}

// Compiler compiles firewall policies into iptables-restore payloads.
type Compiler struct {
	db       *sql.DB
	resolver *Resolver
}

// NewCompiler creates a new Compiler with the given database.
func NewCompiler(database *sql.DB) *Compiler {
	return &Compiler{
		db:       database,
		resolver: &Resolver{db: database},
	}
}

// policyInfo holds the extracted policy fields needed for rule compilation.
type policyInfo struct {
	ID          int
	Name        string
	SourceID    int
	SourceType  string
	ServiceID   int
	TargetID    int
	TargetType  string
	Action      string
	Priority    int
	TargetScope string
	Direction   string
	IsTarget    bool
	IsSource    bool
}

// ruleWriter writes iptables rules for a specific action to a strings.Builder.
// The match parameter contains everything between "-A CHAIN" and "-j ACTION".
type ruleWriter struct{ buf *strings.Builder }

func (rw *ruleWriter) accept(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j ACCEPT\n", chain, match)
}

func (rw *ruleWriter) drop(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j DROP\n", chain, match)
}

func (rw *ruleWriter) logDrop(chain, match string) {
	fmt.Fprintf(rw.buf, "-A %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", chain, match)
	rw.drop(chain, match)
}

func (rw *ruleWriter) writeAction(action, chain, match string) {
	switch action {
	case "ACCEPT":
		rw.accept(chain, match)
	case "DROP":
		rw.drop(chain, match)
	case "LOG_DROP":
		rw.logDrop(chain, match)
	}
}

// formatEntityName returns a human-readable name for an entity (special, peer, or group).
func (c *Compiler) formatEntityName(ctx context.Context, entityType string, entityID int) string {
	switch entityType {
	case "special":
		return c.getSpecialDisplayName(entityID)
	case "peer":
		var hostname string
		err := c.db.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", entityID).Scan(&hostname)
		if err == sql.ErrNoRows {
			return fmt.Sprintf("peer %d (not found)", entityID)
		}
		if err != nil {
			return fmt.Sprintf("peer %d", entityID)
		}
		return hostname
	case "group":
		var name string
		err := c.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ? AND is_pending_delete = 0", entityID).Scan(&name)
		if err == sql.ErrNoRows {
			return fmt.Sprintf("group %d (not found)", entityID)
		}
		if err != nil {
			return fmt.Sprintf("group %d", entityID)
		}
		return name
	default:
		return fmt.Sprintf("%s %d", entityType, entityID)
	}
}

// getSpecialDisplayName returns the human-readable name for a special target ID.
func (c *Compiler) getSpecialDisplayName(specialID int) string {
	names := map[int]string{
		SpecialIDSubnetBroadcast:  "Subnet Broadcast",
		SpecialIDLimitedBroadcast: "Limited Broadcast",
		SpecialIDAllHosts:         "All Hosts (IGMP)",
		SpecialIDmDNS:             "mDNS",
		SpecialIDLoopback:         "Loopback",
		SpecialIDAnyIP:            "Any IP",
		SpecialIDAllPeers:         "All Peers",
		SpecialIDIGMPv3:           "IGMPv3",
		SpecialIDInternet:         "Internet",
	}
	if name, ok := names[specialID]; ok {
		return name
	}
	return fmt.Sprintf("special %d", specialID)
}

func (rw *ruleWriter) newline() {
	rw.buf.WriteString("\n")
}

func (rw *ruleWriter) writeStandardRules(hasDocker bool, controlPlanePort string) {
	// loopback
	rw.buf.WriteString("# --- Standard: loopback ---\n")
	rw.buf.WriteString("-A INPUT -i lo -j ACCEPT\n")
	rw.buf.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	rw.buf.WriteString("\n")

	// ICMP RELATED
	rw.buf.WriteString("# --- Standard: ICMP RELATED ---\n")
	rw.buf.WriteString("-A INPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.buf.WriteString("-A OUTPUT -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
	rw.buf.WriteString("\n")

	// INVALID
	rw.buf.WriteString("# --- Standard: INVALID packet drop ---\n")
	rw.buf.WriteString("-A INPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.buf.WriteString("-A OUTPUT -m conntrack --ctstate INVALID -j DROP\n")
	rw.buf.WriteString("\n")

	// Control Plane Communication
	if controlPlanePort != "" {
		rw.buf.WriteString("# --- Standard: Control Plane Communication ---\n")
		fmt.Fprintf(rw.buf, "# Allows agent to communicate with control plane on port %s\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A OUTPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort)
		fmt.Fprintf(rw.buf, "-A INPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort)
		rw.buf.WriteString("\n")
	}

	// Docker standard rules
	if hasDocker {
		rw.buf.WriteString("# --- Docker: Standard rules for DOCKER-USER ---\n")
		rw.buf.WriteString("-A DOCKER-USER -p icmp -m conntrack --ctstate RELATED -j ACCEPT\n")
		rw.buf.WriteString("-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP\n")
		rw.buf.WriteString("\n")
	}
}

// Compile produces a complete iptables-restore payload for the given peer.
func (c *Compiler) Compile(ctx context.Context, peerID int) (string, error) {
	// 1. Load peer
	var hostname, ipAddress string
	var hasDocker, hasIPSet bool
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker, COALESCE(has_ipset, false) FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress, &hasDocker, &hasIPSet)
	if err != nil {
		return "", fmt.Errorf("load peer %d: %w", peerID, err)
	}
	// 2. Load enabled policies where peer is either target or source, ordered by priority ASC
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, p.action, p.priority, p.target_scope, COALESCE(p.direction, 'both'),
		CASE WHEN p.target_type = 'peer' AND p.target_id = ? THEN 1
		WHEN p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ? THEN 1
		ELSE 0 END as is_target,
		-- MC-EXCLUSION: Multicast special targets (3,4,8) are excluded from is_source
		-- because they represent destinations for outbound multicast, not sources.
		-- BC-EXCLUSION: Broadcast special targets (1,2) are excluded for the same reason.
		-- When Source is broadcast special, the peer is the target (receiving broadcast).
		CASE WHEN p.source_type = 'peer' AND p.source_id = ? THEN 1
		WHEN p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.source_type = 'special' AND p.target_type = 'group' AND p.source_id NOT IN (?, ?, ?, ?, ?) AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0) THEN 1
		WHEN p.source_type = 'special' AND p.target_type = 'peer' AND p.source_id NOT IN (?, ?, ?, ?, ?) AND p.target_id = ? THEN 1
		ELSE 0 END as is_source
		FROM policies p
		WHERE p.enabled = 1 AND p.is_pending_delete = 0 AND (
		(p.target_type = 'peer' AND p.target_id = ?) OR
		(p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.source_type = 'peer' AND p.source_id = ?) OR
		(p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.source_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ?) OR
		(p.source_type = 'special' AND p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members gm JOIN groups g ON gm.group_id = g.id WHERE gm.group_id = p.target_id AND gm.peer_id = ? AND g.is_pending_delete = 0)) OR
		(p.source_type = 'special' AND p.target_type = 'peer' AND p.target_id = ?)
		)
		ORDER BY p.priority ASC`,
		peerID, peerID, peerID, peerID, peerID, peerID, SpecialIDSubnetBroadcast, SpecialIDLimitedBroadcast, SpecialIDAllHosts, SpecialIDmDNS, SpecialIDIGMPv3, peerID, SpecialIDSubnetBroadcast, SpecialIDLimitedBroadcast, SpecialIDAllHosts, SpecialIDmDNS, SpecialIDIGMPv3, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID)
	if err != nil {
		return "", fmt.Errorf("load policies: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("close err", "err", err)
		}
	}()

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		var isTargetInt, isSourceInt int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceID, &p.SourceType, &p.ServiceID, &p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.TargetScope, &p.Direction, &isTargetInt, &isSourceInt); err != nil {
			return "", fmt.Errorf("scan policy: %w", err)
		}
		p.IsTarget = isTargetInt == 1
		p.IsSource = isSourceInt == 1
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	groupIDToName := make(map[int]string)
	var groupOrder []int // preserve insertion order
	for i := range policies {
		pol := &policies[i]
		if pol.SourceType == "group" {
			if _, exists := groupIDToName[pol.SourceID]; !exists {
				var groupName string
				if err := c.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ? AND is_pending_delete = 0", pol.SourceID).Scan(&groupName); err == nil {
					groupIDToName[pol.SourceID] = groupName
					groupOrder = append(groupOrder, pol.SourceID)
				}
				// skip non-existent groups silently
			}
		}
		if pol.TargetType == "group" {
			if _, exists := groupIDToName[pol.TargetID]; !exists {
				var groupName string
				if err := c.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ? AND is_pending_delete = 0", pol.TargetID).Scan(&groupName); err == nil {
					groupIDToName[pol.TargetID] = groupName
					groupOrder = append(groupOrder, pol.TargetID)
				}
				// skip non-existent groups silently
			}
		}
	}

	// 2a. Pre-load all services referenced by these policies (batch load)
	serviceIDs := make(map[int]bool)
	for i := range policies {
		p := &policies[i]
		serviceIDs[p.ServiceID] = true
	}
	// MC-006: Include no_conntrack column
	services := make(map[int]struct {
		Name, Ports, SourcePorts, Protocol string
		NoConntrack                        bool
	})
	if len(serviceIDs) > 0 {
		// Build the IN clause
		serviceIDList := make([]int, 0, len(serviceIDs))
		for id := range serviceIDs {
			serviceIDList = append(serviceIDList, id)
		}

		placeholders := make([]string, len(serviceIDList))
		args := make([]interface{}, len(serviceIDList))
		for i, id := range serviceIDList {
			placeholders[i] = "?"
			args[i] = id
		}
		// MC-006: Updated query to include no_conntrack
		query := "SELECT id, name, ports, COALESCE(source_ports,''), protocol, COALESCE(no_conntrack, 0) FROM services WHERE is_pending_delete = 0 AND id IN (" + strings.Join(placeholders, ",") + ")"

		rows, err := c.db.QueryContext(ctx, query, args...)
		if err != nil {
			return "", fmt.Errorf("batch load services: %w", err)
		}
		defer func() {
			if err := rows.Close(); err != nil {
				log.Warn("close err", "err", err)
			}
		}()

		for rows.Next() {
			var sid int
			var s struct {
				Name, Ports, SourcePorts, Protocol string
				NoConntrack                        bool
			}
			if err := rows.Scan(&sid, &s.Name, &s.Ports, &s.SourcePorts, &s.Protocol, &s.NoConntrack); err != nil {
				return "", fmt.Errorf("scan service: %w", err)
			}
			services[sid] = s
		}
		if err := rows.Err(); err != nil {
			return "", err
		}
	}

	// 2c. Resolve ipset data if peer supports it, and build group->ipset mapping simultaneously
	type ipsetData struct {
		Name    string // sanitized ipset name (e.g. runic_group_webservers)
		SetType string // hash:ip or hash:net
		Members []string
	}
	var ipsets []ipsetData
	groupIDToIpsetName := make(map[int]string)
	if hasIPSet && len(groupOrder) > 0 {
		for _, gid := range groupOrder {
			members, hasCIDR, err := c.resolver.resolveGroupForIpset(ctx, gid)
			if err != nil {
				return "", fmt.Errorf("resolve group %d for ipset: %w", gid, err)
			}
			setType := "hash:ip"
			if hasCIDR {
				setType = "hash:net"
			}
			sanitizedName := "runic_group_" + sanitizeForIpset(groupIDToName[gid])
			var addrs []string
			for _, m := range members {
				addrs = append(addrs, m.Address)
			}
			ipsets = append(ipsets, ipsetData{
				Name:    sanitizedName,
				SetType: setType,
				Members: addrs,
			})
			groupIDToIpsetName[gid] = sanitizedName
		}
	}

	// 3. Build the iptables-restore output
	var buf strings.Builder
	rw := &ruleWriter{buf: &buf}
	now := time.Now().UTC().Format(time.RFC3339)

	// Header comment
	buf.WriteString("# Runic rule bundle\n")
	fmt.Fprintf(&buf, "# Host: %s\n", hostname)
	fmt.Fprintf(&buf, "# Generated: %s\n", now)
	fmt.Fprintf(&buf, "# Policies: %d\n", len(policies))
	if hasIPSet && len(ipsets) > 0 {
		fmt.Fprintf(&buf, "# Ipsets: %d\n", len(ipsets))
	}

	// Ipset definitions (before *filter)
	if hasIPSet && len(ipsets) > 0 {
		buf.WriteString("\n# --- Ipset Definitions ---\n")
		for _, is := range ipsets {
			fmt.Fprintf(&buf, "create %s %s family inet\n", is.Name, is.SetType)
			for _, member := range is.Members {
				fmt.Fprintf(&buf, "add %s %s\n", is.Name, member)
			}
			buf.WriteString("\n")
		}
	}

	// Add __internet__ private ranges ipset (used for negation to allow all non-private IPs)
	privateCIDRs := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"}
	if hasIPSet {
		buf.WriteString("# --- Ipset: Private Ranges for __internet__ exclusion ---\n")
		buf.WriteString("create runic_private_ranges hash:net family inet\n")
		for _, cidr := range privateCIDRs {
			fmt.Fprintf(&buf, "add runic_private_ranges %s\n", cidr)
		}
		buf.WriteString("\n")
	}

	// Filter table and chain policies
	buf.WriteString("*filter\n")
	buf.WriteString(":INPUT DROP [0:0]\n")
	buf.WriteString(":OUTPUT DROP [0:0]\n")
	buf.WriteString(":FORWARD DROP [0:0]\n")

	// Docker chain declaration if needed
	if hasDocker {
		buf.WriteString(":DOCKER-USER - [0:0]\n")
	}

	buf.WriteString("\n")

	// Query control plane port before calling writeStandardRules
	var controlPlanePort string
	if err := c.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'control_plane_port'").Scan(&controlPlanePort); err != nil {
		log.WarnContext(ctx, "Failed to load control_plane_port, using default 8080", "error", err)
		controlPlanePort = "8080"
	}

	// Standard rules (extracted to helper)
	rw.writeStandardRules(hasDocker, controlPlanePort)

	// Policy rules
	for i := range policies {
		pol := &policies[i]
		writeToHost := pol.TargetScope == "host" || pol.TargetScope == "both"
		writeToDocker := hasDocker && (pol.TargetScope == "docker" || pol.TargetScope == "both")

		// Get service from pre-loaded map
		svc, ok := services[pol.ServiceID]
		if !ok {
			return "", fmt.Errorf("service %d not found", pol.ServiceID)
		}
		serviceName := svc.Name
		ports := svc.Ports
		sourcePorts := svc.SourcePorts
		protocol := svc.Protocol
		noConntrack := svc.NoConntrack

		// Expand ports for non-multicast, non-broadcast, and non-IGMP/VRRP services
		var portClauses []PortClause
		isBroadcastService := serviceName == "Subnet Broadcast" || serviceName == "Limited Broadcast"
		isIGMPorVRRP := strings.EqualFold(serviceName, "IGMP") || strings.EqualFold(serviceName, "VRRP")
		if serviceName != "Multicast" && !isBroadcastService && !isIGMPorVRRP {
			portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
			if err != nil {
				return "", fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
			}
		}

		fmt.Fprintf(&buf, "# --- Policy: %s ---\n", pol.Name)

		// IG-001: Special IGMP handling - skip normal source/target resolution
		// VRRP-001: Special VRRP handling - skip normal source/target resolution
		if strings.EqualFold(serviceName, "IGMP") || strings.EqualFold(serviceName, "VRRP") {
			if writeToHost {
				if strings.EqualFold(serviceName, "IGMP") {
					c.writeIGMPRules(rw, pol.TargetScope, hasDocker)
				} else if strings.EqualFold(serviceName, "VRRP") {
					c.writeVRRPRules(rw, pol.TargetScope, hasDocker)
				}
			}
			buf.WriteString("\n")
			continue // Skip to next policy
		}

		// Process as TARGET (Ingress traffic)
		// Only emit if direction is 'both' or 'backward' (backward = target receives inbound from source)
		// MD-001: Skip "As Target" when target is a multicast/broadcast special.
		// When target is a multicast group (mDNS, All Hosts, IGMPv3) or broadcast address,
		// the peer is the source of outbound traffic to that address. Generating "As Target"
		// ingress rules would create self-referencing rules (INPUT from the peer's own IP)
		// which are nonsensical. The useful rules are generated in the "As Source" block.
		isSpecialMulticastOrBroadcastTarget := pol.TargetType == "special" &&
			(isMulticastSpecialID(pol.TargetID) || isBroadcastSpecialID(pol.TargetID))
		if pol.IsTarget && (pol.Direction == "both" || pol.Direction == "backward") && !isSpecialMulticastOrBroadcastTarget {
			sourceName := c.formatEntityName(ctx, pol.SourceType, pol.SourceID)
			fmt.Fprintf(&buf, "# As Target (Ingress from %s)\n", sourceName)

			// MC-009: Multicast special targets as Source indicate the host receives multicast traffic
			// When Source is a multicast special target (IDs 3=__all_hosts__, 4=__mdns__, 8=__igmpv3__),
			// this means the host should receive multicast traffic from that group - GENERATE INPUT rules
			isMulticastSource := pol.SourceType == "special" && isMulticastSpecialID(pol.SourceID)
			// BC-003: Broadcast special targets as Source indicate the host receives broadcast traffic
			// When Source is a broadcast special target (IDs 1=__subnet_broadcast__, 2=__limited_broadcast__),
			// this means the host should receive broadcast traffic - GENERATE INPUT rules with -d (destination)
			isBroadcastSource := pol.SourceType == "special" && isBroadcastSpecialID(pol.SourceID)

			// Check if we should use ipset for this source
			useIpset := hasIPSet && pol.SourceType == "group"
			var ipsetName string
			if useIpset {
				ipsetName = groupIDToIpsetName[pol.SourceID]
				useIpset = ipsetName != ""
			}

			switch {
			case isMulticastSource:
				// Multicast source: use packet type matching for receiving multicast traffic
				c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
			case isBroadcastSource:
				// Broadcast source: resolve the broadcast address and use -d (destination) matching
				cidrs, err := c.resolver.ResolveSpecialTarget(ctx, pol.SourceID, ipAddress)
				if err != nil {
					return "", fmt.Errorf("resolve broadcast source for policy %s: %w", pol.Name, err)
				}
				// Generate broadcast rules for each resolved CIDR
				for _, cidr := range cidrs {
					c.writeBroadcastRule(rw, pol.Action, pol.TargetScope, hasDocker, cidr)
				}
			case useIpset:
				// Use ipset-based rules (single rule per port clause)
				if serviceName == "Multicast" {
					c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
				} else {
					rules, err := c.writeTargetRules(ctx, pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack)
					if err != nil {
						return "", err
					}
					for _, rule := range rules {
						rw.buf.WriteString(rule + "\n")
					}
				}
			default:
				// Use individual rules (fallback for non-group or non-ipset peers)
				var cidrs []string
				var err error
				if pol.SourceType == "special" {
					cidrs, err = c.resolver.ResolveSpecialTarget(ctx, pol.SourceID, ipAddress)
				} else {
					cidrs, err = c.resolver.ResolveEntity(ctx, pol.SourceType, pol.SourceID)
				}
				if err != nil {
					return "", fmt.Errorf("resolve source for policy %s: %w", pol.Name, err)
				}
				if serviceName == "Multicast" {
					c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
				} else {
					rules, err := c.writeTargetRules(ctx, pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack)
					if err != nil {
						return "", err
					}
					for _, rule := range rules {
						rw.buf.WriteString(rule + "\n")
					}
				}
			}
		}

		// Process as SOURCE (Egress traffic)
		// Only emit if direction is 'both' or 'forward' (forward = source sends outbound to target)
		if pol.IsSource && (pol.Direction == "both" || pol.Direction == "forward") {
			targetName := c.formatEntityName(ctx, pol.TargetType, pol.TargetID)
			fmt.Fprintf(&buf, "# As Source (Egress to %s)\n", targetName)

			// Check if target is __internet__ special target - use ipset negation
			isInternetTarget := pol.TargetType == "special" && pol.TargetID == SpecialIDInternet
			useInternetIpset := hasIPSet && isInternetTarget

			// Check if we should use ipset for this target
			useIpset := hasIPSet && pol.TargetType == "group"
			var ipsetName string
			if useIpset {
				ipsetName = groupIDToIpsetName[pol.TargetID]
				useIpset = ipsetName != ""
			}

			switch {
			case useIpset:
				// Use ipset-based rules (single rule per port clause)
				if serviceName == "Multicast" {
					// MC-012: Only generate OUTPUT multicast rule when Target is a multicast special target
					isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
					if isMulticastTarget && pol.Action == "ACCEPT" {
						buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					}
				} else {
					isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
					rules, err := c.writeSourceRules(ctx, pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, isMulticastTarget)
					if err != nil {
						return "", err
					}
					for _, rule := range rules {
						rw.buf.WriteString(rule + "\n")
					}
				}
			case useInternetIpset:
				// __internet__ special target: use ipset negation to exclude private ranges
				isMulticastTarget := false
				rules, err := c.writeInternetRules(ctx, pol, portClauses, ipAddress, writeToHost, writeToDocker, noConntrack, isMulticastTarget)
				if err != nil {
					return "", err
				}
				for _, rule := range rules {
					rw.buf.WriteString(rule + "\n")
				}
			default:
				// Use individual rules (fallback for non-group or non-ipset peers)
				var cidrs []string
				var err error
				if pol.TargetType == "special" {
					cidrs, err = c.resolver.ResolveSpecialTarget(ctx, pol.TargetID, ipAddress)
				} else {
					cidrs, err = c.resolver.ResolveEntity(ctx, pol.TargetType, pol.TargetID)
				}
				if err != nil {
					return "", fmt.Errorf("resolve target for policy %s: %w", pol.Name, err)
				}
				if serviceName == "Multicast" {
					// MC-012: Only generate OUTPUT multicast rule when Target is a multicast special target
					isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
					if isMulticastTarget && pol.Action == "ACCEPT" {
						buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					}
				} else {
					isMulticastTarget := pol.TargetType == "special" && isMulticastSpecialID(pol.TargetID)
					rules, err := c.writeSourceRules(ctx, pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, isMulticastTarget)
					if err != nil {
						return "", err
					}
					for _, rule := range rules {
						rw.buf.WriteString(rule + "\n")
					}
				}
			}
		}

		buf.WriteString("\n")
	}

	// Logging and default deny (always last)
	buf.WriteString("# --- Logging and default deny ---\n")
	buf.WriteString("-A INPUT -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
	buf.WriteString("-A INPUT -j DROP\n")
	buf.WriteString("-A OUTPUT -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
	buf.WriteString("-A OUTPUT -j DROP\n")

	// Docker section: RETURN at the end of DOCKER-USER chain
	if hasDocker {
		buf.WriteString("\n")
		buf.WriteString("# --- Docker: DOCKER-USER chain default ---\n")
		buf.WriteString("-A DOCKER-USER -j RETURN\n")
	}

	buf.WriteString("\nCOMMIT\n")

	return buf.String(), nil
}

// writeIGMPRules generates fixed IGMP rules for all hosts communication.
// IGMP is connectionless multicast, so no conntrack or return rules are needed.
func (c *Compiler) writeIGMPRules(rw *ruleWriter, targetScope string, hasDocker bool) {
	writeToHost := targetScope == "host" || targetScope == "both"
	writeToDocker := hasDocker && (targetScope == "docker" || targetScope == "both")

	if writeToHost {
		// Accept IGMP queries (224.0.0.1 = All Hosts on this subnet)
		rw.accept("INPUT", "-d 224.0.0.1/32 -p igmp")
		// Send IGMPv3 reports (224.0.0.22 = IGMPv3 routers)
		rw.accept("OUTPUT", "-d 224.0.0.22/32 -p igmp")
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", "-d 224.0.0.1/32 -p igmp")
		rw.accept("DOCKER-USER", "-d 224.0.0.22/32 -p igmp")
	}
}

// writeVRRPRules generates fixed VRRP rules for VRRP communication.
// VRRP is a protocol for virtual router redundancy, using multicast 224.0.0.18.
// No conntrack or return rules are needed.
func (c *Compiler) writeVRRPRules(rw *ruleWriter, targetScope string, hasDocker bool) {
	writeToHost := targetScope == "host" || targetScope == "both"
	writeToDocker := hasDocker && (targetScope == "docker" || targetScope == "both")

	if writeToHost {
		// Accept VRRP advertisements (224.0.0.18 = VRRP multicast)
		rw.accept("OUTPUT", "-d 224.0.0.18/32 -p vrrp")
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", "-d 224.0.0.18/32 -p vrrp")
	}
}

// writeMulticastRule generates multicast tracking rules using a ruleWriter.
func (c *Compiler) writeMulticastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool) {
	writeToHost := targetScope == "host" || targetScope == "both"
	writeToDocker := hasDocker && (targetScope == "docker" || targetScope == "both")

	if writeToHost {
		rw.writeAction(action, "INPUT", "-m pkttype --pkt-type multicast")
	}
	if writeToDocker {
		rw.writeAction(action, "DOCKER-USER", "-m pkttype --pkt-type multicast")
	}
	rw.newline()
}

// writeBroadcastRule generates broadcast acceptance rules using a ruleWriter.
// Broadcast traffic is connectionless, so no conntrack or return rules are needed.
// For broadcast, we match on destination (-d) since broadcast packets are sent TO the broadcast address.
func (c *Compiler) writeBroadcastRule(rw *ruleWriter, action string, targetScope string, hasDocker bool, broadcastAddr string) {
	writeToHost := targetScope == "host" || targetScope == "both"
	writeToDocker := hasDocker && (targetScope == "docker" || targetScope == "both")

	if writeToHost {
		// Accept broadcast traffic destined for the broadcast address
		rw.accept("INPUT", fmt.Sprintf("-d %s -p udp", broadcastAddr))
	}
	if writeToDocker {
		rw.accept("DOCKER-USER", fmt.Sprintf("-d %s -p udp", broadcastAddr))
	}
}

// writeTargetRules writes ingress (target) rules for a policy.
// When useIpset is true, ipsetName contains the ipset to match against.
// When useIpset is false, cidrs contains the individual CIDRs to generate rules for.
// noConntrack when true skips conntrack marking for multicast protocols.
func (c *Compiler) writeTargetRules(
	ctx context.Context,
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
) ([]string, error) {
	var rules []string
	for _, pc := range portClauses {
		inputPortMatch := pc.PortMatch
		if pc.SrcPortMatch != "" {
			inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
		}
		outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		var conntrackFull string
		if noConntrack {
			conntrackFull = ""
		} else {
			conntrackFull = "-m conntrack --ctstate NEW,ESTABLISHED"
		}

		// Handle LOG_DROP action by generating two rules: LOG then DROP
		handleLogDrop := func(action, chain, match string) {
			if action == "LOG_DROP" {
				rules = append(rules,
					fmt.Sprintf("-A %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4", chain, match),
					fmt.Sprintf("-A %s %s -j DROP", chain, match),
				)
			} else {
				rules = append(rules, fmt.Sprintf("-A %s %s -j %s", chain, match, action))
			}
		}

		if useIpset {
			ipsetMatchSrc := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			ipsetMatchDst := fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			if writeToHost {
				if pol.Action == "ACCEPT" {
					rules = append(rules,
						fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchSrc, inputPortMatch, conntrackFull, pol.Action),
						fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, ipsetMatchDst, outputPortMatch, conntrackFull),
					)
				} else {
					handleLogDrop(pol.Action, "INPUT", fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchSrc, inputPortMatch))
				}
			}
			if writeToDocker {
				if pol.Action == "ACCEPT" {
					rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchSrc, inputPortMatch, conntrackFull, pol.Action))
				} else {
					handleLogDrop(pol.Action, "DOCKER-USER", fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatchSrc, inputPortMatch))
				}
			}
		} else {
			for _, cidr := range cidrs {
				if writeToHost {
					if pol.Action == "ACCEPT" {
						rules = append(rules,
							fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j %s", cidr, pc.Protocol, inputPortMatch, conntrackFull, pol.Action),
							fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j ACCEPT", cidr, pc.Protocol, outputPortMatch, conntrackFull),
						)
					} else {
						handleLogDrop(pol.Action, "INPUT", fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, inputPortMatch))
					}
				}
				if writeToDocker {
					if pol.Action == "ACCEPT" {
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s %s -j %s", cidr, pc.Protocol, inputPortMatch, conntrackFull, pol.Action))
					} else {
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j %s", cidr, pc.Protocol, inputPortMatch, pol.Action))
					}
				}
			}
		}
	}
	return rules, nil
}

// writeSourceRules writes egress (source) rules for a policy.
// When useIpset is true, ipsetName contains the ipset to match against.
// When useIpset is false, cidrs contains the individual CIDRs to generate rules for.
// noConntrack when true skips conntrack marking for multicast protocols.
// isMulticastTarget when true indicates the target is a multicast special target (3=__all_hosts__, 4=__mdns__, 8=__igmpv3__)
func (c *Compiler) writeSourceRules(
	ctx context.Context,
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	isMulticastTarget bool,
) ([]string, error) {
	var rules []string
	for _, pc := range portClauses {
		outputPortMatch := pc.PortMatch
		if pc.SrcPortMatch != "" {
			outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
		}
		inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		// For bidirectional policies, we need NEW,ESTABLISHED for both outbound and return traffic
		var conntrackFull string
		if noConntrack {
			conntrackFull = ""
		} else {
			conntrackFull = "-m conntrack --ctstate NEW,ESTABLISHED"
		}

		// MC-010/MD-002: For multicast targets, determine INPUT return rule behavior.
		// When noConntrack is true (e.g., mDNS), skip INPUT return rules entirely.
		// mDNS responses arrive as multicast themselves, so a separate INPUT return
		// rule is unnecessary and overly permissive (would accept from 0.0.0.0/0).
		// When noConntrack is false, use 0.0.0.0/0 with conntrack ESTABLISHED state
		// since responses come from individual hosts, not the multicast address.
		var returnCIDRs []string
		if isMulticastTarget {
			if noConntrack {
				// Skip INPUT return rules for no_conntrack multicast services
				returnCIDRs = nil
			} else {
				returnCIDRs = []string{"0.0.0.0/0"}
			}
		} else {
			returnCIDRs = cidrs
		}

		// Filter out self-referencing rules (peer connecting to itself)
		filteredCidrs := make([]string, 0, len(cidrs))
		for _, cidr := range cidrs {
			if cidr != ipAddress+"/32" {
				filteredCidrs = append(filteredCidrs, cidr)
			}
		}
		cidrs = filteredCidrs

		// Same for returnCIDRs
		filteredReturnCidrs := make([]string, 0, len(returnCIDRs))
		for _, cidr := range returnCIDRs {
			if cidr != ipAddress+"/32" {
				filteredReturnCidrs = append(filteredReturnCidrs, cidr)
			}
		}
		returnCIDRs = filteredReturnCidrs

		if useIpset {
			ipsetMatchSrc := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			ipsetMatchDst := fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			rules = append(rules,
				fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchDst, outputPortMatch, conntrackFull, pol.Action),
				fmt.Sprintf("-A INPUT -p %s %s %s %s -j %s", pc.Protocol, ipsetMatchSrc, inputPortMatch, conntrackFull, pol.Action),
			)
		} else {
			for _, cidr := range cidrs {
				if pol.Action == "ACCEPT" {
					rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s %s -j %s", cidr, pc.Protocol, outputPortMatch, conntrackFull, pol.Action))
				} else {
					rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s -j %s", cidr, pc.Protocol, outputPortMatch, pol.Action))
				}
			}
			// Write INPUT rules from returnCIDRs (either specific CIDRs or 0.0.0.0/0 for multicast)
			for _, returnCidr := range returnCIDRs {
				if pol.Action == "ACCEPT" {
					rules = append(rules, fmt.Sprintf("-A INPUT -s %s -p %s %s %s -j ACCEPT", returnCidr, pc.Protocol, inputPortMatch, conntrackFull))
				}
			}
		}
	}
	return rules, nil
}

// writeInternetRules generates rules for the __internet__ special target.
// Uses ipset negation to match all IPs except private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).
func (c *Compiler) writeInternetRules(
	ctx context.Context,
	pol *policyInfo,
	portClauses []PortClause,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	isMulticastTarget bool,
) ([]string, error) {
	var rules []string
	privateIpsetMatch := "-m set ! --match-set runic_private_ranges dst"

	for _, pc := range portClauses {
		outputPortMatch := pc.PortMatch
		if pc.SrcPortMatch != "" {
			outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
		}
		inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		var conntrackFull string
		if noConntrack {
			conntrackFull = ""
		} else {
			conntrackFull = "-m conntrack --ctstate NEW,ESTABLISHED"
		}

		// Use negation ipset match to exclude private ranges
		privateIpsetMatchSrc := "-m set ! --match-set runic_private_ranges src"
		if writeToHost {
			if pol.Action == "ACCEPT" {
				rules = append(rules,
					fmt.Sprintf("-A OUTPUT -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, outputPortMatch, conntrackFull, pol.Action),
					fmt.Sprintf("-A INPUT -p %s %s %s %s -j ACCEPT", pc.Protocol, privateIpsetMatchSrc, inputPortMatch, conntrackFull),
				)
			} else {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -p %s %s %s -j %s", pc.Protocol, privateIpsetMatch, outputPortMatch, pol.Action))
			}
		}
		if writeToDocker {
			if pol.Action == "ACCEPT" {
				rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s %s -j %s", pc.Protocol, privateIpsetMatch, outputPortMatch, conntrackFull, pol.Action))
			} else {
				rules = append(rules, fmt.Sprintf("-A DOCKER-USER -p %s %s %s -j %s", pc.Protocol, privateIpsetMatch, outputPortMatch, pol.Action))
			}
		}
	}
	return rules, nil
}

// PreviewCompile generates a preview of iptables rules for a policy without storing them.
// Unlike Compile(), this is policy-centric: it resolves both source and target entities
// and generates rules based on direction, showing the complete picture across all hosts.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceID int, sourceType string, targetID int, targetType string, serviceID int, direction string, targetScope string) ([]string, error) {
	// Load a peer IP for special target resolution (uses peerID as reference)
	var ipAddress string
	if peerID != 0 {
		if err := c.db.QueryRowContext(ctx,
			"SELECT ip_address FROM peers WHERE id = ?", peerID,
		).Scan(&ipAddress); err != nil && err != sql.ErrNoRows {
			// Log but don't fail - IP is optional for preview
			log.WarnContext(ctx, "Failed to load peer IP for preview", "error", err)
		}
	}

	// Default direction
	if direction == "" {
		direction = "both"
	}

	// Default target_scope
	if targetScope == "" {
		targetScope = "both"
	}

	var rules []string

	// Load service - MC-011: Include no_conntrack column
	var serviceName, ports, sourcePorts, protocol string
	var noConntrack bool
	err := c.db.QueryRowContext(ctx, "SELECT name, ports, source_ports, protocol, COALESCE(no_conntrack, 0) FROM services WHERE id = ? AND is_pending_delete = 0", serviceID).Scan(&serviceName, &ports, &sourcePorts, &protocol, &noConntrack)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("service %d is pending delete or does not exist", serviceID)
	}
	if err != nil {
		return nil, fmt.Errorf("load service: %w", err)
	}

	var portClauses []PortClause
	// Skip port expansion for special services that don't use ports
	isIGMPorVRRP := strings.EqualFold(serviceName, "IGMP") || strings.EqualFold(serviceName, "VRRP")
	if serviceName != "Multicast" && !isIGMPorVRRP {
		portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
		if err != nil {
			return nil, fmt.Errorf("expand ports: %w", err)
		}
	}

	// Resolve source CIDRs
	var sourceCIDRs []string
	if sourceType == "special" {
		sourceCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, sourceID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve source special target %d: %w", sourceID, err)
		}
	} else {
		sourceCIDRs, err = c.resolver.ResolveEntity(ctx, sourceType, sourceID)
		if err != nil {
			return nil, fmt.Errorf("resolve source entity %s/%d: %w", sourceType, sourceID, err)
		}
	}

	// Resolve target CIDRs
	var targetCIDRs []string
	if targetType == "special" {
		targetCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, targetID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve target special target %d: %w", targetID, err)
		}
	} else {
		targetCIDRs, err = c.resolver.ResolveEntity(ctx, targetType, targetID)
		if err != nil {
			return nil, fmt.Errorf("resolve target entity %s/%d: %w", targetType, targetID, err)
		}
	}

	// Check if target is __internet__ special target
	isInternetTarget := targetType == "special" && targetID == SpecialIDInternet

	// Build policy info for helper functions
	pol := &policyInfo{
		Action: "ACCEPT", // Preview assumes ACCEPT for rule generation
	}

	// Forward: Source initiates connections TO Target
	// Source hosts get: OUTPUT to target + INPUT established from target
	// Target hosts get: INPUT from source + OUTPUT established to source
	if targetScope == "host" || targetScope == "both" {
		// IG-002: Special IGMP handling - skip normal source/target resolution
		// VRRP-002: Special VRRP handling - skip normal source/target resolution
		switch {
		case strings.EqualFold(serviceName, "IGMP"):
			// IG-002: Special IGMP handling
			rules = append(rules,
				"-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT",
				"-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT",
			)
		case strings.EqualFold(serviceName, "VRRP"):
			// VRRP-002: Special VRRP handling (advertisements are sent to 224.0.0.18)
			rules = append(rules, "-A OUTPUT -d 224.0.0.18/32 -p vrrp -j ACCEPT")
		case direction == "both" || direction == "forward":
			rules = append(rules, "# Forward (Source → Target)")
			for _, targetCIDR := range targetCIDRs {
				if serviceName == "Multicast" {
					// MC-012: Only generate OUTPUT multicast rule when Target is a multicast special target
					isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
					if isMulticastTarget {
						rules = append(rules, "-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
					}
					continue
				}
				_ = targetCIDR // suppress unused variable warning
			}
			// Use writeSourceRules for forward direction (egress)
			if isInternetTarget {
				// Use writeInternetRules for internet target
				writeRules, err := c.writeInternetRules(ctx, pol, portClauses, ipAddress, true, false, noConntrack, false)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			} else {
				// Use writeSourceRules for regular targets
				isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
				writeRules, err := c.writeSourceRules(ctx, pol, portClauses, false, "", targetCIDRs, ipAddress, true, false, noConntrack, isMulticastTarget)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			}
		}

		// Backward: Target initiates connections TO Source
		// Target hosts get: OUTPUT to source + INPUT established from source
		// Source hosts get: INPUT from target + OUTPUT established to target
		// IG-002: Skip backward for IGMP (already handled above)
		// VRRP-002: Skip backward for VRRP (already handled above)
		if !strings.EqualFold(serviceName, "IGMP") && !strings.EqualFold(serviceName, "VRRP") && (direction == "both" || direction == "backward") {
			rules = append(rules, "# Backward (Target → Source)")
			// MC-009: Multicast special targets as Source indicate receiving multicast traffic
			isMulticastSource := sourceType == "special" && isMulticastSpecialID(sourceID)
			// BC-003: Broadcast special targets as Source indicate receiving broadcast traffic
			isBroadcastSource := sourceType == "special" && isBroadcastSpecialID(sourceID)
			switch {
			case isMulticastSource:
				// Multicast source: use packet type matching for receiving multicast traffic
				if serviceName == "Multicast" {
					rules = append(rules, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT")
				} else {
					// For non-Multicast services with multicast special source, generate INPUT rules
					writeRules, err := c.writeTargetRules(ctx, pol, portClauses, false, "", sourceCIDRs, ipAddress, true, false, noConntrack)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			case isBroadcastSource:
				// Broadcast source: use -d (destination) matching since broadcast packets are sent TO the broadcast address
				for _, sourceCIDR := range sourceCIDRs {
					rules = append(rules, fmt.Sprintf("-A INPUT -d %s -p udp -j ACCEPT", sourceCIDR))
				}
			default:
				// Use writeTargetRules for backward direction (ingress from source perspective)
				writeRules, err := c.writeTargetRules(ctx, pol, portClauses, false, "", sourceCIDRs, ipAddress, true, false, noConntrack)
				if err != nil {
					return nil, err
				}
				rules = append(rules, writeRules...)
			}
		}
	}

	// Docker: DOCKER-USER chain rules (for Docker containers)
	// Generated when targetScope is "docker" or "both"
	if targetScope == "docker" || targetScope == "both" {
		// IG-002: Special IGMP handling for Docker
		// VRRP-002: Special VRRP handling for Docker
		switch {
		case strings.EqualFold(serviceName, "IGMP"):
			// IG-002: Special IGMP handling for Docker
			rules = append(rules,
				"-A DOCKER-USER -d 224.0.0.1/32 -p igmp -j ACCEPT",
				"-A DOCKER-USER -d 224.0.0.22/32 -p igmp -j ACCEPT",
			)
		case strings.EqualFold(serviceName, "VRRP"):
			// VRRP-002: Special VRRP handling (advertisements are sent to 224.0.0.18)
			rules = append(rules, "-A DOCKER-USER -d 224.0.0.18/32 -p vrrp -j ACCEPT")
		default:
			rules = append(rules, "# Docker: DOCKER-USER chain rules")
			// Forward direction: Source → Target (Docker)
			if direction == "both" || direction == "forward" {
				for _, targetCIDR := range targetCIDRs {
					if serviceName == "Multicast" {
						rules = append(rules, "-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT")
						continue
					}
					_ = targetCIDR // suppress unused variable warning
				}
				// Use writeSourceRules for Docker forward direction (egress to Docker)
				if isInternetTarget {
					writeRules, err := c.writeInternetRules(ctx, pol, portClauses, ipAddress, false, true, noConntrack, false)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				} else {
					isMulticastTarget := targetType == "special" && isMulticastSpecialID(targetID)
					writeRules, err := c.writeSourceRules(ctx, pol, portClauses, false, "", targetCIDRs, ipAddress, false, true, noConntrack, isMulticastTarget)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			}
			// Backward direction: Target (Docker) ← Source
			// IG-002: Skip backward for IGMP (already handled above)
			// VRRP-002: Skip backward for VRRP (already handled above)
			if !strings.EqualFold(serviceName, "IGMP") && !strings.EqualFold(serviceName, "VRRP") && (direction == "both" || direction == "backward") {
				// MC-009: Multicast special targets as Source indicate receiving multicast traffic
				isMulticastSource := sourceType == "special" && isMulticastSpecialID(sourceID)
				// BC-003: Broadcast special targets as Source indicate receiving broadcast traffic
				isBroadcastSource := sourceType == "special" && isBroadcastSpecialID(sourceID)
				switch {
				case isMulticastSource:
					// Multicast source: use packet type matching for receiving multicast traffic
					if serviceName == "Multicast" {
						rules = append(rules, "-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT")
					} else {
						// For non-Multicast services with multicast special source, generate DOCKER-USER INPUT rules
						writeRules, err := c.writeTargetRules(ctx, pol, portClauses, false, "", sourceCIDRs, ipAddress, false, true, noConntrack)
						if err != nil {
							return nil, err
						}
						rules = append(rules, writeRules...)
					}
				case isBroadcastSource:
					// Broadcast source: use -d (destination) matching for broadcast traffic
					for _, sourceCIDR := range sourceCIDRs {
						rules = append(rules, fmt.Sprintf("-A DOCKER-USER -d %s -p udp -j ACCEPT", sourceCIDR))
					}
				default:
					// Use writeTargetRules for Docker backward direction
					writeRules, err := c.writeTargetRules(ctx, pol, portClauses, false, "", sourceCIDRs, ipAddress, false, true, noConntrack)
					if err != nil {
						return nil, err
					}
					rules = append(rules, writeRules...)
				}
			}
		}
	}

	return rules, nil
}

// CompileAndStore compiles the rules for a peer, signs them, and stores the bundle.
func (c *Compiler) CompileAndStore(ctx context.Context, peerID int) (models.RuleBundleRow, error) {
	content, err := c.Compile(ctx, peerID)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("compile: %w", err)
	}

	// Fetch the peer's HMAC key from the database
	var hmacKey string
	err = c.db.QueryRowContext(ctx, "SELECT hmac_key FROM peers WHERE id = ?", peerID).Scan(&hmacKey)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("fetch peer HMAC key: %w", err)
	}

	version := Version(content)
	signature := Sign(content, hmacKey)

	// Compute next version number for this peer
	var versionNumber int
	err = c.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version_number), 0) + 1 FROM rule_bundles WHERE peer_id = ?", peerID).Scan(&versionNumber)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("get next version number: %w", err)
	}

	// Use db.SaveBundle to avoid duplicate transaction logic
	params := models.CreateBundleParams{
		PeerID:        peerID,
		Version:       version,
		VersionNumber: versionNumber,
		RulesContent:  content,
		HMAC:          signature,
	}

	bundle, err := db.SaveBundle(ctx, c.db, params)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("save bundle: %w", err)
	}

	return bundle, nil
}

// RecompileAffectedPeers finds all peers affected by a group change and recompiles their bundles.
func (c *Compiler) RecompileAffectedPeers(ctx context.Context, groupID int) error {
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT id FROM policies WHERE is_pending_delete = 0 AND ((source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?)) AND enabled = 1`, groupID, groupID)
	if err != nil {
		return fmt.Errorf("find affected policies: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Warn("close err", "err", err)
		}
	}()

	var policyIDs []int
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			return err
		}
		policyIDs = append(policyIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	peerSet := make(map[int]bool)
	for _, pid := range policyIDs {
		affected, err := c.GetAffectedPeersByPolicy(ctx, pid)
		if err != nil {
			log.ErrorContext(ctx, "Failed to get affected peers for recompile", "policy_id", pid, "error", err)
			continue
		}
		for _, peerID := range affected {
			peerSet[peerID] = true
		}
	}

	for peerID := range peerSet {
		if _, err := c.CompileAndStore(ctx, peerID); err != nil {
			return fmt.Errorf("recompile peer %d: %w", peerID, err)
		}
	}
	return nil
}

// GetAffectedPeersByPolicy returns all peer IDs that need recompilation if a policy changes.
// It finds any peer present in either the source or target of the policy.
func (c *Compiler) GetAffectedPeersByPolicy(ctx context.Context, policyID int) ([]int, error) {
	var srcType, tgtType string
	var srcID, tgtID int
	if err := c.db.QueryRowContext(ctx, "SELECT source_type, source_id, target_type, target_id FROM policies WHERE id = ? AND is_pending_delete = 0", policyID).Scan(&srcType, &srcID, &tgtType, &tgtID); err != nil {
		return nil, fmt.Errorf("get policy abstract: %w", err)
	}

	peers := make(map[int]bool)

	// Process source - handle peer, group, and special types
	// Note: Even if source is special, we still check target for peer/group
	switch srcType {
	case "peer":
		peers[srcID] = true
	case "group":
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm.peer_id
			FROM group_members gm
			JOIN groups g ON gm.group_id = g.id
			WHERE gm.group_id = ? AND g.is_pending_delete = 0
		`, srcID)
		if err != nil {
			return nil, fmt.Errorf("query source group members for policy %d: %w", policyID, err)
		}
		if rows != nil {
			defer func() {
				if cErr := rows.Close(); cErr != nil {
					log.Warn("close err", "err", cErr)
				}
			}()
			for rows.Next() {
				var p int
				if err := rows.Scan(&p); err == nil {
					peers[p] = true
				} else {
					log.Warn("Failed to scan peer from group", "error", err)
				}
			}
		}
	}

	// Process target - handle peer, group, and special types
	// Note: Even if target is special, we still check source for peer/group
	switch tgtType {
	case "peer":
		peers[tgtID] = true
	case "group":
		rows, err := c.db.QueryContext(ctx, `
			SELECT DISTINCT gm.peer_id
			FROM group_members gm
			JOIN groups g ON gm.group_id = g.id
			WHERE gm.group_id = ? AND g.is_pending_delete = 0
		`, tgtID)
		if err != nil {
			return nil, fmt.Errorf("query target group members for policy %d: %w", policyID, err)
		}
		if rows != nil {
			defer func() {
				if cErr := rows.Close(); cErr != nil {
					log.Warn("close err", "err", cErr)
				}
			}()
			for rows.Next() {
				var p int
				if err := rows.Scan(&p); err != nil {
					log.Warn("Failed to scan peer from target group", "error", err)
				} else {
					peers[p] = true
				}
			}
		}
	}

	var peerList []int
	for id := range peers {
		peerList = append(peerList, id)
	}
	return peerList, nil
}

// invertPortMatch swaps destination and source port matches for egress rules.
// For egress traffic, the destination ports become source ports and vice versa.
// Example: dstMatch="--dport 80", srcMatch="--sport 5353" -> "--sport 80 --dport 5353"
func invertPortMatch(dstMatch, srcMatch string) string {
	var result string

	// Convert destination port match to source port match
	if dstMatch != "" {
		result = strings.ReplaceAll(dstMatch, "--dport", "--sport")
		result = strings.ReplaceAll(result, "--dports", "--sports")
	}

	// Convert source port match to destination port match and append
	if srcMatch != "" {
		srcToDst := strings.ReplaceAll(srcMatch, "--sport", "--dport")
		srcToDst = strings.ReplaceAll(srcToDst, "--sports", "--dports")
		if result != "" {
			result = result + " " + srcToDst
		} else {
			result = srcToDst
		}
	}

	return result
}
