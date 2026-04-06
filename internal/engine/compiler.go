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
		     WHEN p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.target_id AND peer_id = ?) THEN 1
		     WHEN p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.source_id AND peer_id = ?) THEN 1
		     WHEN p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ? THEN 1
		     ELSE 0 END as is_target,
		CASE WHEN p.source_type = 'peer' AND p.source_id = ? THEN 1
		     WHEN p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.source_id AND peer_id = ?) THEN 1
		     WHEN p.source_type = 'special' AND p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.target_id AND peer_id = ?) THEN 1
		     WHEN p.source_type = 'special' AND p.target_type = 'peer' AND p.target_id = ? THEN 1
		     ELSE 0 END as is_source
		FROM policies p
		WHERE p.enabled = 1 AND (
			(p.target_type = 'peer' AND p.target_id = ?) OR
			(p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.target_id AND peer_id = ?)) OR
			(p.source_type = 'peer' AND p.source_id = ?) OR
			(p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.source_id AND peer_id = ?)) OR
			(p.target_type = 'special' AND p.source_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.source_id AND peer_id = ?)) OR
			(p.target_type = 'special' AND p.source_type = 'peer' AND p.source_id = ?) OR
			(p.source_type = 'special' AND p.target_type = 'group' AND EXISTS (SELECT 1 FROM group_members WHERE group_id = p.target_id AND peer_id = ?)) OR
			(p.source_type = 'special' AND p.target_type = 'peer' AND p.target_id = ?)
		)
		ORDER BY p.priority ASC`,
		peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID, peerID)
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
				if err := c.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ?", pol.SourceID).Scan(&groupName); err == nil {
					groupIDToName[pol.SourceID] = groupName
					groupOrder = append(groupOrder, pol.SourceID)
				}
				// skip non-existent groups silently
			}
		}
		if pol.TargetType == "group" {
			if _, exists := groupIDToName[pol.TargetID]; !exists {
				var groupName string
				if err := c.db.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ?", pol.TargetID).Scan(&groupName); err == nil {
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
		query := "SELECT id, name, ports, COALESCE(source_ports,''), protocol, COALESCE(no_conntrack, 0) FROM services WHERE id IN (" + strings.Join(placeholders, ",") + ")"

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

		// Expand ports for non-multicast services
		var portClauses []PortClause
		if serviceName != "Multicast" {
			portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
			if err != nil {
				return "", fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
			}
		}

		fmt.Fprintf(&buf, "# --- Policy: %s ---\n", pol.Name)

		// IG-001: Special IGMP handling - skip normal source/target resolution
		if strings.EqualFold(serviceName, "IGMP") {
			if writeToHost {
				c.writeIGMPRules(rw, pol.TargetScope, hasDocker)
			}
			buf.WriteString("\n")
			continue // Skip to next policy
		}

		// Process as TARGET (Ingress traffic)
		// Only emit if direction is 'both' or 'backward' (backward = target receives inbound from source)
		if pol.IsTarget && (pol.Direction == "both" || pol.Direction == "backward") {
			fmt.Fprintf(&buf, "# As Target (Ingress from %s %d)\n", pol.SourceType, pol.SourceID)

			// MC-009: Multicast special targets as Source indicate the host receives multicast traffic
			// When Source is a multicast special target (IDs 3=__all_hosts__, 4=__mdns__, 8=__igmpv3__),
			// this means the host should receive multicast traffic from that group - GENERATE INPUT rules
			isMulticastSource := pol.SourceType == "special" && (pol.SourceID == 3 || pol.SourceID == 4 || pol.SourceID == 8)

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
			case useIpset:
				// Use ipset-based rules (single rule per port clause)
				if serviceName == "Multicast" {
					c.writeMulticastRule(rw, pol.Action, pol.TargetScope, hasDocker)
				} else {
					if err := c.writeTargetRules(ctx, rw, pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack); err != nil {
						return "", err
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
					if err := c.writeTargetRules(ctx, rw, pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack); err != nil {
						return "", err
					}
				}
			}
		}

		// Process as SOURCE (Egress traffic)
		// Only emit if direction is 'both' or 'forward' (forward = source sends outbound to target)
		if pol.IsSource && (pol.Direction == "both" || pol.Direction == "forward") {
			fmt.Fprintf(&buf, "# As Source (Egress to %s %d)\n", pol.TargetType, pol.TargetID)

			// Check if we should use ipset for this target
			useIpset := hasIPSet && pol.TargetType == "group"
			var ipsetName string
			if useIpset {
				ipsetName = groupIDToIpsetName[pol.TargetID]
				useIpset = ipsetName != ""
			}

			if useIpset {
				// Use ipset-based rules (single rule per port clause)
				if serviceName == "Multicast" {
					if pol.Action == "ACCEPT" {
						buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					}
				} else {
					isMulticastTarget := pol.TargetType == "special" && (pol.TargetID == 3 || pol.TargetID == 4 || pol.TargetID == 8)
					if err := c.writeSourceRules(ctx, rw, pol, portClauses, true, ipsetName, nil, ipAddress, writeToHost, writeToDocker, noConntrack, isMulticastTarget); err != nil {
						return "", err
					}
				}
			} else {
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
					// Source for multicast doesn't need strict port tracking, just let it output to multicast range 224.0.0.0/4
					if pol.Action == "ACCEPT" {
						buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					}
				} else {
					isMulticastTarget := pol.TargetType == "special" && (pol.TargetID == 3 || pol.TargetID == 4 || pol.TargetID == 8)
					if err := c.writeSourceRules(ctx, rw, pol, portClauses, false, "", cidrs, ipAddress, writeToHost, writeToDocker, noConntrack, isMulticastTarget); err != nil {
						return "", err
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

// writeTargetRules writes ingress (target) rules for a policy.
// When useIpset is true, ipsetName contains the ipset to match against.
// When useIpset is false, cidrs contains the individual CIDRs to generate rules for.
// noConntrack when true skips conntrack marking for multicast protocols.
func (c *Compiler) writeTargetRules(
	ctx context.Context,
	rw *ruleWriter,
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
) error {
	for _, pc := range portClauses {
		inputPortMatch := pc.PortMatch
		if pc.SrcPortMatch != "" {
			inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
		}
		outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		var conntrackNew, conntrackEstab string
		if noConntrack {
			conntrackNew = ""
			conntrackEstab = ""
		} else {
			conntrackNew = "-m conntrack --ctstate NEW,ESTABLISHED"
			conntrackEstab = "-m conntrack --ctstate ESTABLISHED"
		}

		if useIpset {
			ipsetMatch := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			if writeToHost {
				if pol.Action == "ACCEPT" {
					rw.writeAction(pol.Action, "INPUT", fmt.Sprintf("-p %s %s %s %s", pc.Protocol, ipsetMatch, inputPortMatch, conntrackNew))
					rw.accept("OUTPUT", fmt.Sprintf("-p %s %s %s %s", pc.Protocol, ipsetMatch, outputPortMatch, conntrackEstab))
				} else {
					rw.writeAction(pol.Action, "INPUT", fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatch, inputPortMatch))
				}
			}
			if writeToDocker {
				if pol.Action == "ACCEPT" {
					rw.writeAction(pol.Action, "DOCKER-USER", fmt.Sprintf("-p %s %s %s %s", pc.Protocol, ipsetMatch, inputPortMatch, conntrackNew))
				} else {
					rw.writeAction(pol.Action, "DOCKER-USER", fmt.Sprintf("-p %s %s %s", pc.Protocol, ipsetMatch, inputPortMatch))
				}
			}
		} else {
			for _, cidr := range cidrs {
				if writeToHost {
					if pol.Action == "ACCEPT" {
						rw.writeAction(pol.Action, "INPUT", fmt.Sprintf("-s %s -p %s %s %s", cidr, pc.Protocol, inputPortMatch, conntrackNew))
						rw.accept("OUTPUT", fmt.Sprintf("-d %s -p %s %s %s", cidr, pc.Protocol, outputPortMatch, conntrackEstab))
					} else {
						rw.writeAction(pol.Action, "INPUT", fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, inputPortMatch))
					}
				}
				if writeToDocker {
					if pol.Action == "ACCEPT" {
						rw.writeAction(pol.Action, "DOCKER-USER", fmt.Sprintf("-s %s -p %s %s %s", cidr, pc.Protocol, inputPortMatch, conntrackNew))
					} else {
						rw.writeAction(pol.Action, "DOCKER-USER", fmt.Sprintf("-s %s -p %s %s", cidr, pc.Protocol, inputPortMatch))
					}
				}
			}
		}
	}
	return nil
}

// writeSourceRules writes egress (source) rules for a policy.
// When useIpset is true, ipsetName contains the ipset to match against.
// When useIpset is false, cidrs contains the individual CIDRs to generate rules for.
// noConntrack when true skips conntrack marking for multicast protocols.
// isMulticastTarget when true indicates the target is a multicast special target (3=__all_hosts__, 4=__mdns__, 8=__igmpv3__)
func (c *Compiler) writeSourceRules(
	ctx context.Context,
	rw *ruleWriter,
	pol *policyInfo,
	portClauses []PortClause,
	useIpset bool,
	ipsetName string,
	cidrs []string,
	ipAddress string,
	writeToHost, writeToDocker bool,
	noConntrack bool,
	isMulticastTarget bool,
) error {
	for _, pc := range portClauses {
		outputPortMatch := pc.PortMatch
		if pc.SrcPortMatch != "" {
			outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
		}
		inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

		// Build conntrack part based on noConntrack flag
		var conntrackNew, conntrackEstab string
		if noConntrack {
			conntrackNew = ""
			conntrackEstab = ""
		} else {
			conntrackNew = "-m conntrack --ctstate NEW,ESTABLISHED"
			conntrackEstab = "-m conntrack --ctstate ESTABLISHED"
		}

		// MC-010: For multicast targets, INPUT return rule should accept from any source (0.0.0.0/0)
		// This is because mDNS/IGMP responses come from individual hosts, not from the multicast address
		var returnCIDRs []string
		if isMulticastTarget {
			returnCIDRs = []string{"0.0.0.0/0"}
		} else {
			returnCIDRs = cidrs
		}

		if useIpset {
			ipsetMatchSrc := fmt.Sprintf("-m set --match-set %s src", ipsetName)
			ipsetMatchDst := fmt.Sprintf("-m set --match-set %s dst", ipsetName)
			rw.writeAction(pol.Action, "OUTPUT", fmt.Sprintf("-p %s %s %s %s", pc.Protocol, ipsetMatchDst, outputPortMatch, conntrackNew))
			rw.writeAction(pol.Action, "INPUT", fmt.Sprintf("-p %s %s %s %s", pc.Protocol, ipsetMatchSrc, inputPortMatch, conntrackEstab))
		} else {
			for _, cidr := range cidrs {
				if pol.Action == "ACCEPT" {
					rw.writeAction(pol.Action, "OUTPUT", fmt.Sprintf("-d %s -p %s %s %s", cidr, pc.Protocol, outputPortMatch, conntrackNew))
				} else {
					rw.writeAction(pol.Action, "OUTPUT", fmt.Sprintf("-d %s -p %s %s", cidr, pc.Protocol, outputPortMatch))
				}
			}
			// Write INPUT rules from returnCIDRs (either specific CIDRs or 0.0.0.0/0 for multicast)
			for _, returnCidr := range returnCIDRs {
				if pol.Action == "ACCEPT" {
					rw.accept("INPUT", fmt.Sprintf("-s %s -p %s %s %s", returnCidr, pc.Protocol, inputPortMatch, conntrackEstab))
				}
			}
		}
	}
	return nil
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

	var buf strings.Builder

	// Load service - MC-011: Include no_conntrack column
	var serviceName, ports, sourcePorts, protocol string
	var noConntrack bool
	err := c.db.QueryRowContext(ctx, "SELECT name, ports, source_ports, protocol, COALESCE(no_conntrack, 0) FROM services WHERE id = ?", serviceID).Scan(&serviceName, &ports, &sourcePorts, &protocol, &noConntrack)
	if err != nil {
		return nil, fmt.Errorf("load service: %w", err)
	}

	var portClauses []PortClause
	if serviceName != "Multicast" {
		portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
		if err != nil {
			return nil, fmt.Errorf("expand ports: %w", err)
		}
	}

	// Resolve source CIDRs
	var sourceCIDRs []string
	if sourceType == "special" {
		var err error
		sourceCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, sourceID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve source special target %d: %w", sourceID, err)
		}
	} else {
		var err error
		sourceCIDRs, err = c.resolver.ResolveEntity(ctx, sourceType, sourceID)
		if err != nil {
			return nil, fmt.Errorf("resolve source entity %s/%d: %w", sourceType, sourceID, err)
		}
	}

	// Resolve target CIDRs
	var targetCIDRs []string
	if targetType == "special" {
		var err error
		targetCIDRs, err = c.resolver.ResolveSpecialTarget(ctx, targetID, ipAddress)
		if err != nil {
			return nil, fmt.Errorf("resolve target special target %d: %w", targetID, err)
		}
	} else {
		var err error
		targetCIDRs, err = c.resolver.ResolveEntity(ctx, targetType, targetID)
		if err != nil {
			return nil, fmt.Errorf("resolve target entity %s/%d: %w", targetType, targetID, err)
		}
	}

	// Forward: Source initiates connections TO Target
	// Source hosts get: OUTPUT to target + INPUT established from target
	// Target hosts get: INPUT from source + OUTPUT established to source
	if targetScope == "host" || targetScope == "both" {
		// IG-002: Special IGMP handling - skip normal source/target resolution
		if strings.EqualFold(serviceName, "IGMP") {
			buf.WriteString("-A INPUT -d 224.0.0.1/32 -p igmp -j ACCEPT\n")
			buf.WriteString("-A OUTPUT -d 224.0.0.22/32 -p igmp -j ACCEPT\n")
		} else if direction == "both" || direction == "forward" {
			buf.WriteString("# Forward (Source → Target)\n")
			for _, targetCIDR := range targetCIDRs {
				if serviceName == "Multicast" {
					buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					continue
				}
				for _, pc := range portClauses {
					outputPortMatch := pc.PortMatch
					if pc.SrcPortMatch != "" {
						outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
					}
					inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
					// MC-011: Handle no_conntrack flag
					if noConntrack {
						fmt.Fprintf(&buf, "-A OUTPUT -d %s -p %s %s -j ACCEPT\n", targetCIDR, pc.Protocol, outputPortMatch)
					} else {
						fmt.Fprintf(&buf, "-A OUTPUT -d %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", targetCIDR, pc.Protocol, outputPortMatch)
						fmt.Fprintf(&buf, "-A INPUT -s %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", targetCIDR, pc.Protocol, inputPortMatch)
					}
				}
			}
		}

		// Backward: Target initiates connections TO Source
		// Target hosts get: OUTPUT to source + INPUT established from source
		// Source hosts get: INPUT from target + OUTPUT established to target
		// IG-002: Skip backward for IGMP (already handled above)
		if !strings.EqualFold(serviceName, "IGMP") && (direction == "both" || direction == "backward") {
			buf.WriteString("# Backward (Target → Source)\n")
			// MC-009: Multicast special targets as Source indicate receiving multicast traffic
			// When Source is a multicast special target (IDs 3=__all_hosts__, 4=__mdns__, 8=__igmpv3__),
			// this means the host should receive multicast traffic from that group - GENERATE INPUT rules
			isMulticastSource := sourceType == "special" && (sourceID == 3 || sourceID == 4 || sourceID == 8)
			if isMulticastSource {
				// Multicast source: use packet type matching for receiving multicast traffic
				if serviceName == "Multicast" {
					buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j ACCEPT\n")
				} else {
					// For non-Multicast services with multicast special source, generate INPUT rules
					for _, pc := range portClauses {
						inputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
						}
						outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
						// MC-011: Handle no_conntrack flag
						if noConntrack {
							fmt.Fprintf(&buf, "-A INPUT -m pkttype --pkt-type multicast -p %s %s -j ACCEPT\n", pc.Protocol, inputPortMatch)
						} else {
							fmt.Fprintf(&buf, "-A INPUT -m pkttype --pkt-type multicast -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", pc.Protocol, inputPortMatch)
							fmt.Fprintf(&buf, "-A OUTPUT -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", pc.Protocol, outputPortMatch)
						}
					}
				}
			} else {
				for _, sourceCIDR := range sourceCIDRs {
					if serviceName == "Multicast" {
						buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j ACCEPT\n")
						continue
					}
					for _, pc := range portClauses {
						inputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
						}
						outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
						// MC-011: Handle no_conntrack flag
						if noConntrack {
							fmt.Fprintf(&buf, "-A INPUT -s %s -p %s %s -j ACCEPT\n", sourceCIDR, pc.Protocol, inputPortMatch)
						} else {
							fmt.Fprintf(&buf, "-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", sourceCIDR, pc.Protocol, inputPortMatch)
							fmt.Fprintf(&buf, "-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", sourceCIDR, pc.Protocol, outputPortMatch)
						}
					}
				}
			}
		}
	}

	// Docker: DOCKER-USER chain rules (for Docker containers)
	// Generated when targetScope is "docker" or "both"
	if targetScope == "docker" || targetScope == "both" {
		// IG-002: Special IGMP handling for Docker
		if strings.EqualFold(serviceName, "IGMP") {
			buf.WriteString("-A DOCKER-USER -d 224.0.0.1/32 -p igmp -j ACCEPT\n")
			buf.WriteString("-A DOCKER-USER -d 224.0.0.22/32 -p igmp -j ACCEPT\n")
		} else {
			buf.WriteString("# Docker: DOCKER-USER chain rules\n")
			// Forward direction: Source → Target (Docker)
			if direction == "both" || direction == "forward" {
				for _, targetCIDR := range targetCIDRs {
					if serviceName == "Multicast" {
						buf.WriteString("-A DOCKER-USER -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
						continue
					}
					for _, pc := range portClauses {
						outputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
						}
						// MC-011: Handle no_conntrack flag
						if noConntrack {
							fmt.Fprintf(&buf, "-A DOCKER-USER -d %s -p %s %s -j ACCEPT\n", targetCIDR, pc.Protocol, outputPortMatch)
						} else {
							fmt.Fprintf(&buf, "-A DOCKER-USER -d %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", targetCIDR, pc.Protocol, outputPortMatch)
						}
					}
				}
			}
			// Backward direction: Target (Docker) ← Source
			// IG-002: Skip backward for IGMP (already handled above)
			if !strings.EqualFold(serviceName, "IGMP") && (direction == "both" || direction == "backward") {
				// MC-009: Multicast special targets as Source indicate receiving multicast traffic
				isMulticastSource := sourceType == "special" && (sourceID == 3 || sourceID == 4 || sourceID == 8)
				if isMulticastSource {
					// Multicast source: use packet type matching for receiving multicast traffic
					if serviceName == "Multicast" {
						buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT\n")
					} else {
						// For non-Multicast services with multicast special source, generate DOCKER-USER INPUT rules
						for _, pc := range portClauses {
							inputPortMatch := pc.PortMatch
							if pc.SrcPortMatch != "" {
								inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
							}
							// MC-011: Handle no_conntrack flag
							if noConntrack {
								fmt.Fprintf(&buf, "-A DOCKER-USER -m pkttype --pkt-type multicast -p %s %s -j ACCEPT\n", pc.Protocol, inputPortMatch)
							} else {
								fmt.Fprintf(&buf, "-A DOCKER-USER -m pkttype --pkt-type multicast -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", pc.Protocol, inputPortMatch)
							}
						}
					}
				} else {
					for _, sourceCIDR := range sourceCIDRs {
						if serviceName == "Multicast" {
							buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT\n")
							continue
						}
						for _, pc := range portClauses {
							inputPortMatch := pc.PortMatch
							if pc.SrcPortMatch != "" {
								inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
							}
							// MC-011: Handle no_conntrack flag
							if noConntrack {
								fmt.Fprintf(&buf, "-A DOCKER-USER -s %s -p %s %s -j ACCEPT\n", sourceCIDR, pc.Protocol, inputPortMatch)
							} else {
								fmt.Fprintf(&buf, "-A DOCKER-USER -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", sourceCIDR, pc.Protocol, inputPortMatch)
							}
						}
					}
				}
			}
		}
	}

	rules := strings.Split(buf.String(), "\n")
	var finalRules []string
	for _, line := range rules {
		line = strings.TrimSpace(line)
		if line != "" {
			finalRules = append(finalRules, line)
		}
	}
	return finalRules, nil
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
		`SELECT DISTINCT id FROM policies WHERE (source_type = 'group' AND source_id = ?) OR (target_type = 'group' AND target_id = ?) AND enabled = 1`, groupID, groupID)
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
	if err := c.db.QueryRowContext(ctx, "SELECT source_type, source_id, target_type, target_id FROM policies WHERE id = ?", policyID).Scan(&srcType, &srcID, &tgtType, &tgtID); err != nil {
		return nil, fmt.Errorf("get policy abstract: %w", err)
	}

	peers := make(map[int]bool)

	// Process source if not a special type
	if srcType != "special" {
		switch srcType {
		case "peer":
			peers[srcID] = true
		case "group":
			rows, err := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", srcID)
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
	}

	// Process target if not a special type
	if tgtType != "special" {
		switch tgtType {
		case "peer":
			peers[tgtID] = true
		case "group":
			rows, err := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", tgtID)
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
