package engine

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

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
		`SELECT DISTINCT p.id, p.name, p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, p.action, p.priority, p.docker_only, COALESCE(p.direction, 'both'),
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
	defer rows.Close()

	type policyInfo struct {
		ID         int
		Name       string
		SourceID   int
		SourceType string
		ServiceID  int
		TargetID   int
		TargetType string
		Action     string
		Priority   int
		DockerOnly bool
		Direction  string
		IsTarget   bool
		IsSource   bool
	}

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		var isTargetInt, isSourceInt int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceID, &p.SourceType, &p.ServiceID, &p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.DockerOnly, &p.Direction, &isTargetInt, &isSourceInt); err != nil {
			return "", fmt.Errorf("scan policy: %w", err)
		}
		p.IsTarget = isTargetInt == 1
		p.IsSource = isSourceInt == 1
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// 2b. Collect unique group IDs used in policies (source or target) for ipset generation
	type groupRef struct {
		ID   int
		Name string
	}
	groupIDToName := make(map[int]string)
	var groupOrder []int // preserve insertion order
	for _, pol := range policies {
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
	now := time.Now().UTC().Format(time.RFC3339)

	// Header comment
	buf.WriteString("# Runic rule bundle\n")
	buf.WriteString(fmt.Sprintf("# Host: %s\n", hostname))
	buf.WriteString(fmt.Sprintf("# Generated: %s\n", now))
	buf.WriteString(fmt.Sprintf("# Policies: %d\n", len(policies)))
	if hasIPSet && len(ipsets) > 0 {
		buf.WriteString(fmt.Sprintf("# Ipsets: %d\n", len(ipsets)))
	}

	// Ipset definitions (before *filter)
	if hasIPSet && len(ipsets) > 0 {
		buf.WriteString("\n# --- Ipset Definitions ---\n")
		for _, is := range ipsets {
			buf.WriteString(fmt.Sprintf("create %s %s family inet\n", is.Name, is.SetType))
			for _, member := range is.Members {
				buf.WriteString(fmt.Sprintf("add %s %s\n", is.Name, member))
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

	// Standard rules: loopback
	buf.WriteString("# --- Standard: loopback ---\n")
	buf.WriteString("-A INPUT -i lo -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	buf.WriteString("\n")

	// Standard rules: established/related (using conntrack for better compatibility)
	buf.WriteString("# --- Standard: established/related ---\n")
	buf.WriteString("-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
	buf.WriteString("\n")

	// Standard rules: INVALID packet drop
	buf.WriteString("# --- Standard: INVALID packet drop ---\n")
	buf.WriteString("-A INPUT -m conntrack --ctstate INVALID -j DROP\n")
	buf.WriteString("\n")

	// Standard rules: Control Plane Communication
	// Read control plane port from system_config
	var controlPlanePort string
	err = c.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'control_plane_port'").Scan(&controlPlanePort)
	if err == nil && controlPlanePort != "" {
		buf.WriteString("# --- Standard: Control Plane Communication ---\n")
		buf.WriteString(fmt.Sprintf("# Allows agent to communicate with control plane on port %s\n", controlPlanePort))
		// Allow inbound from control plane (for push notifications/commands)
		buf.WriteString(fmt.Sprintf("-A INPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort))
		buf.WriteString(fmt.Sprintf("-A OUTPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort))
		// Allow outbound to control plane (for heartbeats, bundle pulls, key rotation)
		buf.WriteString(fmt.Sprintf("-A OUTPUT -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort))
		buf.WriteString(fmt.Sprintf("-A INPUT -p tcp --sport %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", controlPlanePort))
		buf.WriteString("\n")
	}

	// Docker: Control Plane Communication
	if hasDocker && err == nil && controlPlanePort != "" {
		buf.WriteString("# --- Docker: Control Plane Communication ---\n")
		buf.WriteString(fmt.Sprintf("-A DOCKER-USER -p tcp --dport %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", controlPlanePort))
		buf.WriteString("\n")
	}

	// Docker standard rules: Add established/related and INVALID to DOCKER-USER chain
	if hasDocker {
		buf.WriteString("# --- Docker: Standard rules for DOCKER-USER ---\n")
		buf.WriteString("-A DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		buf.WriteString("-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP\n")
		buf.WriteString("\n")
	}

	// Policy rules
	for _, pol := range policies {
		// Load service
		var serviceName, ports, sourcePorts, protocol string
		err = c.db.QueryRowContext(ctx,
			"SELECT name, ports, source_ports, protocol FROM services WHERE id = ?", pol.ServiceID,
		).Scan(&serviceName, &ports, &sourcePorts, &protocol)
		if err != nil {
			return "", fmt.Errorf("load service %d: %w", pol.ServiceID, err)
		}

		// Expand ports for non-multicast services
		var portClauses []PortClause
		if serviceName != "Multicast" {
			portClauses, err = ExpandPorts(ports, sourcePorts, protocol)
			if err != nil {
				return "", fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
			}
		}

		buf.WriteString(fmt.Sprintf("# --- Policy: %s ---\n", pol.Name))

		// Process as TARGET (Ingress traffic)
		// Only emit if direction is 'both' or 'backward' (backward = target receives inbound from source)
		if pol.IsTarget && (pol.Direction == "both" || pol.Direction == "backward") {
			buf.WriteString(fmt.Sprintf("# As Target (Ingress from %s %d)\n", pol.SourceType, pol.SourceID))

			// Check if we should use ipset for this source
			useIpset := hasIPSet && pol.SourceType == "group"
			var ipsetName string
			if useIpset {
				ipsetName = groupIDToIpsetName[pol.SourceID]
				useIpset = ipsetName != ""
			}

			if useIpset {
				// Use ipset-based rules (single rule per port clause)
				if serviceName == "Multicast" {
					c.writeMulticastRule(&buf, pol.Action, pol.DockerOnly, hasDocker)
				} else {
					for _, pc := range portClauses {
						inputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
						}
						outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
						ipsetMatch := fmt.Sprintf("-m set --match-set %s src", ipsetName)

						switch pol.Action {
						case "ACCEPT":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -p %s %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", pc.Protocol, ipsetMatch, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A OUTPUT -p %s %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", pc.Protocol, ipsetMatch, outputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", pc.Protocol, ipsetMatch, inputPortMatch))
							}
						case "DROP":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, inputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, inputPortMatch))
							}
						case "LOG_DROP":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -p %s %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", pc.Protocol, ipsetMatch, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A INPUT -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, inputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", pc.Protocol, ipsetMatch, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, inputPortMatch))
							}
						}
					}
				}
			} else {
				// Use individual rules (fallback for non-group or non-ipset peers)
				var cidrs []string
				var err error
				if pol.SourceType == "special" {
					cidrs, err = c.resolver.ResolveSpecialTarget(pol.SourceID, ipAddress)
				} else {
					cidrs, err = c.resolver.ResolveEntity(ctx, pol.SourceType, pol.SourceID)
				}
				if err != nil {
					return "", fmt.Errorf("resolve source for policy %s: %w", pol.Name, err)
				}
				for _, cidr := range cidrs {
					if serviceName == "Multicast" {
						c.writeMulticastRule(&buf, pol.Action, pol.DockerOnly, hasDocker)
						continue
					}
					for _, pc := range portClauses {
						// For INPUT (ingress): use destination ports as --dport, source ports as --sport
						inputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							inputPortMatch = pc.SrcPortMatch + " " + inputPortMatch
						}
						// For OUTPUT (egress): swap - destination ports become --sport, source ports become --dport
						outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

						switch pol.Action {
						case "ACCEPT":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
							}
						case "DROP":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
							}
						case "LOG_DROP":
							if !pol.DockerOnly {
								buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
							}
							if hasDocker {
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, inputPortMatch))
								buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
							}
						}
					}
				}
			}
		}

		// Process as SOURCE (Egress traffic)
		// Only emit if direction is 'both' or 'forward' (forward = source sends outbound to target)
		if pol.IsSource && (pol.Direction == "both" || pol.Direction == "forward") {
			buf.WriteString(fmt.Sprintf("# As Source (Egress to %s %d)\n", pol.TargetType, pol.TargetID))

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
					for _, pc := range portClauses {
						outputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
						}
						inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
						ipsetMatch := fmt.Sprintf("-m set --match-set %s src", ipsetName)

						switch pol.Action {
						case "ACCEPT":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -p %s %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", pc.Protocol, ipsetMatch, outputPortMatch))
							buf.WriteString(fmt.Sprintf("-A INPUT -p %s %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", pc.Protocol, ipsetMatch, inputPortMatch))
						case "DROP":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, outputPortMatch))
						case "LOG_DROP":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -p %s %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", pc.Protocol, ipsetMatch, outputPortMatch))
							buf.WriteString(fmt.Sprintf("-A OUTPUT -p %s %s %s -j DROP\n", pc.Protocol, ipsetMatch, outputPortMatch))
						}
					}
				}
			} else {
				// Use individual rules (fallback for non-group or non-ipset peers)
				var cidrs []string
				var err error
				if pol.TargetType == "special" {
					cidrs, err = c.resolver.ResolveSpecialTarget(pol.TargetID, ipAddress)
				} else {
					cidrs, err = c.resolver.ResolveEntity(ctx, pol.TargetType, pol.TargetID)
				}
				if err != nil {
					return "", fmt.Errorf("resolve target for policy %s: %w", pol.Name, err)
				}
				for _, cidr := range cidrs {
					if serviceName == "Multicast" {
						// Source for multicast doesn't need strict port tracking, just let it output to multicast range 224.0.0.0/4
						if pol.Action == "ACCEPT" {
							buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
						}
						continue
					}
					for _, pc := range portClauses {
						// For OUTPUT (egress from source): use destination port directly (sending TO the server port)
						outputPortMatch := pc.PortMatch
						if pc.SrcPortMatch != "" {
							outputPortMatch = pc.SrcPortMatch + " " + outputPortMatch
						}
						// For INPUT (response): inverted — server responds from its port back to our ephemeral port
						inputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)

						switch pol.Action {
						case "ACCEPT":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
						case "DROP":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -j DROP\n", cidr, pc.Protocol, outputPortMatch))
						case "LOG_DROP":
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, outputPortMatch))
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -j DROP\n", cidr, pc.Protocol, outputPortMatch))
						}
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

// writeMulticastRule generates multicast tracking
func (c *Compiler) writeMulticastRule(buf *strings.Builder, action string, dockerOnly bool, hasDocker bool) {
	switch action {
	case "ACCEPT":
		if !dockerOnly {
			buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j ACCEPT\n")
		}
		if hasDocker {
			buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT\n")
		}
	case "DROP":
		if !dockerOnly {
			buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j DROP\n")
		}
		if hasDocker {
			buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j DROP\n")
		}
	case "LOG_DROP":
		if !dockerOnly {
			buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
			buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j DROP\n")
		}
		if hasDocker {
			buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
			buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j DROP\n")
		}
	}
	buf.WriteString("\n")
}

// PreviewCompile generates a preview of iptables rules for a policy without storing them.
// Unlike Compile(), this is policy-centric: it resolves both source and target entities
// and generates rules based on direction, showing the complete picture across all hosts.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceID int, sourceType string, targetID int, targetType string, serviceID int, direction string) ([]string, error) {
	// Load a peer IP for special target resolution (uses peerID as reference)
	var ipAddress string
	if peerID != 0 {
		_ = c.db.QueryRowContext(ctx,
			"SELECT ip_address FROM peers WHERE id = ?", peerID,
		).Scan(&ipAddress)
	}

	// Default direction
	if direction == "" {
		direction = "both"
	}

	var buf strings.Builder

	// Load service
	var serviceName, ports, sourcePorts, protocol string
	err := c.db.QueryRowContext(ctx, "SELECT name, ports, source_ports, protocol FROM services WHERE id = ?", serviceID).Scan(&serviceName, &ports, &sourcePorts, &protocol)
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
		sourceCIDRs, _ = c.resolver.ResolveSpecialTarget(sourceID, ipAddress)
	} else {
		sourceCIDRs, _ = c.resolver.ResolveEntity(ctx, sourceType, sourceID)
	}

	// Resolve target CIDRs
	var targetCIDRs []string
	if targetType == "special" {
		targetCIDRs, _ = c.resolver.ResolveSpecialTarget(targetID, ipAddress)
	} else {
		targetCIDRs, _ = c.resolver.ResolveEntity(ctx, targetType, targetID)
	}

	// Forward: Source initiates connections TO Target
	// Source hosts get: OUTPUT to target + INPUT established from target
	// Target hosts get: INPUT from source + OUTPUT established to source
	if direction == "both" || direction == "forward" {
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
				buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", targetCIDR, pc.Protocol, outputPortMatch))
				buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", targetCIDR, pc.Protocol, inputPortMatch))
			}
		}
	}

	// Backward: Target initiates connections TO Source
	// Target hosts get: OUTPUT to source + INPUT established from source
	// Source hosts get: INPUT from target + OUTPUT established to target
	if direction == "both" || direction == "backward" {
		buf.WriteString("# Backward (Target → Source)\n")
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
				buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", sourceCIDR, pc.Protocol, inputPortMatch))
				buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", sourceCIDR, pc.Protocol, outputPortMatch))
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

func (c *Compiler) isAdminPeerInGroup(ctx context.Context, peerID, groupID int) bool {
	var count int
	c.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM group_members WHERE group_id = ? AND peer_id = ?", groupID, peerID).Scan(&count)
	return count > 0
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

	// Use db.SaveBundle to avoid duplicate transaction logic
	params := models.CreateBundleParams{
		PeerID:       peerID,
		Version:      version,
		RulesContent: content,
		HMAC:         signature,
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
	defer rows.Close()

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
		affected, _ := c.GetAffectedPeersByPolicy(ctx, pid)
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
	if srcType == "peer" {
		peers[srcID] = true
	} else if srcType == "group" {
		rows, err := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", srcID)
		if err != nil {
			return nil, fmt.Errorf("query source group members for policy %d: %w", policyID, err)
		}
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var p int
				rows.Scan(&p)
				peers[p] = true
			}
		}
	}

	if tgtType == "peer" {
		peers[tgtID] = true
	} else if tgtType == "group" {
		rows, err := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", tgtID)
		if err != nil {
			return nil, fmt.Errorf("query target group members for policy %d: %w", policyID, err)
		}
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var p int
				rows.Scan(&p)
				peers[p] = true
			}
		}
	}
	// Note: "special" source/target types don't add any peers to the affected list.
	// Special types (e.g., __loopback__, __subnet_broadcast__, __all_hosts__) represent
	// fixed addresses rather than dynamic peer entities. They resolve to specific IPs
	// at compile time and don't require recompilation when peers are added/removed.
	// The policy assignment determines which peers need the rules, not the special target itself.

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
