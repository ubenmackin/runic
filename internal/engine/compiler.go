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
	var hasDocker bool
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress, &hasDocker)
	if err != nil {
		return "", fmt.Errorf("load peer %d: %w", peerID, err)
	}
	// 2. Load enabled policies where peer is either target or source, ordered by priority ASC
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT p.id, p.name, p.source_id, p.source_type, p.service_id, p.target_id, p.target_type, p.action, p.priority, p.docker_only,
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
		IsTarget   bool
		IsSource   bool
	}

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		var isTargetInt, isSourceInt int
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceID, &p.SourceType, &p.ServiceID, &p.TargetID, &p.TargetType, &p.Action, &p.Priority, &p.DockerOnly, &isTargetInt, &isSourceInt); err != nil {
			return "", fmt.Errorf("scan policy: %w", err)
		}
		p.IsTarget = isTargetInt == 1
		p.IsSource = isSourceInt == 1
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}

	// 3. Build the iptables-restore output
	var buf strings.Builder
	now := time.Now().UTC().Format(time.RFC3339)

	// Header comment
	buf.WriteString("# Runic rule bundle\n")
	buf.WriteString(fmt.Sprintf("# Host: %s\n", hostname))
	buf.WriteString(fmt.Sprintf("# Generated: %s\n", now))
	buf.WriteString(fmt.Sprintf("# Policies: %d\n", len(policies)))

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
		if pol.IsTarget {
			buf.WriteString(fmt.Sprintf("# As Target (Ingress from %s %d)\n", pol.SourceType, pol.SourceID))
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

		// Process as SOURCE (Egress traffic)
		if pol.IsSource {
			buf.WriteString(fmt.Sprintf("# As Source (Egress to %s %d)\n", pol.TargetType, pol.TargetID))
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
					// For OUTPUT (egress from source): swap ports - destination becomes --sport, source becomes --dport
					outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
					// For INPUT (response): reverse of output - use swapped ports
					inputPortMatch := invertPortMatch(pc.SrcPortMatch, pc.PortMatch)

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

// PreviewCompile generates a preview of iptables rules for a specific policy without storing them.
// This is used by the API preview endpoint to show users what rules would be generated.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceID int, sourceType string, targetID int, targetType string, serviceID int) ([]string, error) {
	// Load peer info
	var hostname, ipAddress string
	var hasDocker bool
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress, &hasDocker)
	if err != nil {
		return nil, fmt.Errorf("load peer %d: %w", peerID, err)
	}

	var buf strings.Builder
	// Evaluate if peer is source or target in memory
	isTarget := false
	isSource := false

	if targetType == "peer" && targetID == peerID {
		isTarget = true
	} else if targetType == "group" {
		isTarget = c.isAdminPeerInGroup(ctx, peerID, targetID)
	}

	if sourceType == "peer" && sourceID == peerID {
		isSource = true
	} else if sourceType == "group" {
		isSource = c.isAdminPeerInGroup(ctx, peerID, sourceID)
	}

	buf.WriteString(fmt.Sprintf("# --- Preview Policy --- (Target=%v, Source=%v)\n", isTarget, isSource))

	var serviceName, ports, sourcePorts, protocol string
	err = c.db.QueryRowContext(ctx, "SELECT name, ports, source_ports, protocol FROM services WHERE id = ?", serviceID).Scan(&serviceName, &ports, &sourcePorts, &protocol)
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

	if isTarget {
		var cidrs []string
		var err error
		if sourceType == "special" {
			cidrs, err = c.resolver.ResolveSpecialTarget(sourceID, ipAddress)
		} else {
			cidrs, err = c.resolver.ResolveEntity(ctx, sourceType, sourceID)
		}
		if err == nil {
			for _, cidr := range cidrs {
				if serviceName == "Multicast" {
					c.writeMulticastRule(&buf, "ACCEPT", false, hasDocker)
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
					buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
					buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
				}
			}
		}
	}

	if isSource {
		var cidrs []string
		var err error
		if targetType == "special" {
			cidrs, err = c.resolver.ResolveSpecialTarget(targetID, ipAddress)
		} else {
			cidrs, err = c.resolver.ResolveEntity(ctx, targetType, targetID)
		}
		if err == nil {
			for _, cidr := range cidrs {
				if serviceName == "Multicast" {
					buf.WriteString("-A OUTPUT -d 224.0.0.0/4 -m pkttype --pkt-type multicast -j ACCEPT\n")
					continue
				}
				for _, pc := range portClauses {
					// For OUTPUT (egress from source): swap ports
					outputPortMatch := invertPortMatch(pc.PortMatch, pc.SrcPortMatch)
					// For INPUT (response): reverse of output
					inputPortMatch := invertPortMatch(pc.SrcPortMatch, pc.PortMatch)
					buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
					buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
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
		rows, _ := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", srcID)
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
		rows, _ := c.db.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", tgtID)
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
