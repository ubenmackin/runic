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
	hmacKey  string
}

// NewCompiler creates a new Compiler with the given database and HMAC key.
func NewCompiler(database *sql.DB, hmacKey string) *Compiler {
	return &Compiler{
		db:       database,
		resolver: &Resolver{db: database},
		hmacKey:  hmacKey,
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

	// 2. Load enabled policies ordered by priority ASC, including docker_only field
	rows, err := c.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.source_group_id, p.service_id, p.action, p.priority, p.docker_only
		FROM policies p
		WHERE p.target_peer_id = ? AND p.enabled = 1
		ORDER BY p.priority ASC`, peerID)
	if err != nil {
		return "", fmt.Errorf("load policies: %w", err)
	}
	defer rows.Close()

	type policyInfo struct {
		ID            int
		Name          string
		SourceGroupID int
		ServiceID     int
		Action        string
		Priority      int
		DockerOnly    bool
	}

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceGroupID, &p.ServiceID, &p.Action, &p.Priority, &p.DockerOnly); err != nil {
			return "", fmt.Errorf("scan policy: %w", err)
		}
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

	// Standard rules: ICMP
	buf.WriteString("# --- Standard: ICMP ---\n")
	buf.WriteString("-A INPUT -p icmp -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -p icmp -j ACCEPT\n")
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
		// Resolve source group
		cidrs, err := c.resolver.ResolveGroup(ctx, pol.SourceGroupID, make(map[int]bool))
		if err != nil {
			return "", fmt.Errorf("resolve group %d for policy %s: %w", pol.SourceGroupID, pol.Name, err)
		}

		// Load service
		var serviceName, ports, protocol string
		err = c.db.QueryRowContext(ctx,
			"SELECT name, ports, protocol FROM services WHERE id = ?", pol.ServiceID,
		).Scan(&serviceName, &ports, &protocol)
		if err != nil {
			return "", fmt.Errorf("load service %d: %w", pol.ServiceID, err)
		}

		// Load group name for comment
		var groupName string
		err = c.db.QueryRowContext(ctx,
			"SELECT name FROM groups WHERE id = ?", pol.SourceGroupID,
		).Scan(&groupName)
		if err != nil {
			return "", fmt.Errorf("load group %d: %w", pol.SourceGroupID, err)
		}

		buf.WriteString(fmt.Sprintf("# --- Policy: %s | %s -> %s ---\n", pol.Name, groupName, serviceName))

		// Special handling for Multicast service: use packet type match instead of source IP
		if serviceName == "Multicast" {
			switch pol.Action {
			case "ACCEPT":
				if !pol.DockerOnly {
					buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
				if hasDocker {
					buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j ACCEPT\n")
				}
			case "DROP":
				if !pol.DockerOnly {
					buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j DROP\n")
				}
				if hasDocker {
					buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j DROP\n")
				}
			case "LOG_DROP":
				if !pol.DockerOnly {
					buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
					buf.WriteString("-A INPUT -m pkttype --pkt-type multicast -j DROP\n")
				}
				if hasDocker {
					buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
					buf.WriteString("-A DOCKER-USER -m pkttype --pkt-type multicast -j DROP\n")
				}
			}
			buf.WriteString("\n")
			continue
		}

		// Expand ports for non-multicast services
		portClauses, err := ExpandPorts(ports, protocol)
		if err != nil {
			return "", fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
		}

		for _, cidr := range cidrs {
			for _, pc := range portClauses {
				// Build port match strings for INPUT (--dport) and OUTPUT (--sport)
				inputPortMatch := pc.PortMatch
				outputPortMatch := strings.ReplaceAll(pc.PortMatch, "--dport", "--sport")
				outputPortMatch = strings.ReplaceAll(outputPortMatch, "--dports", "--sports")

				switch pol.Action {
				case "ACCEPT":
					// For docker_only=false: apply to both INPUT and DOCKER-USER (if Docker peer)
					// For docker_only=true: apply only to DOCKER-USER (if Docker peer)
					if !pol.DockerOnly {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol))
						}
						if outputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s -m conntrack --ctstate ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol))
						}
					}
					// Apply to DOCKER-USER chain for Docker peers
					if hasDocker {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol))
						}
					}
				case "DROP":
					if !pol.DockerOnly {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s -j DROP\n", cidr, pc.Protocol))
						}
					}
					if hasDocker {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s -j DROP\n", cidr, pc.Protocol))
						}
					}
				case "LOG_DROP":
					if !pol.DockerOnly {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, inputPortMatch))
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol))
							buf.WriteString(fmt.Sprintf("-A INPUT -s %s -p %s -j DROP\n", cidr, pc.Protocol))
						}
					}
					if hasDocker {
						if inputPortMatch != "" {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, inputPortMatch))
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
						} else {
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol))
							buf.WriteString(fmt.Sprintf("-A DOCKER-USER -s %s -p %s -j DROP\n", cidr, pc.Protocol))
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

// PreviewCompile generates a preview of iptables rules for a specific policy without storing them.
// This is used by the API preview endpoint to show users what rules would be generated.
func (c *Compiler) PreviewCompile(ctx context.Context, peerID, sourceGroupID, serviceID int) ([]string, error) {
	// Load peer info
	var hostname, ipAddress string
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address FROM peers WHERE id = ?", peerID,
	).Scan(&hostname, &ipAddress)
	if err != nil {
		return nil, fmt.Errorf("load peer %d: %w", peerID, err)
	}

	// Resolve source group
	cidrs, err := c.resolver.ResolveGroup(ctx, sourceGroupID, make(map[int]bool))
	if err != nil {
		return nil, fmt.Errorf("resolve group %d: %w", sourceGroupID, err)
	}

	// Load service
	var serviceName, ports, protocol string
	err = c.db.QueryRowContext(ctx,
		"SELECT name, ports, protocol FROM services WHERE id = ?", serviceID,
	).Scan(&serviceName, &ports, &protocol)
	if err != nil {
		return nil, fmt.Errorf("load service %d: %w", serviceID, err)
	}

	// Load group name for comment
	var groupName string
	err = c.db.QueryRowContext(ctx,
		"SELECT name FROM groups WHERE id = ?", sourceGroupID,
	).Scan(&groupName)
	if err != nil {
		return nil, fmt.Errorf("load group %d: %w", sourceGroupID, err)
	}

	// Expand ports
	portClauses, err := ExpandPorts(ports, protocol)
	if err != nil {
		return nil, fmt.Errorf("expand ports for service %d: %w", serviceID, err)
	}

	// Generate rules
	var rules []string

	// Special handling for Multicast service
	if serviceName == "Multicast" {
		rules = append(rules, "-A INPUT -m pkttype --pkt-type multicast -j ACCEPT")
		return rules, nil
	}

	for _, cidr := range cidrs {
		for _, pc := range portClauses {
			// Build port match strings for INPUT (--dport) and OUTPUT (--sport)
			inputPortMatch := pc.PortMatch
			outputPortMatch := strings.ReplaceAll(pc.PortMatch, "--dport", "--sport")
			outputPortMatch = strings.ReplaceAll(outputPortMatch, "--dports", "--sports")

			// Generate INPUT rule
			if inputPortMatch != "" {
				rules = append(rules, fmt.Sprintf("-A INPUT -s %s -p %s %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT", cidr, pc.Protocol, inputPortMatch))
			} else {
				rules = append(rules, fmt.Sprintf("-A INPUT -s %s -p %s -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT", cidr, pc.Protocol))
			}

			// Generate OUTPUT rule
			if outputPortMatch != "" {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m conntrack --ctstate ESTABLISHED -j ACCEPT", cidr, pc.Protocol, outputPortMatch))
			} else {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s -m conntrack --ctstate ESTABLISHED -j ACCEPT", cidr, pc.Protocol))
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

	version := Version(content)
	signature := Sign(content, c.hmacKey)

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
		`SELECT DISTINCT target_peer_id FROM policies WHERE source_group_id = ? AND enabled = 1`, groupID)
	if err != nil {
		return fmt.Errorf("find affected peers: %w", err)
	}
	defer rows.Close()

	var peerIDs []int
	for rows.Next() {
		var pid int
		if err := rows.Scan(&pid); err != nil {
			return err
		}
		peerIDs = append(peerIDs, pid)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, pid := range peerIDs {
		if _, err := c.CompileAndStore(ctx, pid); err != nil {
			return fmt.Errorf("recompile peer %d: %w", pid, err)
		}
	}
	return nil
}
