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

// Compile produces a complete iptables-restore payload for the given server.
func (c *Compiler) Compile(ctx context.Context, serverID int) (string, error) {
	// 1. Load server
	var hostname, ipAddress string
	var hasDocker bool
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address, has_docker FROM servers WHERE id = ?", serverID,
	).Scan(&hostname, &ipAddress, &hasDocker)
	if err != nil {
		return "", fmt.Errorf("load server %d: %w", serverID, err)
	}

	// 2. Load enabled policies ordered by priority ASC
	rows, err := c.db.QueryContext(ctx,
		`SELECT p.id, p.name, p.source_group_id, p.service_id, p.action, p.priority
		 FROM policies p
		 WHERE p.target_server_id = ? AND p.enabled = 1
		 ORDER BY p.priority ASC`, serverID)
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
	}

	var policies []policyInfo
	for rows.Next() {
		var p policyInfo
		if err := rows.Scan(&p.ID, &p.Name, &p.SourceGroupID, &p.ServiceID, &p.Action, &p.Priority); err != nil {
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
	buf.WriteString(fmt.Sprintf("# Host:      %s\n", hostname))
	buf.WriteString(fmt.Sprintf("# Generated: %s\n", now))
	buf.WriteString(fmt.Sprintf("# Policies:  %d\n", len(policies)))

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
	buf.WriteString("-A INPUT  -i lo -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -o lo -j ACCEPT\n")
	buf.WriteString("\n")

	// Standard rules: ICMP
	buf.WriteString("# --- Standard: ICMP ---\n")
	buf.WriteString("-A INPUT  -p icmp -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -p icmp -j ACCEPT\n")
	buf.WriteString("\n")

	// Standard rules: established/related
	buf.WriteString("# --- Standard: established/related ---\n")
	buf.WriteString("-A INPUT  -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buf.WriteString("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n")
	buf.WriteString("\n")

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

		// Expand ports
		portClauses, err := ExpandPorts(ports, protocol)
		if err != nil {
			return "", fmt.Errorf("expand ports for policy %s: %w", pol.Name, err)
		}

		buf.WriteString(fmt.Sprintf("# --- Policy: %s | %s -> %s ---\n", pol.Name, groupName, serviceName))

		for _, cidr := range cidrs {
			for _, pc := range portClauses {
				// Build port match strings for INPUT (--dport) and OUTPUT (--sport)
				inputPortMatch := pc.PortMatch
				outputPortMatch := strings.ReplaceAll(pc.PortMatch, "--dport", "--sport")
				outputPortMatch = strings.ReplaceAll(outputPortMatch, "--dports", "--sports")

				switch pol.Action {
				case "ACCEPT":
					if inputPortMatch != "" {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s %s -m state --state NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, inputPortMatch))
					} else {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s -m state --state NEW,ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol))
					}
					if outputPortMatch != "" {
						buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m state --state ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol, outputPortMatch))
					} else {
						buf.WriteString(fmt.Sprintf("-A OUTPUT -d %s -p %s -m state --state ESTABLISHED -j ACCEPT\n", cidr, pc.Protocol))
					}
				case "DROP":
					if inputPortMatch != "" {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
					} else {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s -j DROP\n", cidr, pc.Protocol))
					}
				case "LOG_DROP":
					if inputPortMatch != "" {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol, inputPortMatch))
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s %s -j DROP\n", cidr, pc.Protocol, inputPortMatch))
					} else {
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n", cidr, pc.Protocol))
						buf.WriteString(fmt.Sprintf("-A INPUT  -s %s -p %s -j DROP\n", cidr, pc.Protocol))
					}
				}
			}
		}
		buf.WriteString("\n")
	}

	// Logging and default deny (always last)
	buf.WriteString("# --- Logging and default deny ---\n")
	buf.WriteString("-A INPUT  -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
	buf.WriteString("-A INPUT  -j DROP\n")
	buf.WriteString("-A OUTPUT -j LOG --log-prefix \"[RUNIC-DROP] \" --log-level 4\n")
	buf.WriteString("-A OUTPUT -j DROP\n")

	// Docker section
	if hasDocker {
		buf.WriteString("\n")
		buf.WriteString("# --- Docker: DOCKER-USER chain management ---\n")
		buf.WriteString("-A DOCKER-USER -j RETURN\n")
	}

	buf.WriteString("\nCOMMIT\n")

	return buf.String(), nil
}

// PreviewCompile generates a preview of iptables rules for a specific policy without storing them.
// This is used by the API preview endpoint to show users what rules would be generated.
func (c *Compiler) PreviewCompile(ctx context.Context, serverID, sourceGroupID, serviceID int) ([]string, error) {
	// Load server info
	var hostname, ipAddress string
	err := c.db.QueryRowContext(ctx,
		"SELECT hostname, ip_address FROM servers WHERE id = ?", serverID,
	).Scan(&hostname, &ipAddress)
	if err != nil {
		return nil, fmt.Errorf("load server %d: %w", serverID, err)
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

	for _, cidr := range cidrs {
		for _, pc := range portClauses {
			// Build port match strings for INPUT (--dport) and OUTPUT (--sport)
			inputPortMatch := pc.PortMatch
			outputPortMatch := strings.ReplaceAll(pc.PortMatch, "--dport", "--sport")
			outputPortMatch = strings.ReplaceAll(outputPortMatch, "--dports", "--sports")

			// Generate INPUT rule
			if inputPortMatch != "" {
				rules = append(rules, fmt.Sprintf("-A INPUT  -s %s -p %s %s -m state --state NEW,ESTABLISHED -j ACCEPT", cidr, pc.Protocol, inputPortMatch))
			} else {
				rules = append(rules, fmt.Sprintf("-A INPUT  -s %s -p %s -m state --state NEW,ESTABLISHED -j ACCEPT", cidr, pc.Protocol))
			}

			// Generate OUTPUT rule
			if outputPortMatch != "" {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s %s -m state --state ESTABLISHED -j ACCEPT", cidr, pc.Protocol, outputPortMatch))
			} else {
				rules = append(rules, fmt.Sprintf("-A OUTPUT -d %s -p %s -m state --state ESTABLISHED -j ACCEPT", cidr, pc.Protocol))
			}
		}
	}

	return rules, nil
}

// CompileAndStore compiles the rules for a server, signs them, and stores the bundle.
func (c *Compiler) CompileAndStore(ctx context.Context, serverID int) (models.RuleBundleRow, error) {
	content, err := c.Compile(ctx, serverID)
	if err != nil {
		return models.RuleBundleRow{}, fmt.Errorf("compile: %w", err)
	}

	version := Version(content)
	signature := Sign(content, c.hmacKey)

	// Use db.SaveBundle to avoid duplicate transaction logic
	params := models.CreateBundleParams{
		ServerID:     serverID,
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

// RecompileAffectedServers finds all servers affected by a group change and recompiles their bundles.
func (c *Compiler) RecompileAffectedServers(ctx context.Context, groupID int) error {
	rows, err := c.db.QueryContext(ctx,
		`SELECT DISTINCT target_server_id FROM policies WHERE source_group_id = ? AND enabled = 1`, groupID)
	if err != nil {
		return fmt.Errorf("find affected servers: %w", err)
	}
	defer rows.Close()

	var serverIDs []int
	for rows.Next() {
		var sid int
		if err := rows.Scan(&sid); err != nil {
			return err
		}
		serverIDs = append(serverIDs, sid)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, sid := range serverIDs {
		if _, err := c.CompileAndStore(ctx, sid); err != nil {
			return fmt.Errorf("recompile server %d: %w", sid, err)
		}
	}
	return nil
}
