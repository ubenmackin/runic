// Package importer provides logic for parsing iptables backups and applying import sessions.
package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/iptparse"
)

// resolveRules walks all import_rules for a session and attempts to map them to existing Runic entities.
// It also processes ipset data to create group/peer mappings.
func resolveRules(ctx context.Context, database db.Querier, sessionID int64, rawIpsets string) error {
	// Parse ipset data for group member resolution
	ipsetMembers := parseIpsetData(rawIpsets)

	// Get all pending rules for this session
	rows, err := database.QueryContext(ctx,
		"SELECT id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name FROM import_rules WHERE session_id = ? AND status = 'pending'",
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("query rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type ruleRow struct {
		ID          int64
		Chain       string
		RuleOrder   int
		RawRule     string
		Status      string
		SkipReason  string
		Action      string
		Priority    int
		Direction   string
		TargetScope string
		PolicyName  string
	}

	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		if err := rows.Scan(&r.ID, &r.Chain, &r.RuleOrder, &r.RawRule, &r.Status, &r.SkipReason, &r.Action, &r.Priority, &r.Direction, &r.TargetScope, &r.PolicyName); err != nil {
			return fmt.Errorf("scan rule: %w", err)
		}
		rules = append(rules, r)
	}
	_ = rows.Close()

	// Re-parse each rule to get source/target/service info
	for i := range rules {
		r := &rules[i]
		parsedRules, _ := iptparse.Parse(fmt.Sprintf("-A %s %s", r.Chain, strings.TrimPrefix(r.RawRule, "-A "+r.Chain+" ")), []string{r.Chain})
		if len(parsedRules) == 0 || len(parsedRules[0].Rules) == 0 {
			continue
		}
		pr := &parsedRules[0].Rules[0]

		// Resolve source
		sourceType, sourceID, sourceStagingID := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, true)

		// Resolve target (destination)
		targetType, targetID, targetStagingID := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, false)

		// Resolve service
		serviceID, serviceStagingID := resolveService(ctx, database, sessionID, pr)

		// Update the import_rule with resolved mappings
		_, err := database.ExecContext(ctx,
			"UPDATE import_rules SET source_type = ?, source_id = ?, source_staging_id = ?, target_type = ?, target_id = ?, target_staging_id = ?, service_id = ?, service_staging_id = ?, status = 'resolved' WHERE id = ?",
			sourceType, sqlNullInt64(sourceID), sqlNullInt64(sourceStagingID),
			targetType, sqlNullInt64(targetID), sqlNullInt64(targetStagingID),
			sqlNullInt64(serviceID), sqlNullInt64(serviceStagingID),
			r.ID,
		)
		if err != nil {
			log.Warn("Failed to update rule mapping", "rule_id", r.ID, "error", err)
		}
	}

	return nil
}

// resolveEndpoint resolves a source or target endpoint for a rule.
// Returns (type, realID, stagingID) — realID is set if mapped to existing entity, stagingID if new.
func resolveEndpoint(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule, ipsetMembers map[string][]string, isSource bool) (string, int64, int64) {
	// Check for ipset match
	if rule.IpsetMatch != nil {
		isMatchForEndpoint := (isSource && rule.IpsetMatch.Direction == "src") || (!isSource && rule.IpsetMatch.Direction == "dst")
		if isMatchForEndpoint {
			return resolveIpsetEndpoint(ctx, database, sessionID, rule.IpsetMatch.Name, ipsetMembers)
		}
	}

	// Get the IP based on source/destination
	ip := rule.DestIP
	if isSource {
		ip = rule.SourceIP
	}

	// 0.0.0.0/0 or empty = any IP → special target
	if ip == "" || ip == "0.0.0.0/0" {
		return "special", 6, 0 // __any_ip__ has id=6 in special_targets
	}

	// Look up existing peer by IP
	var peerID int64
	err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", ip).Scan(&peerID)
	if err == nil {
		return "peer", peerID, 0
	}

	// No existing peer — create staging peer mapping
	// Clean IP for hostname generation (remove CIDR notation)
	hostname := strings.Split(ip, "/")[0]
	stagingID, err := createStagingPeer(ctx, database, sessionID, ip, hostname)
	if err != nil {
		log.Warn("resolveEndpoint: staging peer creation failed — rule will be unresolvable",
			"ip", ip, "session_id", sessionID, "error", err)
		return "peer", 0, 0
	}
	return "peer", 0, stagingID
}

// resolveIpsetEndpoint resolves an ipset reference to a group.
func resolveIpsetEndpoint(ctx context.Context, database db.Querier, sessionID int64, ipsetName string, ipsetMembers map[string][]string) (string, int64, int64) {
	// Derive group name: strip "runic_group_" prefix if present
	groupName := ipsetName
	if strings.HasPrefix(ipsetName, "runic_group_") {
		groupName = strings.TrimPrefix(ipsetName, "runic_group_")
	}

	// Check if group exists in real DB
	var groupID int64
	err := database.QueryRowContext(ctx, "SELECT id FROM groups WHERE name = ?", groupName).Scan(&groupID)
	if err == nil {
		return "group", groupID, 0
	}

	// Create staging group mapping
	members := ipsetMembers[ipsetName]
	memberIPsJSON, _ := json.Marshal(members)

	// Resolve member peer IDs
	var existingPeerIDs []int64
	var stagingPeerIDs []int64
	for _, memberIP := range members {
		var pid int64
		err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", memberIP).Scan(&pid)
		if err == nil {
			existingPeerIDs = append(existingPeerIDs, pid)
		} else {
			// Create staging peer for this member
			spid, err := createStagingPeer(ctx, database, sessionID, memberIP, memberIP)
			if err == nil {
				stagingPeerIDs = append(stagingPeerIDs, spid)
			}
		}
	}

	existingPeerIDsJSON, _ := json.Marshal(existingPeerIDs)
	stagingPeerIDsJSON, _ := json.Marshal(stagingPeerIDs)

	result, err := database.ExecContext(ctx,
		"INSERT INTO import_group_mappings (session_id, group_name, ipset_name, status, member_ips, member_peer_ids, member_staging_peer_ids) VALUES (?, ?, ?, 'mapped', ?, ?, ?)",
		sessionID, groupName, ipsetName, string(memberIPsJSON), string(existingPeerIDsJSON), string(stagingPeerIDsJSON),
	)
	if err != nil {
		log.Warn("resolveIpsetEndpoint: staging group creation failed — rule will be unresolvable",
			"group", groupName, "ipset", ipsetName, "session_id", sessionID, "error", err)
		return "group", 0, 0
	}
	stagingID, _ := result.LastInsertId()

	return "group", 0, stagingID
}

// resolveService resolves a service from protocol+port.
func resolveService(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule) (int64, int64) {
	port := rule.DestPort
	protocol := rule.Protocol
	if protocol == "" || protocol == "all" {
		protocol = "tcp"
	}
	if port == "" {
		return 0, 0 // no service needed
	}

	// Look up existing service by port+protocol
	var serviceID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE ports = ? AND protocol = ?",
		port, protocol,
	).Scan(&serviceID)
	if err == nil {
		return serviceID, 0
	}

	// Also try finding by individual port number (services.ports can be "80" or "80,443")
	err = database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE protocol = ? AND (ports = ? OR ports LIKE ? OR ports LIKE ? OR ports LIKE ?)",
		protocol, port, port+",%", "%,"+port, "%,"+port+",%",
	).Scan(&serviceID)
	if err == nil {
		return serviceID, 0
	}

	// Create staging service mapping
	serviceName := fmt.Sprintf("imported-%s-%s", protocol, port)
	result, err := database.ExecContext(ctx,
		"INSERT INTO import_service_mappings (session_id, name, ports, protocol, status) VALUES (?, ?, ?, ?, 'mapped')",
		sessionID, serviceName, port, protocol,
	)
	if err != nil {
		log.Warn("Failed to create staging service", "port", port, "protocol", protocol, "error", err)
		return 0, 0
	}
	stagingID, _ := result.LastInsertId()

	return 0, stagingID
}

// createStagingPeer creates a staging peer mapping for an IP that doesn't match an existing peer.
func createStagingPeer(ctx context.Context, database db.Querier, sessionID int64, ip, hostname string) (int64, error) {
	// Check if staging peer already exists for this IP in this session
	var existingID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM import_peer_mappings WHERE session_id = ? AND ip_address = ?",
		sessionID, ip,
	).Scan(&existingID)
	if err == nil {
		return existingID, nil
	}

	result, err := database.ExecContext(ctx,
		"INSERT INTO import_peer_mappings (session_id, ip_address, hostname, status) VALUES (?, ?, ?, 'mapped')",
		sessionID, ip, hostname,
	)
	if err != nil {
		return 0, fmt.Errorf("insert staging peer: %w", err)
	}
	id, _ := result.LastInsertId()
	return id, nil
}

// parseIpsetData parses raw ipset list output into a map of ipset name -> member IPs.
// Example input:
//
//	Name: runic_group_web
//	Members:
//	10.0.0.1
//	10.0.0.2
func parseIpsetData(rawIpsets string) map[string][]string {
	result := make(map[string][]string)
	if rawIpsets == "" {
		return result
	}

	var currentName string
	for _, line := range strings.Split(rawIpsets, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name: ") {
			currentName = strings.TrimPrefix(line, "Name: ")
			result[currentName] = []string{}
		} else if currentName != "" && line != "" && line != "Members:" &&
			!strings.HasPrefix(line, "Type:") &&
			!strings.HasPrefix(line, "Revision:") &&
			!strings.HasPrefix(line, "Header:") &&
			!strings.HasPrefix(line, "Size in memory") &&
			!strings.HasPrefix(line, "References:") &&
			!strings.HasPrefix(line, "Number of entries") {
			// This line is a member IP
			// IP entries may have CIDR or comments after space
			parts := strings.Fields(line)
			if len(parts) > 0 {
				ip := parts[0]
				if netIP := parseIPPart(ip); netIP != "" {
					result[currentName] = append(result[currentName], netIP)
				}
			}
		}
	}
	return result
}

// parseIPPart extracts just the IP portion (before /CIDR).
func parseIPPart(s string) string {
	return strings.Split(s, "/")[0]
}

// sqlNullInt64 returns a sql.NullInt64 value.
// Zero maps to NULL (Valid=false), non-zero maps to the integer value (Valid=true).
func sqlNullInt64(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: v != 0}
}
