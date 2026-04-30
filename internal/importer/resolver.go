// Package importer provides logic for parsing iptables backups and applying import sessions.
package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/iptparse"
)

const (
	specialTargetAnyIP            int64 = 6 // __any_ip__
	specialTargetLimitedBroadcast int64 = 2 // __limited_broadcast__
	specialTargetAllPeers         int64 = 7 // __all_peers__
	specialTargetAllHosts         int64 = 3 // __all_hosts__
)

// normalizeIP strips single-host CIDR notation (/32) from an IP address.
// Other CIDR suffixes (e.g., /24, /16) are preserved as they represent subnets.
func normalizeIP(ip string) string {
	if strings.HasSuffix(ip, "/32") {
		return strings.TrimSuffix(ip, "/32")
	}
	return ip
}

// resolveRules walks all import_rules for a session and attempts to map them to existing Runic entities.
// It also processes ipset data to create group/peer mappings.
func resolveRules(ctx context.Context, database db.Querier, sessionID int64, peerID int64, peerIPs []string, rawIpsets string) error {
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

		// Check for multicast rule
		if pr.PktType == "multicast" {
			if err := resolveMulticastRule(ctx, database, sessionID, r.ID); err != nil {
				log.Warn("Failed to resolve multicast rule", "rule_id", r.ID, "error", err)
			}
			// Update status to resolved for multicast rules
			_, _ = database.ExecContext(ctx, "UPDATE import_rules SET status = 'resolved' WHERE id = ?", r.ID)
			continue
		}

		// Resolve source
		sourceType, sourceID, sourceStagingID, sourceIP := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, true, r.Chain, peerID, peerIPs)

		// Resolve target (destination)
		targetType, targetID, targetStagingID, targetIP := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, false, r.Chain, peerID, peerIPs)

		// Resolve service
		serviceID, serviceStagingID := resolveService(ctx, database, sessionID, pr)

		// Correct source mapping for system policy patterns
		if sourceType == "special" && sourceID == specialTargetAnyIP {
			if targetType == "special" && serviceID > 0 {
				// Check if the service is a system service
				var isSystemService bool
				err := database.QueryRowContext(ctx, "SELECT is_system FROM services WHERE id = ?", serviceID).Scan(&isSystemService)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					log.Warn("source correction: failed to check service system status", "service_id", serviceID, "error", err)
				}

				if err == nil && isSystemService {
					// Get the special target name for the target
					var targetName string
					err := database.QueryRowContext(ctx, "SELECT name FROM special_targets WHERE id = ?", targetID).Scan(&targetName)
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						log.Warn("source correction: failed to look up special target name", "target_id", targetID, "error", err)
					}

					if err == nil {
						switch targetName {
						case "__all_hosts__", "__igmpv3__":
							// IGMP rules: source should be __all_peers__
							sourceType = "special"
							sourceID = specialTargetAllPeers
							sourceStagingID = 0
							sourceIP = ""
						case "__limited_broadcast__":
							// Limited Broadcast rules: source should be __limited_broadcast__
							sourceType = "special"
							sourceID = specialTargetLimitedBroadcast
							sourceStagingID = 0
							sourceIP = ""
						}
					}
				}
			}
		}

		// Update the import_rule with resolved mappings
		_, err := database.ExecContext(ctx,
			"UPDATE import_rules SET source_type = ?, source_id = ?, source_staging_id = ?, target_type = ?, target_id = ?, target_staging_id = ?, service_id = ?, service_staging_id = ?, source_ip = ?, target_ip = ?, status = 'resolved' WHERE id = ?",
			sourceType, sqlNullInt64(sourceID), sqlNullInt64(sourceStagingID),
			targetType, sqlNullInt64(targetID), sqlNullInt64(targetStagingID),
			sqlNullInt64(serviceID), sqlNullInt64(serviceStagingID),
			sqlNullString(sourceIP), sqlNullString(targetIP),
			r.ID,
		)
		if err != nil {
			log.Warn("Failed to update rule mapping", "rule_id", r.ID, "error", err)
		}
	}

	return nil
}

// resolveEndpoint resolves a source or target endpoint for a rule.
// Returns (type, realID, stagingID, matchedIP) — realID is set if mapped to existing entity, stagingID if new.
// matchedIP is set when the IP was found via peer_ips (non-primary IP match).
func resolveEndpoint(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule, ipsetMembers map[string][]string, isSource bool, chain string, peerID int64, peerIPs []string) (string, int64, int64, string) {
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

	// Normalize IP (strip /32 CIDR)
	ip = normalizeIP(ip)

	// Determine if this endpoint represents the "self" side of the imported peer
	isSelfEndpoint := (!isSource && (chain == "INPUT" || chain == "DOCKER-USER")) || (isSource && chain == "OUTPUT")

	// If this is the self-endpoint and IP is empty/0.0.0.0/0/0.0.0.0, map to the imported peer
	if isSelfEndpoint && (ip == "" || ip == "0.0.0.0" || ip == "0.0.0.0/0") {
		primaryIP := ""
		if len(peerIPs) > 0 {
			primaryIP = peerIPs[0]
		}
		return "peer", peerID, 0, primaryIP
	}

	// If this IP matches ANY of the imported peer's IPs, map to the imported peer with that specific IP
	for _, peerIP := range peerIPs {
		if ip == peerIP {
			return "peer", peerID, 0, peerIP
		}
	}

	// 0.0.0.0, 0.0.0.0/0, or empty = any IP → special target
	if ip == "" || ip == "0.0.0.0" || ip == "0.0.0.0/0" {
		return "special", specialTargetAnyIP, 0, "" // __any_ip__
	}

	// Look up existing peer by primary IP
	var existingPeerID int64
	err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", ip).Scan(&existingPeerID)
	if err == nil {
		return "peer", existingPeerID, 0, ""
	}

	// Check peer_ips table for non-primary IP match
	var peerIDFromIPs int64
	err = database.QueryRowContext(ctx, "SELECT peer_id FROM peer_ips WHERE ip_address = ?", ip).Scan(&peerIDFromIPs)
	if err == nil {
		return "peer", peerIDFromIPs, 0, ip
	}

	// Check if IP matches a special target address (e.g., 224.0.0.1 = __all_hosts__, 255.255.255.255 = __limited_broadcast__)
	var specialID int64
	err = database.QueryRowContext(ctx, "SELECT id FROM special_targets WHERE address = ?", ip).Scan(&specialID)
	if err == nil {
		return "special", specialID, 0, ""
	}

	// No existing peer — create staging peer mapping
	// Clean IP for hostname generation (remove CIDR notation)
	hostname := strings.Split(ip, "/")[0]
	stagingID, err := createStagingPeer(ctx, database, sessionID, ip, hostname)
	if err != nil {
		log.Warn("resolveEndpoint: staging peer creation failed — rule will be unresolvable",
			"ip", ip, "session_id", sessionID, "error", err)
		return "peer", 0, 0, ""
	}
	return "peer", 0, stagingID, ""
}

// resolveIpsetEndpoint resolves an ipset reference to a group.
// Returns (type, realID, stagingID, matchedIP) — matchedIP is always empty for ipset resolution.
func resolveIpsetEndpoint(ctx context.Context, database db.Querier, sessionID int64, ipsetName string, ipsetMembers map[string][]string) (string, int64, int64, string) {
	// Derive group name: strip "runic_group_" prefix if present
	groupName := ipsetName
	if strings.HasPrefix(ipsetName, "runic_group_") {
		groupName = strings.TrimPrefix(ipsetName, "runic_group_")
	}

	// Check if staging group already exists for this ipset in this session
	var existingStagingID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM import_group_mappings WHERE session_id = ? AND ipset_name = ?",
		sessionID, ipsetName,
	).Scan(&existingStagingID)
	if err == nil {
		return "group", 0, existingStagingID, ""
	}

	// Resolve member peer IDs first (needed for both phases)
	members := ipsetMembers[ipsetName]
	memberIPsJSON, _ := json.Marshal(members)

	var existingPeerIDs []int64
	var stagingPeerIDs []int64
	for _, memberIP := range members {
		memberIP = normalizeIP(memberIP) // Normalize before lookup
		var pid int64
		err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", memberIP).Scan(&pid)
		if err == nil {
			existingPeerIDs = append(existingPeerIDs, pid)
		} else {
			// Check peer_ips for non-primary IP match
			err = database.QueryRowContext(ctx, "SELECT peer_id FROM peer_ips WHERE ip_address = ?", memberIP).Scan(&pid)
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
	}

	existingPeerIDsJSON, _ := json.Marshal(existingPeerIDs)
	stagingPeerIDsJSON, _ := json.Marshal(stagingPeerIDs)

	// Phase 1: Check if group with same name exists and has matching members
	var groupID int64
	err = database.QueryRowContext(ctx, "SELECT id FROM groups WHERE name = ?", groupName).Scan(&groupID)
	if err == nil {
		// Verify member set matches
		var dbMemberPeerIDs []int64
		memberRows, mErr := database.QueryContext(ctx, "SELECT peer_id FROM group_members WHERE group_id = ?", groupID)
		if mErr == nil {
			for memberRows.Next() {
				var pid int64
				if memberRows.Scan(&pid) == nil {
					dbMemberPeerIDs = append(dbMemberPeerIDs, pid)
				}
			}
			_ = memberRows.Close()
		}

		// Sort both slices for comparison
		sort.Slice(existingPeerIDs, func(i, j int) bool { return existingPeerIDs[i] < existingPeerIDs[j] })
		sort.Slice(dbMemberPeerIDs, func(i, j int) bool { return dbMemberPeerIDs[i] < dbMemberPeerIDs[j] })

		if reflect.DeepEqual(existingPeerIDs, dbMemberPeerIDs) {
			// Members match — create staging record pointing to existing group
			result, _ := database.ExecContext(ctx,
				"INSERT INTO import_group_mappings (session_id, group_name, ipset_name, status, existing_group_id, member_ips, member_peer_ids, member_staging_peer_ids) VALUES (?, ?, ?, 'mapped', ?, ?, ?, ?)",
				sessionID, groupName, ipsetName, groupID, string(memberIPsJSON), string(existingPeerIDsJSON), string(stagingPeerIDsJSON),
			)
			var stagingID int64
			if result != nil {
				stagingID, _ = result.LastInsertId()
			}
			return "group", groupID, stagingID, ""
		}
		// Members don't match — fall through to Phase 2
	}

	// Phase 2: Search for group with matching member set
	if len(existingPeerIDs) > 0 {
		placeholders := strings.Repeat("?,", len(existingPeerIDs))
		placeholders = placeholders[:len(placeholders)-1] // trim trailing comma
		args := make([]interface{}, len(existingPeerIDs)+1)
		for i, id := range existingPeerIDs {
			args[i] = id
		}
		args[len(existingPeerIDs)] = int64(len(existingPeerIDs)) // HAVING count

		query := fmt.Sprintf(
			"SELECT gm.group_id FROM group_members gm WHERE gm.peer_id IN (%s) GROUP BY gm.group_id HAVING COUNT(DISTINCT gm.peer_id) = ?",
			placeholders,
		)

		var matchingGroupID int64
		err := database.QueryRowContext(ctx, query, args...).Scan(&matchingGroupID)
		if err == nil {
			// Verify this group has NO extra members beyond our set
			var totalMembers int
			_ = database.QueryRowContext(ctx, "SELECT COUNT(*) FROM group_members WHERE group_id = ?", matchingGroupID).Scan(&totalMembers)
			if totalMembers == len(existingPeerIDs) {
				// Exact match found — create staging record with existing_group_id set
				result, err := database.ExecContext(ctx,
					"INSERT INTO import_group_mappings (session_id, group_name, ipset_name, status, existing_group_id, member_ips, member_peer_ids, member_staging_peer_ids) VALUES (?, ?, ?, 'mapped', ?, ?, ?, ?)",
					sessionID, groupName, ipsetName, matchingGroupID, string(memberIPsJSON), string(existingPeerIDsJSON), string(stagingPeerIDsJSON),
				)
				if err == nil {
					stagingID, _ := result.LastInsertId()
					return "group", matchingGroupID, stagingID, ""
				}
			}
		}
	}

	// No match found — create new staging group
	result, err := database.ExecContext(ctx,
		"INSERT INTO import_group_mappings (session_id, group_name, ipset_name, status, member_ips, member_peer_ids, member_staging_peer_ids) VALUES (?, ?, ?, 'mapped', ?, ?, ?)",
		sessionID, groupName, ipsetName, string(memberIPsJSON), string(existingPeerIDsJSON), string(stagingPeerIDsJSON),
	)
	if err != nil {
		log.Warn("resolveIpsetEndpoint: staging group creation failed — rule will be unresolvable",
			"group", groupName, "ipset", ipsetName, "session_id", sessionID, "error", err)
		return "group", 0, 0, ""
	}
	stagingID, _ := result.LastInsertId()

	return "group", 0, stagingID, ""
}

// resolveService resolves a service from protocol+port.
func resolveService(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule) (int64, int64) {
	port := rule.DestPort
	protocol := rule.Protocol
	if protocol == "" || protocol == "all" {
		protocol = "tcp"
	}
	if port == "" {
		// For protocol-only rules (e.g., IGMP, Limited Broadcast), try matching system services
		if protocol != "" {
			var sysServiceID int64
			err := database.QueryRowContext(ctx,
				"SELECT id FROM services WHERE protocol = ? AND (ports = '' OR ports IS NULL) AND is_system = 1",
				protocol,
			).Scan(&sysServiceID)
			if err == nil {
				return sysServiceID, 0
			}
		}
		return 0, 0
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

	// For multiport values (comma-separated), try sorted port matching
	if strings.Contains(port, ",") {
		// Sort the port numbers for consistent matching
		portParts := strings.Split(port, ",")
		sort.Strings(portParts)
		sortedPort := strings.Join(portParts, ",")

		// Try exact match on sorted form
		err = database.QueryRowContext(ctx,
			"SELECT id FROM services WHERE protocol = ? AND ports = ?",
			protocol, sortedPort,
		).Scan(&serviceID)
		if err == nil {
			return serviceID, 0
		}

		// Try matching against each individual port in the multiport list
		for _, singlePort := range portParts {
			singlePort = strings.TrimSpace(singlePort)
			err = database.QueryRowContext(ctx,
				"SELECT id FROM services WHERE protocol = ? AND ports = ?",
				protocol, singlePort,
			).Scan(&serviceID)
			if err == nil {
				return serviceID, 0
			}
		}
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
	ip = normalizeIP(ip) // Normalize before dedup/insert
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

// sqlNullString returns a sql.NullString value.
// Empty string maps to NULL (Valid=false), non-empty maps to the string value (Valid=true).
func sqlNullString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}

// resolveMulticastRule maps a pkttype multicast rule to Runic policy entities.
// Multicast INPUT rules map to: source=special(__all_peers__, ID=7), target=special(__all_hosts__, ID=3), service=Multicast system service.
func resolveMulticastRule(ctx context.Context, database db.Querier, sessionID int64, ruleID int64) error {
	// Look up the Multicast system service
	var multicastServiceID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE name = 'Multicast' AND is_system = 1",
	).Scan(&multicastServiceID)
	if err != nil {
		return fmt.Errorf("multicast system service not found: %w", err)
	}

	// Update the rule with multicast mapping
	_, err = database.ExecContext(ctx,
		fmt.Sprintf("UPDATE import_rules SET source_type = 'special', source_id = %d, target_type = 'special', target_id = %d, service_id = ? WHERE id = ?", specialTargetAllPeers, specialTargetAllHosts),
		multicastServiceID, ruleID,
	)
	return err
}
