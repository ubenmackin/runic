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
	"runic/internal/resolve"
)

// Multicast detection on OUTPUT/FORWARD chains is skipped because those represent
// the peer sending multicast, not receiving it — analogous to resolve.IsBroadcastDest.
func isMulticastPktType(rule *iptparse.ParsedRule, chain string) bool {
	if rule.PktType != "multicast" {
		return false
	}
	return chain == "INPUT" || chain == "DOCKER-USER"
}

// indicating an IGMP rule that needs special handling before normal endpoint resolution.
// IGMP rules on OUTPUT/FORWARD chains are skipped because those represent the peer sending
// IGMP, not receiving it — analogous to resolve.IsBroadcastDest and isMulticastPktType.
func isIGMPProtocol(rule *iptparse.ParsedRule, chain string) bool {
	if rule.Protocol != "igmp" {
		return false
	}
	return chain == "INPUT" || chain == "DOCKER-USER"
}

// IGMP INPUT rules map to: source=special(__all_hosts__, ID=3), target=peer(self), service=IGMP system service, direction=both.
// This mirrors the multicast pattern and ensures the policy is tied to the peer (target_type='peer')
// so it compiles correctly in loadApplicablePolicies (which only matches peer/group targets, never 'special').
func resolveIGMPRule(ctx context.Context, database db.Querier, ruleID int64, peerID int64) error {
	var igmpServiceID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE name = 'IGMP' AND is_system = 1",
	).Scan(&igmpServiceID)
	if err != nil {
		return fmt.Errorf("IGMP system service not found: %w", err)
	}

	// Determine the peer's primary IP for the target_ip field
	var primaryIP string
	_ = database.QueryRowContext(ctx, "SELECT ip_address FROM peers WHERE id = ?", peerID).Scan(&primaryIP)

	// source = __all_hosts__ (IGMP/multicast group, the broadcast domain)
	// target = peer (the machine receiving the IGMP packets)
	_, err = database.ExecContext(ctx,
		"UPDATE import_rules SET source_type = 'special', source_id = ?, source_staging_id = NULL, target_type = 'peer', target_id = ?, target_staging_id = NULL, service_id = ?, service_staging_id = NULL, source_ip = '', direction = 'both', target_ip = ?, status = 'resolved' WHERE id = ?",
		int64(resolve.SpecialIDAllHosts), peerID, igmpServiceID, primaryIP, ruleID,
	)
	return err
}

// It also processes ipset data to create group/peer mappings.
func resolveRules(ctx context.Context, database db.Querier, sessionID int64, peerID int64, peerIPs []string, rawIpsets string) error {
	ipsetMembers := parseIpsetData(rawIpsets)

	rows, err := database.QueryContext(ctx,
		"SELECT id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name FROM import_rules WHERE session_id = ? AND status = 'pending'",
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("query rules: %w", err)
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			log.Warn("Error closing resolver rows", "error", cErr)
		}
	}()

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
	if cErr := rows.Close(); cErr != nil {
		log.Warn("Error closing resolver rows after iteration", "error", cErr)
	}

	// Re-parse each rule to get source/target/service info
	for i := range rules {
		r := &rules[i]
		parsedRules, _ := iptparse.Parse(fmt.Sprintf("-A %s %s", r.Chain, strings.TrimPrefix(r.RawRule, "-A "+r.Chain+" ")), []string{r.Chain})
		if len(parsedRules) == 0 || len(parsedRules[0].Rules) == 0 {
			continue
		}
		pr := &parsedRules[0].Rules[0]

		// the peer is receiving multicast packets, not sending them)
		if isMulticastPktType(pr, r.Chain) {
			if err := resolveMulticastRule(ctx, database, r.ID, peerID); err != nil {
				log.Warn("Failed to resolve multicast rule", "rule_id", r.ID, "error", err)
			}
			continue
		}

		// IGMP detection must happen before resolveEndpoint() to prevent
		// the target from being resolved as a special target, which would
		// orphan the policy from the peer in the compiler.
		if isIGMPProtocol(pr, r.Chain) {
			if err := resolveIGMPRule(ctx, database, r.ID, peerID); err != nil {
				log.Warn("Failed to resolve IGMP rule", "rule_id", r.ID, "error", err)
			}
			continue
		}

		// Broadcast detection must happen before resolveEndpoint() so that
		// broadcast destination IPs are not resolved as target endpoints.
		if broadcastSpecialID := resolve.IsBroadcastDest(pr.DestIP, r.Chain, peerIPs); broadcastSpecialID != 0 {
			if err := resolveBroadcastRule(ctx, database, sessionID, r.ID, peerID, int64(broadcastSpecialID), pr); err != nil {
				log.Warn("Failed to resolve broadcast rule", "rule_id", r.ID, "error", err)
			}
			continue
		}

		// Resolve source
		sourceType, sourceID, sourceStagingID, sourceIP := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, true, r.Chain, peerID, peerIPs)

		// Resolve target (destination)
		targetType, targetID, targetStagingID, targetIP := resolveEndpoint(ctx, database, sessionID, pr, ipsetMembers, false, r.Chain, peerID, peerIPs)

		// Resolve service
		serviceID, serviceStagingID := resolveService(ctx, database, sessionID, pr)

		// Correct source mapping for system policy patterns
		if sourceType == "special" && sourceID == int64(resolve.SpecialIDAnyIP) {
			if targetType == "special" && serviceID > 0 {
				var isSystemService bool
				err := database.QueryRowContext(ctx, "SELECT is_system FROM services WHERE id = ?", serviceID).Scan(&isSystemService)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					log.Warn("source correction: failed to check service system status", "service_id", serviceID, "error", err)
				}

				if err == nil && isSystemService {
					var targetName string
					err := database.QueryRowContext(ctx, "SELECT name FROM special_targets WHERE id = ?", targetID).Scan(&targetName)
					if err != nil && !errors.Is(err, sql.ErrNoRows) {
						log.Warn("source correction: failed to look up special target name", "target_id", targetID, "error", err)
					}

					if err == nil {
						if targetName == "__limited_broadcast__" {
							// Note: Broadcast rules with -d 255.255.255.255 are handled by
							// resolveBroadcastRule() before reaching this block, which correctly
							// sets source=broadcast, target=peer, and service=Limited Broadcast.
							// This safety net only corrects the source — target and service
							// will still be incorrect (target=broadcast special, service=Multicast).
							// If this fires, the rule should be flagged for manual review.
							sourceType = "special"
							sourceID = int64(resolve.SpecialIDLimitedBroadcast)
							sourceStagingID = 0
							sourceIP = ""
						}
					}
				}
			}
		}

		// Determine direction based on remote endpoint's agent-managed status
		var remoteType string
		var remoteID, remoteStagingID int64
		if r.Chain == "INPUT" || r.Chain == "DOCKER-USER" {
			remoteType, remoteID, remoteStagingID = sourceType, sourceID, sourceStagingID
		} else {
			remoteType, remoteID, remoteStagingID = targetType, targetID, targetStagingID
		}
		direction := determineDirection(ctx, r.Chain, remoteType, remoteID, remoteStagingID, database)

		_, err := database.ExecContext(ctx,
			"UPDATE import_rules SET source_type = ?, source_id = ?, source_staging_id = ?, target_type = ?, target_id = ?, target_staging_id = ?, service_id = ?, service_staging_id = ?, source_ip = ?, target_ip = ?, direction = ?, status = 'resolved' WHERE id = ?",
			sourceType, sqlNullInt64(sourceID), sqlNullInt64(sourceStagingID),
			targetType, sqlNullInt64(targetID), sqlNullInt64(targetStagingID),
			sqlNullInt64(serviceID), sqlNullInt64(serviceStagingID),
			sqlNullString(sourceIP), sqlNullString(targetIP),
			direction,
			r.ID,
		)
		if err != nil {
			log.Warn("Failed to update rule mapping", "rule_id", r.ID, "error", err)
		}
	}

	return nil
}

// Returns (type, realID, stagingID, matchedIP) — realID is set if mapped to existing entity, stagingID if new.
// matchedIP is set when the IP was found via peer_ips (non-primary IP match).
func resolveEndpoint(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule, ipsetMembers map[string][]string, isSource bool, chain string, peerID int64, peerIPs []string) (string, int64, int64, string) {
	if rule.IpsetMatch != nil {
		isMatchForEndpoint := (isSource && rule.IpsetMatch.Direction == "src") || (!isSource && rule.IpsetMatch.Direction == "dst")
		if isMatchForEndpoint {
			return resolveIpsetEndpoint(ctx, database, sessionID, rule.IpsetMatch.Name, ipsetMembers)
		}
	}

	ip := rule.DestIP
	if isSource {
		ip = rule.SourceIP
	}

	// Normalize IP (strip /32 CIDR)
	ip = resolve.NormalizeIP(ip)

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
		return "special", int64(resolve.SpecialIDAnyIP), 0, "" // __any_ip__
	}

	var existingPeerID int64
	err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", ip).Scan(&existingPeerID)
	if err == nil {
		return "peer", existingPeerID, 0, ""
	}

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

// Returns (type, realID, stagingID, matchedIP) — matchedIP is always empty for ipset resolution.
func resolveIpsetEndpoint(ctx context.Context, database db.Querier, sessionID int64, ipsetName string, ipsetMembers map[string][]string) (string, int64, int64, string) {
	// Derive group name: strip "runic_group_" prefix if present
	groupName := ipsetName
	if strings.HasPrefix(ipsetName, "runic_group_") {
		groupName = strings.TrimPrefix(ipsetName, "runic_group_")
	}

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
		memberIP = resolve.NormalizeIP(memberIP) // Normalize before lookup
		var pid int64
		err := database.QueryRowContext(ctx, "SELECT id FROM peers WHERE ip_address = ?", memberIP).Scan(&pid)
		if err == nil {
			existingPeerIDs = append(existingPeerIDs, pid)
		} else {
			err = database.QueryRowContext(ctx, "SELECT peer_id FROM peer_ips WHERE ip_address = ?", memberIP).Scan(&pid)
			if err == nil {
				existingPeerIDs = append(existingPeerIDs, pid)
			} else {
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
			if cErr := memberRows.Close(); cErr != nil {
				log.Warn("Error closing memberRows", "error", cErr)
			}
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

func resolveService(ctx context.Context, database db.Querier, sessionID int64, rule *iptparse.ParsedRule) (int64, int64) {
	port := rule.DestPort
	protocol := rule.Protocol
	if protocol == "" || protocol == "all" {
		// Protocol "all" in iptables means the rule applies to both TCP and UDP.
		// Use "both" which is the Runic protocol value that expands to tcp+udp rules.
		protocol = "both"
	}
	if port == "" {
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

// whether the remote endpoint is an existing agent-based peer.
// The importing peer always gets rules (backward for INPUT, forward for OUTPUT).
// If the remote endpoint is also agent-based (or is a special/group), direction becomes 'both'.
func determineDirection(ctx context.Context, chain string, remoteType string, remoteID int64, remoteStagingID int64, database db.Querier) string {
	// Default: importing peer gets rules only
	defaultDir := "backward" // INPUT chain (importing peer = target)
	if chain == "OUTPUT" {
		defaultDir = "forward" // OUTPUT chain (importing peer = source)
	}

	// Special endpoints → both (safe default)
	if remoteType == "special" {
		return "both"
	}

	// Group endpoints → both (groups may contain agent peers)
	if remoteType == "group" {
		return "both"
	}

	// Peer endpoint: check if it's an existing agent-based peer
	if remoteType == "peer" && remoteID != 0 && remoteStagingID == 0 {
		var isManual bool
		err := database.QueryRowContext(ctx, "SELECT is_manual FROM peers WHERE id = ?", remoteID).Scan(&isManual)
		if err == nil && !isManual {
			return "both" // Existing agent-based peer
		}
	}

	// Staging peer, manual peer, or unknown → only importing peer gets rules
	return defaultDir
}

func createStagingPeer(ctx context.Context, database db.Querier, sessionID int64, ip, hostname string) (int64, error) {
	ip = resolve.NormalizeIP(ip) // Normalize before dedup/insert
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
				if netIP := strings.Split(ip, "/")[0]; netIP != "" {
					result[currentName] = append(result[currentName], netIP)
				}
			}
		}
	}
	return result
}

// Zero maps to NULL (Valid=false), non-zero maps to the integer value (Valid=true).
func sqlNullInt64(v int64) sql.NullInt64 {
	return sql.NullInt64{Int64: v, Valid: v != 0}
}

// Empty string maps to NULL (Valid=false), non-empty maps to the string value (Valid=true).
func sqlNullString(v string) sql.NullString {
	return sql.NullString{String: v, Valid: v != ""}
}

// Multicast INPUT rules map to: source=special(__all_hosts__, ID=3), target=peer(self), service=Multicast system service.
// This mirrors the broadcast pattern: source=special, target=peer, direction=both.
func resolveMulticastRule(ctx context.Context, database db.Querier, ruleID int64, peerID int64) error {
	var multicastServiceID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE name = 'Multicast' AND is_system = 1",
	).Scan(&multicastServiceID)
	if err != nil {
		return fmt.Errorf("multicast system service not found: %w", err)
	}

	// Determine the peer's primary IP for the target_ip field
	var primaryIP string
	_ = database.QueryRowContext(ctx, "SELECT ip_address FROM peers WHERE id = ?", peerID).Scan(&primaryIP)

	// source = __all_hosts__ (IGMP/multicast group, the broadcast domain)
	// target = peer (the machine receiving the multicast)
	_, err = database.ExecContext(ctx,
		"UPDATE import_rules SET source_type = 'special', source_id = ?, source_staging_id = NULL, target_type = 'peer', target_id = ?, target_staging_id = NULL, service_id = ?, service_staging_id = NULL, source_ip = '', direction = 'both', target_ip = ?, status = 'resolved' WHERE id = ?",
		int64(resolve.SpecialIDAllHosts), peerID, multicastServiceID, primaryIP, ruleID,
	)
	return err
}

// the broadcast special target ID. This avoids the bug where resolveService()
// would return "Multicast" for UDP protocol with no ports, since it just picks
// the first matching system service.
func resolveBroadcastService(ctx context.Context, database db.Querier, broadcastSpecialID int64) (int64, error) {
	var serviceName string
	switch broadcastSpecialID {
	case int64(resolve.SpecialIDSubnetBroadcast): // 1
		serviceName = "Subnet Broadcast"
	case int64(resolve.SpecialIDLimitedBroadcast): // 2
		serviceName = "Limited Broadcast"
	default:
		return 0, fmt.Errorf("unknown broadcast special ID: %d", broadcastSpecialID)
	}

	var serviceID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM services WHERE name = ? AND is_system = 1", serviceName,
	).Scan(&serviceID)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve broadcast service '%s': %w", serviceName, err)
	}
	return serviceID, nil
}

// a broadcast address) to Runic policy entities.
// Broadcast INPUT rules map to: source=special(broadcast), target=peer(self), service=broadcast system service.
// This corrects the semantic mismatch: in iptables, -d 255.255.255.255 describes the
// packet's destination, but in Runic's policy model, the broadcast address semantically
// represents the source (the broadcast domain), while the target is the peer itself
// (the machine receiving the broadcast).
func resolveBroadcastRule(ctx context.Context, database db.Querier, sessionID int64, ruleID int64, peerID int64, broadcastSpecialID int64, rule *iptparse.ParsedRule) error {
	// broadcastSpecialID is already determined by resolve.IsBroadcastDest()

	// Resolve broadcast-specific service
	var serviceID int64
	if rule.DestPort != "" {
		// If the broadcast rule has a specific port, resolve the port-specific service
		// (e.g., DHCP port 67) rather than the generic broadcast system service
		serviceID, _ = resolveService(ctx, database, sessionID, rule)
		if serviceID == 0 {
			log.Warn("Broadcast rule with specific port failed to resolve service", "rule_id", ruleID, "port", rule.DestPort, "protocol", rule.Protocol)
		}
	} else {
		// No specific port — resolve to the appropriate broadcast system service
		var err error
		serviceID, err = resolveBroadcastService(ctx, database, broadcastSpecialID)
		if err != nil {
			return fmt.Errorf("failed to resolve broadcast service: %w", err)
		}
	}

	// Determine the peer's primary IP for the target_ip field
	var primaryIP string
	_ = database.QueryRowContext(ctx, "SELECT ip_address FROM peers WHERE id = ?", peerID).Scan(&primaryIP)

	// Determine direction: use 'both' for broadcast-only rules (no specific port),
	// but preserve the parsed direction for port-specific rules (e.g., DHCP)
	direction := "both"
	if rule.DestPort != "" {
		var origDir string
		err := database.QueryRowContext(ctx, "SELECT direction FROM import_rules WHERE id = ?", ruleID).Scan(&origDir)
		if err == nil && origDir != "" {
			direction = origDir
		}
	}

	// source = broadcast special target (the broadcast domain)
	// target = peer (the machine receiving the broadcast)
	_, err := database.ExecContext(ctx,
		"UPDATE import_rules SET source_type = 'special', source_id = ?, target_type = 'peer', target_id = ?, service_id = ?, direction = ?, target_ip = ?, status = 'resolved' WHERE id = ?",
		broadcastSpecialID, peerID, serviceID, direction, primaryIP, ruleID,
	)
	return err
}
