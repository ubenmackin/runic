// Package importer provides logic for parsing iptables backups and applying import sessions.
package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/sqlutil"
)

type ApplyResult struct {
	PoliciesCreated int
	GroupsCreated   int
	PeersCreated    int
	ServicesCreated int
}

type createdEntity struct {
	entityType string
	entityID   int
	summary    string
}

// ApplySession creates manual peers, groups, services, and policies from the import session.
func ApplySession(ctx context.Context, database db.DB, sessionID int64, changeWorker *common.ChangeWorker) (*ApplyResult, error) {
	result := &ApplyResult{}

	var createdEntities []createdEntity

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rErr := tx.Rollback(); rErr != nil {
				log.Warn("Rollback failed", "error", rErr)
			}
		}
	}()

	// 0. Collect all staging entity IDs referenced by approved rules
	stagingPeerIDSet := make(map[int64]bool)
	stagingGroupIDSet := make(map[int64]bool)
	stagingServiceIDSet := make(map[int64]bool)

	refRows, err := tx.QueryContext(ctx,
		"SELECT source_staging_id, target_staging_id, service_staging_id, source_type, target_type FROM import_rules WHERE session_id = ? AND status = 'approved'",
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("query approved rule references: %w", err)
	}
	for refRows.Next() {
		var sourceStagingID, targetStagingID, serviceStagingID sql.NullInt64
		var sourceType, targetType sql.NullString
		if err := refRows.Scan(&sourceStagingID, &targetStagingID, &serviceStagingID, &sourceType, &targetType); err != nil {
			if cErr := refRows.Close(); cErr != nil {
				log.Warn("Error closing refRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan approved rule reference: %w", err)
		}
		if sourceStagingID.Valid && sourceStagingID.Int64 != 0 {
			if sourceType.Valid && sourceType.String == "peer" {
				stagingPeerIDSet[sourceStagingID.Int64] = true
			} else if sourceType.Valid && sourceType.String == "group" {
				stagingGroupIDSet[sourceStagingID.Int64] = true
			}
		}
		if targetStagingID.Valid && targetStagingID.Int64 != 0 {
			if targetType.Valid && targetType.String == "peer" {
				stagingPeerIDSet[targetStagingID.Int64] = true
			} else if targetType.Valid && targetType.String == "group" {
				stagingGroupIDSet[targetStagingID.Int64] = true
			}
		}
		if serviceStagingID.Valid && serviceStagingID.Int64 != 0 {
			stagingServiceIDSet[serviceStagingID.Int64] = true
		}
	}
	if cErr := refRows.Close(); cErr != nil {
		log.Warn("Error closing refRows", "error", cErr)
	}

	// Also add staging peers that are group members of referenced staging groups
	if len(stagingGroupIDSet) > 0 {
		groupIDs := make([]interface{}, 0, len(stagingGroupIDSet))
		for id := range stagingGroupIDSet {
			groupIDs = append(groupIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(groupIDs))
		gMemberRows, err := tx.QueryContext(ctx,
			fmt.Sprintf("SELECT member_staging_peer_ids FROM import_group_mappings WHERE session_id = ? AND id IN (%s)", placeholders),
			append([]interface{}{sessionID}, groupIDs...)...,
		)
		if err == nil {
			for gMemberRows.Next() {
				var memberJSON string
				if gMemberRows.Scan(&memberJSON) == nil {
					var stagingPeerIDs []int64
					if json.Unmarshal([]byte(memberJSON), &stagingPeerIDs) == nil {
						for _, spid := range stagingPeerIDs {
							stagingPeerIDSet[spid] = true
						}
					}
				}
			}
			if cErr := gMemberRows.Close(); cErr != nil {
				log.Warn("Error closing gMemberRows", "error", cErr)
			}
		}
	}

	// 1. Create manual peers from import_peer_mappings referenced by approved rules
	peerQuery := "SELECT id, ip_address, hostname FROM import_peer_mappings WHERE session_id = ? AND existing_peer_id IS NULL"
	peerArgs := []interface{}{sessionID}
	if len(stagingPeerIDSet) > 0 {
		peerIDs := make([]interface{}, 0, len(stagingPeerIDSet))
		for id := range stagingPeerIDSet {
			peerIDs = append(peerIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(peerIDs))
		peerQuery = fmt.Sprintf("%s AND id IN (%s)", peerQuery, placeholders)
		peerArgs = append(peerArgs, peerIDs...)
	} else {
		// No referenced peers — use impossible ID to return empty set
		peerQuery += " AND id = -1"
	}
	peerRows, err := tx.QueryContext(ctx, peerQuery, peerArgs...)
	if err != nil {
		return nil, fmt.Errorf("query peer mappings: %w", err)
	}

	// Map staging peer ID -> real peer ID for later resolution
	stagingToRealPeer := make(map[int64]int64)

	type peerMapping struct {
		StagingID int64
		IP        string
		Hostname  string
	}
	var peerMappings []peerMapping

	for peerRows.Next() {
		var pm peerMapping
		if err := peerRows.Scan(&pm.StagingID, &pm.IP, &pm.Hostname); err != nil {
			if cErr := peerRows.Close(); cErr != nil {
				log.Warn("Error closing peerRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan peer mapping: %w", err)
		}
		peerMappings = append(peerMappings, pm)
	}
	if cErr := peerRows.Close(); cErr != nil {
		log.Warn("Error closing peerRows", "error", cErr)
	}

	for _, pm := range peerMappings {
		agentKey := fmt.Sprintf("imported-%s", pm.IP)
		res, err := tx.ExecContext(ctx,
			"INSERT INTO peers (hostname, ip_address, is_manual, agent_key, hmac_key, status) VALUES (?, ?, 1, ?, '', 'offline')",
			pm.Hostname, pm.IP, agentKey,
		)
		if err != nil {
			return nil, fmt.Errorf("create manual peer %s: %w", pm.IP, err)
		}
		realID, _ := res.LastInsertId()
		stagingToRealPeer[pm.StagingID] = realID
		_, err = tx.ExecContext(ctx, "INSERT INTO peer_ips (peer_id, ip_address, is_primary) VALUES (?, ?, 1)", realID, pm.IP)
		if err != nil {
			return nil, fmt.Errorf("create peer IP %s: %w", pm.IP, err)
		}
		if err := db.CreateSnapshot(ctx, tx, "peer", int(realID), "create", ""); err != nil {
			return nil, fmt.Errorf("create peer snapshot: %w", err)
		}
		createdEntities = append(createdEntities, createdEntity{entityType: "peer", entityID: int(realID), summary: "Imported peer created"})
		result.PeersCreated++
	}

	// Update staging peers that were mapped to existing peers (only those referenced by approved rules)
	existingPeerQuery := "SELECT id, existing_peer_id FROM import_peer_mappings WHERE session_id = ? AND existing_peer_id IS NOT NULL"
	existingPeerArgs := []interface{}{sessionID}
	if len(stagingPeerIDSet) > 0 {
		epIDs := make([]interface{}, 0, len(stagingPeerIDSet))
		for id := range stagingPeerIDSet {
			epIDs = append(epIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(epIDs))
		existingPeerQuery = fmt.Sprintf("%s AND id IN (%s)", existingPeerQuery, placeholders)
		existingPeerArgs = append(existingPeerArgs, epIDs...)
	} else {
		existingPeerQuery += " AND id = -1"
	}
	existingPeerRows, err := tx.QueryContext(ctx, existingPeerQuery, existingPeerArgs...)
	if err != nil {
		return nil, fmt.Errorf("query existing peer mappings: %w", err)
	}
	for existingPeerRows.Next() {
		var stagingID, realID int64
		if err := existingPeerRows.Scan(&stagingID, &realID); err != nil {
			if cErr := existingPeerRows.Close(); cErr != nil {
				log.Warn("Error closing existingPeerRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan existing peer mapping: %w", err)
		}
		stagingToRealPeer[stagingID] = realID
	}
	if cErr := existingPeerRows.Close(); cErr != nil {
		log.Warn("Error closing existingPeerRows", "error", cErr)
	}

	// 2. Create groups from import_group_mappings referenced by approved rules
	groupQuery := "SELECT id, group_name, member_ips, member_peer_ids, member_staging_peer_ids FROM import_group_mappings WHERE session_id = ? AND existing_group_id IS NULL"
	groupArgs := []interface{}{sessionID}
	if len(stagingGroupIDSet) > 0 {
		gIDs := make([]interface{}, 0, len(stagingGroupIDSet))
		for id := range stagingGroupIDSet {
			gIDs = append(gIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(gIDs))
		groupQuery = fmt.Sprintf("%s AND id IN (%s)", groupQuery, placeholders)
		groupArgs = append(groupArgs, gIDs...)
	} else {
		groupQuery += " AND id = -1"
	}
	groupRows, err := tx.QueryContext(ctx, groupQuery, groupArgs...)
	if err != nil {
		return nil, fmt.Errorf("query group mappings: %w", err)
	}

	stagingToRealGroup := make(map[int64]int64)

	type groupMapping struct {
		StagingID        int64
		GroupName        string
		MemberIPs        string
		MemberPeerIDs    string
		MemberStagingIDs string
	}
	var groupMappings []groupMapping

	for groupRows.Next() {
		var gm groupMapping
		if err := groupRows.Scan(&gm.StagingID, &gm.GroupName, &gm.MemberIPs, &gm.MemberPeerIDs, &gm.MemberStagingIDs); err != nil {
			if cErr := groupRows.Close(); cErr != nil {
				log.Warn("Error closing groupRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan group mapping: %w", err)
		}
		groupMappings = append(groupMappings, gm)
	}
	if cErr := groupRows.Close(); cErr != nil {
		log.Warn("Error closing groupRows", "error", cErr)
	}

	for _, gm := range groupMappings {
		res, err := tx.ExecContext(ctx,
			"INSERT INTO groups (name, description) VALUES (?, ?)",
			gm.GroupName, "Imported from iptables ipset",
		)
		if err != nil {
			return nil, fmt.Errorf("create group %s: %w", gm.GroupName, err)
		}
		realGroupID, _ := res.LastInsertId()
		stagingToRealGroup[gm.StagingID] = realGroupID
		if err := db.CreateSnapshot(ctx, tx, "group", int(realGroupID), "create", ""); err != nil {
			return nil, fmt.Errorf("create group snapshot: %w", err)
		}
		createdEntities = append(createdEntities, createdEntity{entityType: "group", entityID: int(realGroupID), summary: "Imported group created"})
		result.GroupsCreated++

		var memberPeerIDs []int64
		if err := json.Unmarshal([]byte(gm.MemberPeerIDs), &memberPeerIDs); err != nil {
			return nil, fmt.Errorf("unmarshal member peer IDs for group %s: %w", gm.GroupName, err)
		}
		for _, pid := range memberPeerIDs {
			if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)", realGroupID, pid); err != nil {
				return nil, fmt.Errorf("insert group member peer %d into group %s: %w", pid, gm.GroupName, err)
			}
		}

		var stagingPeerIDs []int64
		if err := json.Unmarshal([]byte(gm.MemberStagingIDs), &stagingPeerIDs); err != nil {
			return nil, fmt.Errorf("unmarshal staging peer IDs for group %s: %w", gm.GroupName, err)
		}
		for _, spid := range stagingPeerIDs {
			if realPID, ok := stagingToRealPeer[spid]; ok {
				if _, err := tx.ExecContext(ctx, "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?, ?)", realGroupID, realPID); err != nil {
					return nil, fmt.Errorf("insert group member staging peer %d into group %s: %w", realPID, gm.GroupName, err)
				}
			}
		}
	}

	// Update staging groups that were mapped to existing groups (only those referenced by approved rules)
	existingGroupQuery := "SELECT id, existing_group_id FROM import_group_mappings WHERE session_id = ? AND existing_group_id IS NOT NULL"
	existingGroupArgs := []interface{}{sessionID}
	if len(stagingGroupIDSet) > 0 {
		egIDs := make([]interface{}, 0, len(stagingGroupIDSet))
		for id := range stagingGroupIDSet {
			egIDs = append(egIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(egIDs))
		existingGroupQuery = fmt.Sprintf("%s AND id IN (%s)", existingGroupQuery, placeholders)
		existingGroupArgs = append(existingGroupArgs, egIDs...)
	} else {
		existingGroupQuery += " AND id = -1"
	}
	existingGroupRows, err := tx.QueryContext(ctx, existingGroupQuery, existingGroupArgs...)
	if err != nil {
		return nil, fmt.Errorf("query existing group mappings: %w", err)
	}
	for existingGroupRows.Next() {
		var stagingID, realID int64
		if err := existingGroupRows.Scan(&stagingID, &realID); err != nil {
			if cErr := existingGroupRows.Close(); cErr != nil {
				log.Warn("Error closing existingGroupRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan existing group mapping: %w", err)
		}
		stagingToRealGroup[stagingID] = realID
	}
	if cErr := existingGroupRows.Close(); cErr != nil {
		log.Warn("Error closing existingGroupRows", "error", cErr)
	}

	// 3. Create services from import_service_mappings referenced by approved rules
	svcQuery := "SELECT id, name, ports, source_ports, protocol, direction_hint FROM import_service_mappings WHERE session_id = ? AND existing_service_id IS NULL"
	svcArgs := []interface{}{sessionID}
	if len(stagingServiceIDSet) > 0 {
		sIDs := make([]interface{}, 0, len(stagingServiceIDSet))
		for id := range stagingServiceIDSet {
			sIDs = append(sIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(sIDs))
		svcQuery = fmt.Sprintf("%s AND id IN (%s)", svcQuery, placeholders)
		svcArgs = append(svcArgs, sIDs...)
	} else {
		svcQuery += " AND id = -1"
	}
	svcRows, err := tx.QueryContext(ctx, svcQuery, svcArgs...)
	if err != nil {
		return nil, fmt.Errorf("query service mappings: %w", err)
	}

	stagingToRealService := make(map[int64]int64)

	type svcMapping struct {
		StagingID     int64
		Name          string
		Ports         string
		SourcePorts   string
		Protocol      string
		DirectionHint string
	}
	var svcMappings []svcMapping

	for svcRows.Next() {
		var sm svcMapping
		if err := svcRows.Scan(&sm.StagingID, &sm.Name, &sm.Ports, &sm.SourcePorts, &sm.Protocol, &sm.DirectionHint); err != nil {
			if cErr := svcRows.Close(); cErr != nil {
				log.Warn("Error closing svcRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan service mapping: %w", err)
		}
		svcMappings = append(svcMappings, sm)
	}
	if cErr := svcRows.Close(); cErr != nil {
		log.Warn("Error closing svcRows", "error", cErr)
	}

	for _, sm := range svcMappings {
		dirHint := sm.DirectionHint
		if dirHint == "" {
			dirHint = "inbound"
		}
		res, err := tx.ExecContext(ctx,
			"INSERT INTO services (name, ports, source_ports, protocol, direction_hint) VALUES (?, ?, ?, ?, ?)",
			sm.Name, sm.Ports, sm.SourcePorts, sm.Protocol, dirHint,
		)
		if err != nil {
			return nil, fmt.Errorf("create service %s: %w", sm.Name, err)
		}
		realSvcID, _ := res.LastInsertId()
		stagingToRealService[sm.StagingID] = realSvcID
		if err := db.CreateSnapshot(ctx, tx, "service", int(realSvcID), "create", ""); err != nil {
			return nil, fmt.Errorf("create service snapshot: %w", err)
		}
		createdEntities = append(createdEntities, createdEntity{entityType: "service", entityID: int(realSvcID), summary: "Imported service created"})
		result.ServicesCreated++
	}

	existingSvcQuery := "SELECT id, existing_service_id FROM import_service_mappings WHERE session_id = ? AND existing_service_id IS NOT NULL"
	existingSvcArgs := []interface{}{sessionID}
	if len(stagingServiceIDSet) > 0 {
		esIDs := make([]interface{}, 0, len(stagingServiceIDSet))
		for id := range stagingServiceIDSet {
			esIDs = append(esIDs, id)
		}
		placeholders := sqlutil.BuildPlaceholders(len(esIDs))
		existingSvcQuery = fmt.Sprintf("%s AND id IN (%s)", existingSvcQuery, placeholders)
		existingSvcArgs = append(existingSvcArgs, esIDs...)
	} else {
		existingSvcQuery += " AND id = -1"
	}
	existingSvcRows, err := tx.QueryContext(ctx, existingSvcQuery, existingSvcArgs...)
	if err != nil {
		return nil, fmt.Errorf("query existing service mappings: %w", err)
	}
	for existingSvcRows.Next() {
		var stagingID, realID int64
		if err := existingSvcRows.Scan(&stagingID, &realID); err != nil {
			if cErr := existingSvcRows.Close(); cErr != nil {
				log.Warn("Error closing existingSvcRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan existing service mapping: %w", err)
		}
		stagingToRealService[stagingID] = realID
	}
	if cErr := existingSvcRows.Close(); cErr != nil {
		log.Warn("Error closing existingSvcRows", "error", cErr)
	}

	// 4. Create policies from import_rules (status='approved')
	ruleRows, err := tx.QueryContext(ctx,
		"SELECT id, source_type, source_id, source_staging_id, target_type, target_id, target_staging_id, service_id, service_staging_id, action, priority, direction, target_scope, policy_name, enabled, source_ip, target_ip FROM import_rules WHERE session_id = ? AND status = 'approved'",
		sessionID,
	)
	if err != nil {
		return nil, fmt.Errorf("query approved rules: %w", err)
	}

	session, err := GetSession(ctx, tx, sessionID)
	if err != nil {
		if cErr := ruleRows.Close(); cErr != nil {
			log.Warn("Error closing ruleRows after GetSession failure", "error", cErr)
		}
		return nil, fmt.Errorf("get session: %w", err)
	}

	for ruleRows.Next() {
		var ruleID int64
		var sourceType, targetType, action, direction, targetScope, policyName string
		var priority int
		var enabled int
		var sourceID, sourceStagingID, targetID, targetStagingID, serviceID, serviceStagingID *int64
		var sourceIP, targetIP sql.NullString

		if err := ruleRows.Scan(&ruleID, &sourceType, &sourceID, &sourceStagingID, &targetType, &targetID, &targetStagingID, &serviceID, &serviceStagingID, &action, &priority, &direction, &targetScope, &policyName, &enabled, &sourceIP, &targetIP); err != nil {
			if cErr := ruleRows.Close(); cErr != nil {
				log.Warn("Error closing ruleRows after scan failure", "error", cErr)
			}
			return nil, fmt.Errorf("scan approved rule: %w", err)
		}

		// Resolve staging IDs to real IDs
		realSourceID := resolveID(sourceID, sourceStagingID, sourceType, stagingToRealPeer, stagingToRealGroup)
		realTargetID := resolveID(targetID, targetStagingID, targetType, stagingToRealPeer, stagingToRealGroup)
		realServiceID := resolveID(serviceID, serviceStagingID, "service", stagingToRealPeer, stagingToRealService)

		if realSourceID == 0 || realTargetID == 0 {
			log.Warn("Skipping rule with unresolved IDs", "rule_id", ruleID)
			continue
		}

		// Normalize source_ip/target_ip: pass nil when invalid so SQL stores NULL
		var sourceIPVal, targetIPVal interface{}
		if sourceIP.Valid {
			sourceIPVal = sourceIP.String
		}
		if targetIP.Valid {
			targetIPVal = targetIP.String
		}

		policyRes, err := tx.ExecContext(ctx,
			"INSERT INTO policies (name, source_id, source_type, service_id, target_id, target_type, action, priority, enabled, direction, target_scope, source_ip, target_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			policyName, realSourceID, sourceType, realServiceID, realTargetID, targetType, action, priority, enabled, direction, targetScope, sourceIPVal, targetIPVal,
		)
		if err != nil {
			log.Warn("Failed to create policy", "name", policyName, "error", err)
			continue
		}
		result.PoliciesCreated++
		if policyID, pErr := policyRes.LastInsertId(); pErr == nil {
			if err := db.CreateSnapshot(ctx, tx, "policy", int(policyID), "create", ""); err != nil {
				log.Warn("Failed to create policy snapshot", "policyID", policyID, "error", err)
			}
			createdEntities = append(createdEntities, createdEntity{entityType: "policy", entityID: int(policyID), summary: "Imported policy created"})
		}
	}
	if cErr := ruleRows.Close(); cErr != nil {
		log.Warn("Error closing ruleRows", "error", cErr)
	}

	// 5. Update session status to 'applied'
	if _, err := tx.ExecContext(ctx, "UPDATE import_sessions SET status = 'applied', updated_at = CURRENT_TIMESTAMP WHERE id = ?", sessionID); err != nil {
		return nil, fmt.Errorf("update session status: %w", err)
	}

	// 6. Queue per-entity pending changes for recompilation (inside transaction, before commit)
	if changeWorker != nil {
		for _, e := range createdEntities {
			changeWorker.QueuePeerChange(ctx, []int{int(session.PeerID)}, e.entityType, "create", e.entityID, e.summary)
		}
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	log.Info("Import session applied",
		"session_id", sessionID,
		"policies", result.PoliciesCreated,
		"groups", result.GroupsCreated,
		"peers", result.PeersCreated,
		"services", result.ServicesCreated,
	)

	return result, nil
}

// resolveID resolves a staging entity ID to a real entity ID.
// peerLookup is used when entityType is "peer", groupLookup when entityType is "group" or "service".
func resolveID(realID, stagingID *int64, entityType string, peerLookup, groupLookup map[int64]int64) int64 {
	if realID != nil && *realID != 0 {
		return *realID
	}
	if stagingID != nil && *stagingID != 0 {
		switch entityType {
		case "peer":
			if id, ok := peerLookup[*stagingID]; ok {
				return id
			}
		case "group", "service":
			if id, ok := groupLookup[*stagingID]; ok {
				return id
			}
		}
	}
	return 0
}
