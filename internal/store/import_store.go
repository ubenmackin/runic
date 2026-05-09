package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	apicommon "runic/internal/api/common"
	"runic/internal/common"
	"runic/internal/db"
	"runic/internal/importer"
	"runic/internal/models"
)

type ImportStore struct {
	db           db.DB
	peerStore    *PeerStore
	groupStore   *GroupStore
	serviceStore *ServiceStore
}

func NewImportStore(database db.DB, peerStore *PeerStore, groupStore *GroupStore, serviceStore *ServiceStore) *ImportStore {
	return &ImportStore{
		db:           database,
		peerStore:    peerStore,
		groupStore:   groupStore,
		serviceStore: serviceStore,
	}
}

func (s *ImportStore) GetPeerForImport(ctx context.Context, peerID int64) (isManual bool, hostname string, bundleVersion string, err error) {
	var bundle sql.NullString
	err = s.db.QueryRowContext(ctx, "SELECT is_manual, hostname, bundle_version FROM peers WHERE id = ?", peerID).
		Scan(&isManual, &hostname, &bundle)
	if err != nil {
		return false, "", "", fmt.Errorf("get peer for import: %w", err)
	}
	if bundle.Valid {
		bundleVersion = bundle.String
	}
	return isManual, hostname, bundleVersion, nil
}

func (s *ImportStore) GetPeerHostname(ctx context.Context, peerID int64) (string, error) {
	hostname, err := s.peerStore.GetPeerHostname(ctx, int(peerID))
	if err != nil {
		return "", fmt.Errorf("get peer hostname: %w", err)
	}
	return hostname, nil
}

func (s *ImportStore) GetRules(ctx context.Context, sessionID int64) ([]models.ImportRule, error) {
	query := `SELECT id, session_id, chain, rule_order, raw_rule, status, skip_reason, 
		source_type, source_id, source_staging_id, target_type, target_id, target_staging_id, 
		service_id, service_staging_id, action, priority, direction, target_scope, policy_name, 
		enabled, description, source_ip, target_ip 
		FROM import_rules WHERE session_id = ? 
		ORDER BY CASE chain WHEN 'INPUT' THEN 1 WHEN 'OUTPUT' THEN 2 WHEN 'DOCKER-USER' THEN 3 END, rule_order`

	rows, err := s.db.QueryContext(ctx, query, sessionID)
	if err != nil {
		return nil, fmt.Errorf("query rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var rules []models.ImportRule
	for rows.Next() {
		var r struct {
			ID               int64
			SessionID        int64
			Chain            string
			RuleOrder        int
			RawRule          string
			Status           string
			SkipReason       sql.NullString
			SourceType       sql.NullString
			SourceID         sql.NullInt64
			SourceStagingID  sql.NullInt64
			TargetType       sql.NullString
			TargetID         sql.NullInt64
			TargetStagingID  sql.NullInt64
			ServiceID        sql.NullInt64
			ServiceStagingID sql.NullInt64
			Action           sql.NullString
			Priority         sql.NullInt64
			Direction        sql.NullString
			TargetScope      sql.NullString
			PolicyName       sql.NullString
			Enabled          int
			Description      sql.NullString
			SourceIP         sql.NullString
			TargetIP         sql.NullString
		}
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Chain, &r.RuleOrder, &r.RawRule, &r.Status,
			&r.SkipReason, &r.SourceType, &r.SourceID, &r.SourceStagingID, &r.TargetType, &r.TargetID,
			&r.TargetStagingID, &r.ServiceID, &r.ServiceStagingID, &r.Action, &r.Priority, &r.Direction,
			&r.TargetScope, &r.PolicyName, &r.Enabled, &r.Description, &r.SourceIP, &r.TargetIP); err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}

		rule := models.ImportRule{
			ID:         r.ID,
			SessionID:  r.SessionID,
			Chain:      r.Chain,
			RuleOrder:  r.RuleOrder,
			RawRule:    r.RawRule,
			Status:     r.Status,
			Action:     r.Action.String,
			PolicyName: r.PolicyName.String,
			Enabled:    r.Enabled == 1,
		}

		if r.SkipReason.Valid {
			rule.SkipReason = r.SkipReason.String
		}
		if r.SourceType.Valid {
			rule.SourceType = r.SourceType.String
		}
		if r.TargetType.Valid {
			rule.TargetType = r.TargetType.String
		}
		if r.Direction.Valid {
			rule.Direction = r.Direction.String
		}
		if r.TargetScope.Valid {
			rule.TargetScope = r.TargetScope.String
		}
		if r.Priority.Valid {
			rule.Priority = int(r.Priority.Int64)
		}
		if r.Description.Valid {
			rule.Description = r.Description.String
		}

		if r.SourceID.Valid {
			id := r.SourceID.Int64
			rule.SourceID = &id
		}
		if r.SourceStagingID.Valid {
			id := r.SourceStagingID.Int64
			rule.SourceStagingID = &id
		}
		if r.TargetID.Valid {
			id := r.TargetID.Int64
			rule.TargetID = &id
		}
		if r.TargetStagingID.Valid {
			id := r.TargetStagingID.Int64
			rule.TargetStagingID = &id
		}
		if r.ServiceID.Valid {
			id := r.ServiceID.Int64
			rule.ServiceID = &id
		}
		if r.ServiceStagingID.Valid {
			id := r.ServiceStagingID.Int64
			rule.ServiceStagingID = &id
		}

		if r.SourceIP.Valid {
			ip := r.SourceIP.String
			rule.SourceIP = &ip
		}
		if r.TargetIP.Valid {
			ip := r.TargetIP.String
			rule.TargetIP = &ip
		}

		rule.SourceName = s.ResolveEntityName(ctx, r.SourceType, r.SourceID, r.SourceStagingID, sessionID, r.SourceIP)
		rule.TargetName = s.ResolveEntityName(ctx, r.TargetType, r.TargetID, r.TargetStagingID, sessionID, r.TargetIP)
		rule.ServiceName = s.ResolveServiceName(ctx, r.ServiceID, r.ServiceStagingID, sessionID)

		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error rules: %w", err)
	}

	return common.EnsureSlice(rules), nil
}

func (s *ImportStore) GetGroups(ctx context.Context, sessionID int64) ([]models.ImportGroupMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, session_id, group_name, ipset_name, status, existing_group_id, member_ips, member_peer_ids, member_staging_peer_ids FROM import_group_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("query groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []models.ImportGroupMapping
	for rows.Next() {
		var g struct {
			ID               int64
			SessionID        int64
			GroupName        string
			IpsetName        sql.NullString
			Status           string
			ExistingGroupID  sql.NullInt64
			MemberIPs        string
			MemberPeerIDs    string
			MemberStagingIDs string
		}
		if err := rows.Scan(&g.ID, &g.SessionID, &g.GroupName, &g.IpsetName, &g.Status, &g.ExistingGroupID, &g.MemberIPs, &g.MemberPeerIDs, &g.MemberStagingIDs); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}

		mapping := models.ImportGroupMapping{
			ID:        g.ID,
			SessionID: g.SessionID,
			GroupName: g.GroupName,
			Status:    g.Status,
			MemberIPs: []string{},
		}
		if g.IpsetName.Valid {
			mapping.IpsetName = g.IpsetName.String
		}
		if g.ExistingGroupID.Valid {
			id := g.ExistingGroupID.Int64
			mapping.ExistingGroupID = &id
			if name, err := s.groupStore.GetNameByID(ctx, int(id)); err == nil {
				mapping.ExistingGroupName = name
			}
		}

		_ = json.Unmarshal([]byte(g.MemberIPs), &mapping.MemberIPs)
		groups = append(groups, mapping)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error groups: %w", err)
	}
	return common.EnsureSlice(groups), nil
}

func (s *ImportStore) GetPeers(ctx context.Context, sessionID int64) ([]models.ImportPeerMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, session_id, ip_address, hostname, status, existing_peer_id FROM import_peer_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("query peers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var peers []models.ImportPeerMapping
	for rows.Next() {
		var p struct {
			ID             int64
			SessionID      int64
			IPAddress      string
			Hostname       sql.NullString
			Status         string
			ExistingPeerID sql.NullInt64
		}
		if err := rows.Scan(&p.ID, &p.SessionID, &p.IPAddress, &p.Hostname, &p.Status, &p.ExistingPeerID); err != nil {
			return nil, fmt.Errorf("scan peer: %w", err)
		}

		mapping := models.ImportPeerMapping{
			ID:        p.ID,
			SessionID: p.SessionID,
			IPAddress: p.IPAddress,
			Status:    p.Status,
		}
		if p.Hostname.Valid {
			mapping.Hostname = p.Hostname.String
		}
		if p.ExistingPeerID.Valid {
			id := p.ExistingPeerID.Int64
			mapping.ExistingPeerID = &id
			if name, err := s.peerStore.GetPeerHostname(ctx, int(id)); err == nil {
				mapping.ExistingPeerName = name
			}
		}
		peers = append(peers, mapping)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error peers: %w", err)
	}
	return common.EnsureSlice(peers), nil
}

func (s *ImportStore) GetServices(ctx context.Context, sessionID int64) ([]models.ImportServiceMapping, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, session_id, name, ports, protocol, status, existing_service_id FROM import_service_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("query services: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var services []models.ImportServiceMapping
	for rows.Next() {
		var ms struct {
			ID                int64
			SessionID         int64
			Name              string
			Ports             string
			Protocol          string
			Status            string
			ExistingServiceID sql.NullInt64
		}
		if err := rows.Scan(&ms.ID, &ms.SessionID, &ms.Name, &ms.Ports, &ms.Protocol, &ms.Status, &ms.ExistingServiceID); err != nil {
			return nil, fmt.Errorf("scan service: %w", err)
		}

		mapping := models.ImportServiceMapping{
			ID:        ms.ID,
			SessionID: ms.SessionID,
			Name:      ms.Name,
			Ports:     ms.Ports,
			Protocol:  ms.Protocol,
			Status:    ms.Status,
		}
		if ms.ExistingServiceID.Valid {
			id := ms.ExistingServiceID.Int64
			mapping.ExistingServiceID = &id
			if name, err := s.serviceStore.GetNameByID(ctx, int(id)); err == nil {
				mapping.ExistingServiceName = name
			}
		}
		services = append(services, mapping)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error services: %w", err)
	}
	return common.EnsureSlice(services), nil
}

func (s *ImportStore) GetSkippedRules(ctx context.Context, sessionID int64) ([]models.SkippedRule, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, chain, rule_order, raw_rule, skip_reason FROM import_rules WHERE session_id = ? AND status = 'skipped' ORDER BY CASE chain WHEN 'INPUT' THEN 1 WHEN 'OUTPUT' THEN 2 WHEN 'DOCKER-USER' THEN 3 END, rule_order",
		sessionID)
	if err != nil {
		return nil, fmt.Errorf("query skipped rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var skipped []models.SkippedRule
	for rows.Next() {
		var sr models.SkippedRule
		if err := rows.Scan(&sr.ID, &sr.Chain, &sr.RuleOrder, &sr.RawRule, &sr.SkipReason); err != nil {
			return nil, fmt.Errorf("scan skipped rule: %w", err)
		}
		skipped = append(skipped, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error skipped rules: %w", err)
	}
	return common.EnsureSlice(skipped), nil
}

func (s *ImportStore) executeUpdate(ctx context.Context, tableName string, updates []string, args []interface{}, sessionID, entityID int64) error {
	if len(updates) == 0 {
		return errors.New("no fields to update")
	}
	args = append(args, sessionID, entityID)
	query := fmt.Sprintf("UPDATE %s SET %s WHERE session_id = ? AND id = ?", tableName, strings.Join(updates, ", "))
	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("execute update: %w", err)
	}
	return nil
}

func (s *ImportStore) UpdateRule(ctx context.Context, sessionID, ruleID int64, status, policyName, sourceIP, targetIP *string, enabled *bool) error {
	var updates []string
	var args []interface{}

	if status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *status)
	}
	if policyName != nil {
		updates = append(updates, "policy_name = ?")
		args = append(args, *policyName)
	}
	if enabled != nil {
		val := 0
		if *enabled {
			val = 1
		}
		updates = append(updates, "enabled = ?")
		args = append(args, val)
	}
	if sourceIP != nil {
		updates = append(updates, "source_ip = ?")
		args = append(args, *sourceIP)
	}
	if targetIP != nil {
		updates = append(updates, "target_ip = ?")
		args = append(args, *targetIP)
	}

	return s.executeUpdate(ctx, "import_rules", updates, args, sessionID, ruleID)
}

func (s *ImportStore) UpdateGroup(ctx context.Context, sessionID, groupID int64, status *string, existingGroupID *int64) error {
	var updates []string
	var args []interface{}

	if status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *status)
	}
	if existingGroupID != nil {
		updates = append(updates, "existing_group_id = ?")
		args = append(args, *existingGroupID)
	}

	return s.executeUpdate(ctx, "import_group_mappings", updates, args, sessionID, groupID)
}

func (s *ImportStore) UpdatePeer(ctx context.Context, sessionID, peerID int64, status *string, existingPeerID *int64) error {
	var updates []string
	var args []interface{}

	if status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *status)
	}
	if existingPeerID != nil {
		updates = append(updates, "existing_peer_id = ?")
		args = append(args, *existingPeerID)
	}

	return s.executeUpdate(ctx, "import_peer_mappings", updates, args, sessionID, peerID)
}

func (s *ImportStore) UpdateService(ctx context.Context, sessionID, serviceID int64, status *string, existingServiceID *int64) error {
	var updates []string
	var args []interface{}

	if status != nil {
		updates = append(updates, "status = ?")
		args = append(args, *status)
	}
	if existingServiceID != nil {
		updates = append(updates, "existing_service_id = ?")
		args = append(args, *existingServiceID)
	}

	return s.executeUpdate(ctx, "import_service_mappings", updates, args, sessionID, serviceID)
}

func (s *ImportStore) ResolveEntityName(ctx context.Context, entityType sql.NullString, entityID sql.NullInt64, stagingID sql.NullInt64, sessionID int64, matchedIP sql.NullString) string {
	if !entityType.Valid || entityType.String == "" {
		return ""
	}

	if entityID.Valid && entityID.Int64 != 0 {
		switch entityType.String {
		case "peer":
			var name string
			var err error
			name, err = s.peerStore.GetPeerHostname(ctx, int(entityID.Int64))
			if err == nil {
				if matchedIP.Valid && matchedIP.String != "" {
					return fmt.Sprintf("%s (%s)", name, matchedIP.String)
				}
				return name
			}
		case "group":
			var name string
			var err error
			name, err = s.groupStore.GetNameByID(ctx, int(entityID.Int64))
			if err == nil {
				return name
			}
		case "special":
			var name string
			if err := s.db.QueryRowContext(ctx, "SELECT display_name FROM special_targets WHERE id = ?", entityID.Int64).Scan(&name); err == nil {
				return name
			}
		}
	}

	if stagingID.Valid && stagingID.Int64 != 0 {
		switch entityType.String {
		case "peer":
			var name string
			if err := s.db.QueryRowContext(ctx, "SELECT hostname FROM import_peer_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
				if matchedIP.Valid && matchedIP.String != "" {
					return fmt.Sprintf("%s (%s)", name, matchedIP.String)
				}
				return name
			}
		case "group":
			var name string
			if err := s.db.QueryRowContext(ctx, "SELECT group_name FROM import_group_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
				return name
			}
		}
	}

	return ""
}

func (s *ImportStore) ResolveServiceName(ctx context.Context, serviceID sql.NullInt64, stagingID sql.NullInt64, sessionID int64) string {
	if serviceID.Valid && serviceID.Int64 != 0 {
		var name string
		var err error
		name, err = s.serviceStore.GetNameByID(ctx, int(serviceID.Int64))
		if err == nil {
			return name
		}
	}

	if stagingID.Valid && stagingID.Int64 != 0 {
		var name string
		if err := s.db.QueryRowContext(ctx, "SELECT name FROM import_service_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
			return name
		}
	}

	return ""
}

func (s *ImportStore) CountApprovedRules(ctx context.Context, sessionID int64) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM import_rules WHERE session_id = ? AND status = 'approved'", sessionID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count approved rules: %w", err)
	}
	return count, nil
}

func (s *ImportStore) SubmitBackupSession(ctx context.Context, peerID int64, iptablesBackup, ipsetList string) (int64, error) {
	var sessionID int64

	err := RunInTx(ctx, s.db, func(tx *sql.Tx) error {
		var existingID int64
		var existingStatus string
		err := tx.QueryRowContext(ctx, "SELECT id, status FROM import_sessions WHERE peer_id = ? AND status IN ('pending','parsed','reviewing')", peerID).Scan(&existingID, &existingStatus)

		switch {
		case err == nil:
			sessionID = existingID
			if existingStatus == "pending" {
				_, err = tx.ExecContext(ctx, "UPDATE import_sessions SET raw_backup = ?, raw_ipsets = ?, updated_at = CURRENT_TIMESTAMP WHERE peer_id = ? AND status = 'pending'", iptablesBackup, ipsetList, peerID)
				if err != nil {
					return fmt.Errorf("failed to update import session: %w", err)
				}
			}
		case errors.Is(err, sql.ErrNoRows):
			result, err := tx.ExecContext(ctx, "INSERT INTO import_sessions (peer_id, status, raw_backup, raw_ipsets) VALUES (?, 'pending', ?, ?)", peerID, iptablesBackup, ipsetList)
			if err != nil {
				return fmt.Errorf("failed to create import session: %w", err)
			}
			sessionID, err = result.LastInsertId()
			if err != nil {
				return fmt.Errorf("failed to get session ID: %w", err)
			}
		default:
			return fmt.Errorf("database error: %w", err)
		}
		return nil
	})

	if err != nil {
		return 0, err
	}

	return sessionID, nil
}

// GetSessionByPeer returns the active import session for the given peer, if any.
func (s *ImportStore) GetSessionByPeer(ctx context.Context, peerID int64) (*importer.ImportSession, error) {
	session, err := importer.GetSessionByPeer(ctx, s.db, peerID)
	if err != nil {
		return nil, fmt.Errorf("get session by peer: %w", err)
	}
	return session, nil
}

// CreateSession creates a new import session for the given peer.
func (s *ImportStore) CreateSession(ctx context.Context, peerID int64, rawBackup, rawIpsets string) (*importer.ImportSession, error) {
	sqlDB, ok := s.db.(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("create session: underlying DB is not *sql.DB")
	}
	session, err := importer.CreateSession(ctx, sqlDB, peerID, rawBackup, rawIpsets)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return session, nil
}

// GetSession returns the import session with the given ID.
func (s *ImportStore) GetSession(ctx context.Context, sessionID int64) (*importer.ImportSession, error) {
	session, err := importer.GetSession(ctx, s.db, sessionID)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return session, nil
}

// UpdateSessionStatus updates the status of the import session with the given ID.
func (s *ImportStore) UpdateSessionStatus(ctx context.Context, sessionID int64, status string) error {
	err := importer.UpdateSessionStatus(ctx, s.db, sessionID, status)
	if err != nil {
		return fmt.Errorf("update session status: %w", err)
	}
	return nil
}

// ApplySession applies the import session, creating peers, groups, services, and policies.
func (s *ImportStore) ApplySession(ctx context.Context, sessionID int64, changeWorker *apicommon.ChangeWorker) (*importer.ApplyResult, error) {
	sqlDB, ok := s.db.(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("apply session: underlying DB is not *sql.DB")
	}
	result, err := importer.ApplySession(ctx, sqlDB, sessionID, changeWorker)
	if err != nil {
		return nil, fmt.Errorf("apply session: %w", err)
	}
	return result, nil
}

// DeleteSession deletes the import session with the given ID.
func (s *ImportStore) DeleteSession(ctx context.Context, sessionID int64) error {
	sqlDB, ok := s.db.(*sql.DB)
	if !ok {
		return fmt.Errorf("delete session: underlying DB is not *sql.DB")
	}
	err := importer.DeleteSession(ctx, sqlDB, sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}
