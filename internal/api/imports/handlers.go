// Package imports provides HTTP handlers for the iptables import session API.
package imports

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/api/events"
	runiclog "runic/internal/common/log"
	"runic/internal/importer"
)

// Handler provides HTTP handlers for import session endpoints.
type Handler struct {
	DB           *sql.DB
	SSEHub       *events.SSEHub
	ChangeWorker *common.ChangeWorker
}

// NewHandler creates a new import handler.
func NewHandler(db *sql.DB, sseHub *events.SSEHub, changeWorker *common.ChangeWorker) *Handler {
	return &Handler{DB: db, SSEHub: sseHub, ChangeWorker: changeWorker}
}

// RegisterRoutes registers the import API routes on the given subrouter.
// All routes require editor role — the caller is responsible for applying the middleware.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/peers/{id:[0-9]+}/import", h.InitiateImport).Methods("POST")
	r.HandleFunc("/import-sessions/{id:[0-9]+}", h.GetSession).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/rules", h.GetRules).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/groups", h.GetGroups).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/peers", h.GetPeers).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/services", h.GetServices).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/skipped", h.GetSkippedRules).Methods("GET")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/rules/{rule_id:[0-9]+}", h.UpdateRule).Methods("PUT")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/groups/{group_id:[0-9]+}", h.UpdateGroup).Methods("PUT")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/peers/{peer_id:[0-9]+}", h.UpdatePeer).Methods("PUT")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/services/{service_id:[0-9]+}", h.UpdateService).Methods("PUT")
	r.HandleFunc("/import-sessions/{id:[0-9]+}/apply", h.ApplySession).Methods("POST")
	r.HandleFunc("/import-sessions/{id:[0-9]+}", h.CancelSession).Methods("DELETE")
}

// InitiateImport starts an import session for a peer by triggering the agent's fetch_backup SSE event.
func (h *Handler) InitiateImport(w http.ResponseWriter, r *http.Request) {
	peerIDStr := mux.Vars(r)["id"]
	peerID, err := strconv.ParseInt(peerIDStr, 10, 64)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid peer ID"})
		return
	}

	// Check peer exists and is an agent peer (not manual)
	var isManual bool
	var hostname, bundleVersion string
	err = h.DB.QueryRowContext(r.Context(), "SELECT is_manual, hostname, bundle_version FROM peers WHERE id = ?", peerID).Scan(&isManual, &hostname, &bundleVersion)
	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "peer not found"})
		return
	}
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	if isManual {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot import rules for manual peer"})
		return
	}
	if bundleVersion != "" {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "peer already has deployed rules — import not allowed"})
		return
	}

	// Check for existing active import session
	existingSession, err := importer.GetSessionByPeer(r.Context(), h.DB, peerID)
	if err == nil && existingSession != nil {
		common.RespondJSON(w, http.StatusConflict, map[string]interface{}{
			"error":      "peer already has an active import session",
			"session_id": existingSession.ID,
		})
		return
	}

	// Create import session in pending state
	session, err := importer.CreateSession(r.Context(), h.DB, peerID, "", "")
	if err != nil {
		runiclog.Error("Failed to create import session", "error", err, "peer_id", peerID)
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create import session"})
		return
	}

	// Trigger the agent to fetch and POST its backup via SSE
	hostID := fmt.Sprintf("host-%s", hostname)
	if h.SSEHub != nil {
		h.SSEHub.NotifyFetchBackup(hostID)
		runiclog.Info("Sent fetch_backup SSE event to agent", "host_id", hostID, "peer_id", peerID)
	}

	common.RespondJSON(w, http.StatusCreated, map[string]interface{}{
		"session_id": session.ID,
		"status":     session.Status,
	})
}

// GetSession returns the details of an import session.
func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	session, err := importer.GetSession(r.Context(), h.DB, sessionID)
	if err == sql.ErrNoRows {
		common.RespondJSON(w, http.StatusNotFound, map[string]string{"error": "session not found"})
		return
	}
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	// Look up peer hostname
	var peerHostname string
	_ = h.DB.QueryRowContext(r.Context(), "SELECT hostname FROM peers WHERE id = ?", session.PeerID).Scan(&peerHostname)

	resp := ImportSession{
		ID:              session.ID,
		PeerID:          session.PeerID,
		PeerHostname:    peerHostname,
		Status:          session.Status,
		TotalRulesFound: session.TotalRulesFound,
		ImportableRules: session.ImportableRules,
		SkippedRules:    session.SkippedRules,
		CreatedAt:       session.CreatedAt,
		UpdatedAt:       session.UpdatedAt,
	}
	common.RespondJSON(w, http.StatusOK, resp)
}

// GetRules returns all parsed rules for an import session.
func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, session_id, chain, rule_order, raw_rule, status, skip_reason, source_type, source_id, source_staging_id, target_type, target_id, target_staging_id, service_id, service_staging_id, action, priority, direction, target_scope, policy_name, enabled, description, source_ip, target_ip FROM import_rules WHERE session_id = ? ORDER BY CASE chain WHEN 'INPUT' THEN 1 WHEN 'OUTPUT' THEN 2 WHEN 'DOCKER-USER' THEN 3 END, rule_order",
		sessionID)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	defer func() { _ = rows.Close() }()

	var rules []ImportRule
	ctx := r.Context()
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
		if err := rows.Scan(&r.ID, &r.SessionID, &r.Chain, &r.RuleOrder, &r.RawRule, &r.Status, &r.SkipReason, &r.SourceType, &r.SourceID, &r.SourceStagingID, &r.TargetType, &r.TargetID, &r.TargetStagingID, &r.ServiceID, &r.ServiceStagingID, &r.Action, &r.Priority, &r.Direction, &r.TargetScope, &r.PolicyName, &r.Enabled, &r.Description, &r.SourceIP, &r.TargetIP); err != nil {
			continue
		}

		rule := ImportRule{
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

		// Resolve display names (pass source_ip/target_ip for multi-IP peer name suffix)
		rule.SourceName = h.resolveEntityName(ctx, r.SourceType, r.SourceID, r.SourceStagingID, sessionID, r.SourceIP)
		rule.TargetName = h.resolveEntityName(ctx, r.TargetType, r.TargetID, r.TargetStagingID, sessionID, r.TargetIP)
		rule.ServiceName = h.resolveServiceName(ctx, r.ServiceID, r.ServiceStagingID, sessionID)

		rules = append(rules, rule)
	}

	if rules == nil {
		rules = []ImportRule{}
	}
	common.RespondJSON(w, http.StatusOK, rules)
}

// GetGroups returns all group mappings for an import session.
func (h *Handler) GetGroups(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, session_id, group_name, ipset_name, status, existing_group_id, member_ips, member_peer_ids, member_staging_peer_ids FROM import_group_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	defer func() { _ = rows.Close() }()

	var groups []ImportGroupMapping
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
			continue
		}

		mapping := ImportGroupMapping{
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
			// Get group name
			_ = h.DB.QueryRowContext(r.Context(), "SELECT name FROM groups WHERE id = ?", id).Scan(&mapping.ExistingGroupName)
		}

		_ = json.Unmarshal([]byte(g.MemberIPs), &mapping.MemberIPs)

		groups = append(groups, mapping)
	}

	if groups == nil {
		groups = []ImportGroupMapping{}
	}
	common.RespondJSON(w, http.StatusOK, groups)
}

// GetPeers returns all peer mappings for an import session.
func (h *Handler) GetPeers(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, session_id, ip_address, hostname, status, existing_peer_id FROM import_peer_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	defer func() { _ = rows.Close() }()

	var peers []ImportPeerMapping
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
			continue
		}

		mapping := ImportPeerMapping{
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
			var name string
			if err := h.DB.QueryRowContext(r.Context(), "SELECT hostname FROM peers WHERE id = ?", id).Scan(&name); err == nil {
				mapping.ExistingPeerName = name
			}
		}

		peers = append(peers, mapping)
	}

	if peers == nil {
		peers = []ImportPeerMapping{}
	}
	common.RespondJSON(w, http.StatusOK, peers)
}

// GetServices returns all service mappings for an import session.
func (h *Handler) GetServices(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, session_id, name, ports, protocol, status, existing_service_id FROM import_service_mappings WHERE session_id = ?",
		sessionID)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	defer func() { _ = rows.Close() }()

	var services []ImportServiceMapping
	for rows.Next() {
		var s struct {
			ID                int64
			SessionID         int64
			Name              string
			Ports             string
			Protocol          string
			Status            string
			ExistingServiceID sql.NullInt64
		}
		if err := rows.Scan(&s.ID, &s.SessionID, &s.Name, &s.Ports, &s.Protocol, &s.Status, &s.ExistingServiceID); err != nil {
			continue
		}

		mapping := ImportServiceMapping{
			ID:        s.ID,
			SessionID: s.SessionID,
			Name:      s.Name,
			Ports:     s.Ports,
			Protocol:  s.Protocol,
			Status:    s.Status,
		}
		if s.ExistingServiceID.Valid {
			id := s.ExistingServiceID.Int64
			mapping.ExistingServiceID = &id
			var name string
			if err := h.DB.QueryRowContext(r.Context(), "SELECT name FROM services WHERE id = ?", id).Scan(&name); err == nil {
				mapping.ExistingServiceName = name
			}
		}

		services = append(services, mapping)
	}

	if services == nil {
		services = []ImportServiceMapping{}
	}
	common.RespondJSON(w, http.StatusOK, services)
}

// GetSkippedRules returns all skipped rules for an import session with raw iptables content.
func (h *Handler) GetSkippedRules(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	rows, err := h.DB.QueryContext(r.Context(),
		"SELECT id, chain, rule_order, raw_rule, skip_reason FROM import_rules WHERE session_id = ? AND status = 'skipped' ORDER BY CASE chain WHEN 'INPUT' THEN 1 WHEN 'OUTPUT' THEN 2 WHEN 'DOCKER-USER' THEN 3 END, rule_order",
		sessionID)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}
	defer func() { _ = rows.Close() }()

	type SkippedRule struct {
		ID         int64  `json:"id"`
		Chain      string `json:"chain"`
		RuleOrder  int    `json:"rule_order"`
		RawRule    string `json:"raw_rule"`
		SkipReason string `json:"skip_reason"`
	}

	var skipped []SkippedRule
	for rows.Next() {
		var s SkippedRule
		if err := rows.Scan(&s.ID, &s.Chain, &s.RuleOrder, &s.RawRule, &s.SkipReason); err != nil {
			continue
		}
		skipped = append(skipped, s)
	}

	if skipped == nil {
		skipped = []SkippedRule{}
	}
	common.RespondJSON(w, http.StatusOK, skipped)
}

// parseUpdateIDs extracts session ID and entity ID from URL path parameters.
func (h *Handler) parseUpdateIDs(w http.ResponseWriter, r *http.Request, entityIDParam string) (sessionID int64, entityID int64, ok bool) {
	var err error
	sessionID, err = h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return 0, 0, false
	}
	entityID, err = strconv.ParseInt(mux.Vars(r)[entityIDParam], 10, 64)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ID"})
		return 0, 0, false
	}
	return sessionID, entityID, true
}

// executeUpdate builds and executes a dynamic UPDATE query.
func (h *Handler) executeUpdate(w http.ResponseWriter, r *http.Request, tableName string, updates []string, args []interface{}, sessionID int64, entityID int64) error {
	if len(updates) == 0 {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "no fields to update"})
		return fmt.Errorf("no fields to update")
	}
	args = append(args, sessionID, entityID)
	query := fmt.Sprintf("UPDATE %s SET %s WHERE session_id = ? AND id = ?", tableName, strings.Join(updates, ", "))
	_, err := h.DB.ExecContext(r.Context(), query, args...)
	if err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return err
	}
	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	return nil
}

// UpdateRule updates a rule's mapping or approval status.
func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	sessionID, ruleID, ok := h.parseUpdateIDs(w, r, "rule_id")
	if !ok {
		return
	}

	var input struct {
		Status     *string `json:"status"`
		PolicyName *string `json:"policy_name"`
		Enabled    *bool   `json:"enabled"`
		SourceIP   *string `json:"source_ip"`
		TargetIP   *string `json:"target_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	validRuleStatuses := map[string]bool{"pending": true, "resolved": true, "skipped": true, "approved": true, "rejected": true}
	var updates []string
	var args []interface{}
	if input.Status != nil {
		if !validRuleStatuses[*input.Status] {
			common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status value"})
			return
		}
		updates = append(updates, "status = ?")
		args = append(args, *input.Status)
	}
	if input.PolicyName != nil {
		updates = append(updates, "policy_name = ?")
		args = append(args, *input.PolicyName)
	}
	if input.Enabled != nil {
		enabled := 0
		if *input.Enabled {
			enabled = 1
		}
		updates = append(updates, "enabled = ?")
		args = append(args, enabled)
	}
	if input.SourceIP != nil {
		updates = append(updates, "source_ip = ?")
		args = append(args, *input.SourceIP)
	}
	if input.TargetIP != nil {
		updates = append(updates, "target_ip = ?")
		args = append(args, *input.TargetIP)
	}

	if err := h.executeUpdate(w, r, "import_rules", updates, args, sessionID, ruleID); err != nil {
		runiclog.Warn("UpdateRule failed", "error", err)
	}
}

// UpdateGroup updates a group mapping.
func (h *Handler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	sessionID, groupID, ok := h.parseUpdateIDs(w, r, "group_id")
	if !ok {
		return
	}

	var input struct {
		Status          *string `json:"status"`
		ExistingGroupID *int64  `json:"existing_group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	var updates []string
	var args []interface{}
	if input.Status != nil {
		if !validMappingStatuses[*input.Status] {
			common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status value"})
			return
		}
		updates = append(updates, "status = ?")
		args = append(args, *input.Status)
	}
	if input.ExistingGroupID != nil {
		updates = append(updates, "existing_group_id = ?")
		args = append(args, *input.ExistingGroupID)
	}

	if err := h.executeUpdate(w, r, "import_group_mappings", updates, args, sessionID, groupID); err != nil {
		runiclog.Warn("UpdateGroup failed", "error", err)
	}
}

// UpdatePeer updates a peer mapping.
func (h *Handler) UpdatePeer(w http.ResponseWriter, r *http.Request) {
	sessionID, peerID, ok := h.parseUpdateIDs(w, r, "peer_id")
	if !ok {
		return
	}

	var input struct {
		Status         *string `json:"status"`
		ExistingPeerID *int64  `json:"existing_peer_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	var updates []string
	var args []interface{}
	if input.Status != nil {
		if !validMappingStatuses[*input.Status] {
			common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status value"})
			return
		}
		updates = append(updates, "status = ?")
		args = append(args, *input.Status)
	}
	if input.ExistingPeerID != nil {
		updates = append(updates, "existing_peer_id = ?")
		args = append(args, *input.ExistingPeerID)
	}

	if err := h.executeUpdate(w, r, "import_peer_mappings", updates, args, sessionID, peerID); err != nil {
		runiclog.Warn("UpdatePeer failed", "error", err)
	}
}

// UpdateService updates a service mapping.
func (h *Handler) UpdateService(w http.ResponseWriter, r *http.Request) {
	sessionID, serviceID, ok := h.parseUpdateIDs(w, r, "service_id")
	if !ok {
		return
	}

	var input struct {
		Status            *string `json:"status"`
		ExistingServiceID *int64  `json:"existing_service_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	validMappingStatuses := map[string]bool{"pending": true, "mapped": true, "approved": true, "rejected": true}
	var updates []string
	var args []interface{}
	if input.Status != nil {
		if !validMappingStatuses[*input.Status] {
			common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status value"})
			return
		}
		updates = append(updates, "status = ?")
		args = append(args, *input.Status)
	}
	if input.ExistingServiceID != nil {
		updates = append(updates, "existing_service_id = ?")
		args = append(args, *input.ExistingServiceID)
	}

	if err := h.executeUpdate(w, r, "import_service_mappings", updates, args, sessionID, serviceID); err != nil {
		runiclog.Warn("UpdateService failed", "error", err)
	}
}

// ApplySession applies all approved rules from an import session.
func (h *Handler) ApplySession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	// Update session status to reviewing first
	if err := importer.UpdateSessionStatus(r.Context(), h.DB, sessionID, "reviewing"); err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "database error"})
		return
	}

	// Count approved rules
	var approvedCount int
	_ = h.DB.QueryRowContext(r.Context(), "SELECT COUNT(*) FROM import_rules WHERE session_id = ? AND status = 'approved'", sessionID).Scan(&approvedCount)
	if approvedCount == 0 {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "no approved rules to apply"})
		return
	}

	result, err := importer.ApplySession(r.Context(), h.DB, sessionID, h.ChangeWorker)
	if err != nil {
		runiclog.Error("Failed to apply import session", "error", err, "session_id", sessionID)
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to apply import session"})
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "applied",
		"policies_created": result.PoliciesCreated,
		"groups_created":   result.GroupsCreated,
		"peers_created":    result.PeersCreated,
		"services_created": result.ServicesCreated,
	})
}

// CancelSession cancels and cleans up an import session.
func (h *Handler) CancelSession(w http.ResponseWriter, r *http.Request) {
	sessionID, err := h.getSessionID(r)
	if err != nil {
		common.RespondJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session ID"})
		return
	}

	if err := importer.DeleteSession(r.Context(), h.DB, sessionID); err != nil {
		common.RespondJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to cancel session"})
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"status": "canceled"})
}

// Helper functions

func (h *Handler) getSessionID(r *http.Request) (int64, error) {
	return strconv.ParseInt(mux.Vars(r)["id"], 10, 64)
}

// resolveEntityName looks up the display name for a source or target.
// When matchedIP is set (non-primary IP match via peer_ips), the display name
// includes the specific IP as a suffix, e.g. "graylog (10.20.10.20)".
func (h *Handler) resolveEntityName(ctx context.Context, entityType sql.NullString, entityID sql.NullInt64, stagingID sql.NullInt64, sessionID int64, matchedIP sql.NullString) string {
	if !entityType.Valid || entityType.String == "" {
		return ""
	}

	// If real entity ID exists, look it up
	if entityID.Valid && entityID.Int64 != 0 {
		switch entityType.String {
		case "peer":
			var name string
			if err := h.DB.QueryRowContext(ctx, "SELECT hostname FROM peers WHERE id = ?", entityID.Int64).Scan(&name); err == nil {
				if matchedIP.Valid && matchedIP.String != "" {
					return fmt.Sprintf("%s (%s)", name, matchedIP.String)
				}
				return name
			}
		case "group":
			var name string
			if err := h.DB.QueryRowContext(ctx, "SELECT name FROM groups WHERE id = ?", entityID.Int64).Scan(&name); err == nil {
				return name
			}
		case "special":
			var name string
			if err := h.DB.QueryRowContext(ctx, "SELECT display_name FROM special_targets WHERE id = ?", entityID.Int64).Scan(&name); err == nil {
				return name
			}
		}
	}

	// If staging ID exists, look it up
	if stagingID.Valid && stagingID.Int64 != 0 {
		switch entityType.String {
		case "peer":
			var name string
			if err := h.DB.QueryRowContext(ctx, "SELECT hostname FROM import_peer_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
				if matchedIP.Valid && matchedIP.String != "" {
					return fmt.Sprintf("%s (%s)", name, matchedIP.String)
				}
				return name
			}
			// Fall back to IP
			var ip string
			if err := h.DB.QueryRowContext(ctx, "SELECT ip_address FROM import_peer_mappings WHERE id = ?", stagingID.Int64).Scan(&ip); err == nil {
				return ip
			}
		case "group":
			var name string
			if err := h.DB.QueryRowContext(ctx, "SELECT group_name FROM import_group_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
				return name
			}
		}
	}

	return ""
}

// resolveServiceName looks up the display name for a service.
func (h *Handler) resolveServiceName(ctx context.Context, serviceID sql.NullInt64, stagingID sql.NullInt64, sessionID int64) string {
	if serviceID.Valid && serviceID.Int64 != 0 {
		var name string
		if err := h.DB.QueryRowContext(ctx, "SELECT name FROM services WHERE id = ?", serviceID.Int64).Scan(&name); err == nil {
			return name
		}
	}
	if stagingID.Valid && stagingID.Int64 != 0 {
		var name string
		if err := h.DB.QueryRowContext(ctx, "SELECT name FROM import_service_mappings WHERE id = ?", stagingID.Int64).Scan(&name); err == nil {
			return name
		}
	}
	return ""
}
