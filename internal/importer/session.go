// Package importer provides logic for parsing iptables backups and applying import sessions.
package importer

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/iptparse"
)

// ImportSession represents an import session from the database.
type ImportSession struct {
	ID              int64
	PeerID          int64
	Status          string
	RawBackup       string
	RawIpsets       string
	ChainFilter     string
	TotalRulesFound int
	ImportableRules int
	SkippedRules    int
	CreatedAt       string
	UpdatedAt       string
}

// CreateSession creates a new import session with status 'pending'.
func CreateSession(ctx context.Context, database *sql.DB, peerID int64, rawBackup, rawIpsets string) (*ImportSession, error) {
	// Check if peer already has an active import session
	var existingID int64
	err := database.QueryRowContext(ctx,
		"SELECT id FROM import_sessions WHERE peer_id = ? AND status IN ('pending','parsed','reviewing')",
		peerID,
	).Scan(&existingID)
	if err == nil {
		return nil, fmt.Errorf("peer already has active import session %d", existingID)
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("check existing session: %w", err)
	}

	result, err := database.ExecContext(ctx,
		"INSERT INTO import_sessions (peer_id, status, raw_backup, raw_ipsets) VALUES (?, 'pending', ?, ?)",
		peerID, rawBackup, rawIpsets,
	)
	if err != nil {
		return nil, fmt.Errorf("insert session: %w", err)
	}

	sessionID, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("get last insert id: %w", err)
	}

	return &ImportSession{
		ID:        sessionID,
		PeerID:    peerID,
		Status:    "pending",
		RawBackup: rawBackup,
		RawIpsets: rawIpsets,
	}, nil
}

// GetSession retrieves an import session by ID.
func GetSession(ctx context.Context, database db.Querier, sessionID int64) (*ImportSession, error) {
	s := &ImportSession{}
	err := database.QueryRowContext(ctx,
		"SELECT id, peer_id, status, raw_backup, raw_ipsets, chain_filter, total_rules_found, importable_rules, skipped_rules, created_at, updated_at FROM import_sessions WHERE id = ?",
		sessionID,
	).Scan(&s.ID, &s.PeerID, &s.Status, &s.RawBackup, &s.RawIpsets, &s.ChainFilter, &s.TotalRulesFound, &s.ImportableRules, &s.SkippedRules, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}
	return s, nil
}

// GetSessionByPeer retrieves an active import session for a peer.
func GetSessionByPeer(ctx context.Context, database db.Querier, peerID int64) (*ImportSession, error) {
	s := &ImportSession{}
	err := database.QueryRowContext(ctx,
		"SELECT id, peer_id, status, raw_backup, raw_ipsets, chain_filter, total_rules_found, importable_rules, skipped_rules, created_at, updated_at FROM import_sessions WHERE peer_id = ? AND status IN ('pending','parsed','reviewing')",
		peerID,
	).Scan(&s.ID, &s.PeerID, &s.Status, &s.RawBackup, &s.RawIpsets, &s.ChainFilter, &s.TotalRulesFound, &s.ImportableRules, &s.SkippedRules, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// ParseSession runs the iptparse parser on the session's raw backup, creates import_rules entries, then runs the resolver.
// The entire operation runs within a database transaction for atomicity.
func ParseSession(ctx context.Context, database *sql.DB, sessionID int64) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rErr := tx.Rollback(); rErr != nil {
				log.Warn("Rollback failed", "error", rErr)
			}
		}
	}()

	session, err := GetSession(ctx, tx, sessionID)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}
	if session.Status != "pending" {
		return fmt.Errorf("session is not in pending state (current: %s)", session.Status)
	}

	// Parse chains from the raw backup
	chains := []string{"INPUT", "OUTPUT", "DOCKER-USER"}
	parsedChains, err := iptparse.Parse(session.RawBackup, chains)
	if err != nil {
		return fmt.Errorf("parse iptables: %w", err)
	}

	// Count importable vs skipped
	totalRules := 0
	importableRules := 0
	skippedRules := 0

	// Insert parsed rules into import_rules
	for i := range parsedChains {
		for j := range parsedChains[i].Rules {
			rule := &parsedChains[i].Rules[j]
			totalRules++

			status := "pending"
			skipReason := ""
			switch {
			case rule.IsRunicStandard:
				status = "skipped"
				skipReason = rule.SkipReason
				skippedRules++
			case !rule.IsClean:
				status = "skipped"
				skipReason = rule.SkipReason
				skippedRules++
			default:
				importableRules++
			}

			// Determine action
			action := rule.Target
			if action != "ACCEPT" && action != "DROP" {
				action = ""
			}

			// Determine target_scope
			targetScope := "both"
			if rule.Chain == "DOCKER-USER" {
				targetScope = "docker"
			}

			// Determine direction
			direction := "both"
			if rule.Chain == "INPUT" && rule.DestPort != "" {
				direction = "forward"
			} else if rule.Chain == "OUTPUT" && rule.DestPort != "" {
				direction = "backward"
			}

			// Assign priority based on order (100, 200, 300...)
			priority := rule.Order * 100

			// Auto-generate policy name
			policyName := generatePolicyName(rule)

			_, err := tx.ExecContext(ctx,
				"INSERT INTO import_rules (session_id, chain, rule_order, raw_rule, status, skip_reason, action, priority, direction, target_scope, policy_name, enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
				sessionID, rule.Chain, rule.Order, rule.Raw, status, skipReason, action, priority, direction, targetScope, policyName,
			)
			if err != nil {
				return fmt.Errorf("insert rule: %w", err)
			}
		}
	}

	// Update session stats and status
	_, err = tx.ExecContext(ctx,
		"UPDATE import_sessions SET status = 'parsed', total_rules_found = ?, importable_rules = ?, skipped_rules = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		totalRules, importableRules, skippedRules, sessionID,
	)
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}

	// Commit the transaction before running resolver (which does its own transaction)
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	committed = true

	// Now run the resolver to map IPs/ports/ipsets to Runic entities
	if err := resolveRules(ctx, database, sessionID, session.RawIpsets); err != nil {
		log.Warn("Resolver completed with errors", "session_id", sessionID, "error", err)
		// Don't fail the whole parse — partial resolution is OK
	}

	return nil
}

// DeleteSession cascading deletes an import session and all its staging data.
func DeleteSession(ctx context.Context, database *sql.DB, sessionID int64) error {
	_, err := database.ExecContext(ctx, "DELETE FROM import_sessions WHERE id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// CleanupStaleSessions removes sessions older than maxAge.
func CleanupStaleSessions(ctx context.Context, database *sql.DB, maxAge time.Duration) error {
	cutoff := time.Now().Add(-maxAge).Format("2006-01-02 15:04:05")
	result, err := database.ExecContext(ctx,
		"DELETE FROM import_sessions WHERE status IN ('pending','parsed','reviewing') AND created_at < ?",
		cutoff,
	)
	if err != nil {
		return fmt.Errorf("cleanup stale sessions: %w", err)
	}
	rows, _ := result.RowsAffected()
	log.Info("Cleaned up stale import sessions", "removed", rows)
	return nil
}

// UpdateSessionStatus updates the session's status.
func UpdateSessionStatus(ctx context.Context, database db.Querier, sessionID int64, status string) error {
	_, err := database.ExecContext(ctx,
		"UPDATE import_sessions SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
		status, sessionID,
	)
	return err
}

// generatePolicyName creates an auto-generated policy name from a parsed rule.
func generatePolicyName(rule *iptparse.ParsedRule) string {
	action := rule.Target
	proto := rule.Protocol
	if proto == "" {
		proto = "all"
	}
	port := rule.DestPort
	if port == "" {
		port = "any"
	}
	return fmt.Sprintf("Imported-%s-%s-%s-%s", rule.Chain, proto, port, action)
}
