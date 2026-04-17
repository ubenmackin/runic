// Package alerts provides alert condition evaluation functionality.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
)

// ConditionEvaluator evaluates alert conditions against system state.
// It implements the Evaluator interface defined in scheduler.go.
type ConditionEvaluator struct {
	database db.Querier
}

// NewConditionEvaluator creates a new ConditionEvaluator with the given database connection.
func NewConditionEvaluator(database db.Querier) *ConditionEvaluator {
	return &ConditionEvaluator{
		database: database,
	}
}

// EvaluateRule evaluates a single alert rule and returns true if the condition is met.
// This implements the Evaluator interface.
// Returns (triggered, event, error) where triggered indicates if the alert should fire.
func (e *ConditionEvaluator) EvaluateRule(ctx context.Context, rule *AlertRule) (bool, *AlertEvent, error) {
	if !rule.Enabled {
		return false, nil, nil
	}

	var event *AlertEvent
	var err error

	switch rule.AlertType {
	case AlertTypePeerOffline:
		event, err = e.evaluatePeerOffline(ctx, rule)
	case AlertTypeBundleFailed:
		event, err = e.evaluateBundleFailed(ctx, rule)
	case AlertTypeBlockedSpike:
		event, err = e.evaluateBlockedSpike(ctx, rule)
	case AlertTypePeerOnline:
		event, err = e.evaluatePeerOnline(ctx, rule)
	case AlertTypeNewPeer:
		event, err = e.evaluateNewPeer(ctx, rule)
	default:
		return false, nil, fmt.Errorf("unknown alert type: %s", rule.AlertType)
	}

	if err != nil {
		return false, nil, err
	}

	return event != nil, event, nil
}

// evaluatePeerOffline evaluates the peer_offline alert type.
// Threshold is the number of minutes a peer must be offline.
func (e *ConditionEvaluator) evaluatePeerOffline(ctx context.Context, rule *AlertRule) (*AlertEvent, error) {
	if rule.PeerID != nil {
		return e.checkPeerOfflineByID(ctx, rule, *rule.PeerID)
	}

	rows, err := e.database.QueryContext(ctx, `
		SELECT id, hostname, status, last_heartbeat
		FROM peers
		WHERE status = 'offline'
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query offline peers: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	for rows.Next() {
		var peerID int
		var hostname string
		var status string
		var lastHeartbeat sql.NullTime

		if err := rows.Scan(&peerID, &hostname, &status, &lastHeartbeat); err != nil {
			return nil, fmt.Errorf("failed to scan peer row: %w", err)
		}

		var duration time.Duration
		if lastHeartbeat.Valid {
			duration = time.Since(lastHeartbeat.Time)
		} else {
			// If no heartbeat, peer has never been online - use created_at
			var createdAt time.Time
			err := e.database.QueryRowContext(ctx, `SELECT created_at FROM peers WHERE id = ?`, peerID).Scan(&createdAt)
			if err != nil {
				duration = 24 * time.Hour // Default to 24 hours if we can't determine
			} else {
				duration = time.Since(createdAt)
			}
		}

		threshold := time.Duration(rule.ThresholdValue) * time.Minute
		if duration >= threshold {
			return &AlertEvent{
				Type:      AlertTypePeerOffline,
				PeerID:    peerID,
				PeerName:  hostname,
				Value:     int(duration.Minutes()),
				Timestamp: time.Now(),
				Severity:  rule.AlertType.DefaultSeverity(),
				Subject:   fmt.Sprintf("Peer %s is offline", hostname),
				Message:   fmt.Sprintf("Peer %s has been offline for %v minutes (threshold: %d minutes)", hostname, int(duration.Minutes()), rule.ThresholdValue),
				Metadata: map[string]interface{}{
					"offline_minutes":   int(duration.Minutes()),
					"threshold_minutes": rule.ThresholdValue,
					"last_heartbeat":    lastHeartbeat.Time.Format(time.RFC3339),
				},
			}, nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating offline peers: %w", err)
	}

	return nil, nil
}

// checkPeerOfflineByID checks if a specific peer is offline.
func (e *ConditionEvaluator) checkPeerOfflineByID(ctx context.Context, rule *AlertRule, peerID int) (*AlertEvent, error) {
	var hostname string
	var status string
	var lastHeartbeat sql.NullTime

	err := e.database.QueryRowContext(ctx, `
		SELECT hostname, status, last_heartbeat FROM peers WHERE id = ?
	`, peerID).Scan(&hostname, &status, &lastHeartbeat)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to query peer %d: %w", peerID, err)
	}

	if status != "offline" {
		return nil, nil
	}

	var duration time.Duration
	if lastHeartbeat.Valid {
		duration = time.Since(lastHeartbeat.Time)
	} else {
		duration = 24 * time.Hour
	}

	threshold := time.Duration(rule.ThresholdValue) * time.Minute
	if duration < threshold {
		return nil, nil
	}

	return &AlertEvent{
		Type:      AlertTypePeerOffline,
		PeerID:    peerID,
		PeerName:  hostname,
		Value:     int(duration.Minutes()),
		Timestamp: time.Now(),
		Severity:  rule.AlertType.DefaultSeverity(),
		Subject:   fmt.Sprintf("Peer %s is offline", hostname),
		Message:   fmt.Sprintf("Peer %s has been offline for %v minutes (threshold: %d minutes)", hostname, int(duration.Minutes()), rule.ThresholdValue),
		Metadata: map[string]interface{}{
			"offline_minutes":   int(duration.Minutes()),
			"threshold_minutes": rule.ThresholdValue,
		},
	}, nil
}

// evaluateBundleFailed evaluates the bundle_failed alert type.
// Threshold is the number of consecutive bundle generation failures.
func (e *ConditionEvaluator) evaluateBundleFailed(ctx context.Context, rule *AlertRule) (*AlertEvent, error) {
	if rule.PeerID != nil {
		return e.checkBundleFailedByID(ctx, rule, *rule.PeerID)
	}

	window := time.Duration(rule.ThresholdWindowMinutes) * time.Minute
	cutoff := time.Now().Add(-window)

	rows, err := e.database.QueryContext(ctx, `
		SELECT DISTINCT pjp.peer_id, p.hostname, pjp.error_message
		FROM push_job_peers pjp
		JOIN push_jobs pj ON pjp.job_id = pj.id
		JOIN peers p ON pjp.peer_id = p.id
		WHERE pjp.status = 'failed'
		AND pj.created_at >= ?
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query bundle failures: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	for rows.Next() {
		var peerID int
		var hostname string
		var errorMsg sql.NullString

		if err := rows.Scan(&peerID, &hostname, &errorMsg); err != nil {
			return nil, fmt.Errorf("failed to scan bundle failure row: %w", err)
		}

		failCount, err := e.countConsecutiveFailures(ctx, peerID, window)
		if err != nil {
			return nil, err
		}

		if failCount >= rule.ThresholdValue {
			errMsg := ""
			if errorMsg.Valid {
				errMsg = errorMsg.String
			}
			return &AlertEvent{
				Type:      AlertTypeBundleFailed,
				PeerID:    peerID,
				PeerName:  hostname,
				Value:     failCount,
				Timestamp: time.Now(),
				Severity:  rule.AlertType.DefaultSeverity(),
				Subject:   fmt.Sprintf("Bundle generation failed for peer %s", hostname),
				Message:   fmt.Sprintf("Peer %s has had %d consecutive bundle failures (threshold: %d)", hostname, failCount, rule.ThresholdValue),
				Metadata: map[string]interface{}{
					"failure_count":  failCount,
					"threshold":      rule.ThresholdValue,
					"window_minutes": rule.ThresholdWindowMinutes,
					"last_error":     errMsg,
				},
			}, nil
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bundle failures: %w", err)
	}

	return nil, nil
}

// checkBundleFailedByID checks if a specific peer has bundle failures.
func (e *ConditionEvaluator) checkBundleFailedByID(ctx context.Context, rule *AlertRule, peerID int) (*AlertEvent, error) {
	window := time.Duration(rule.ThresholdWindowMinutes) * time.Minute
	isFailed, err := e.CheckBundleFailed(ctx, strconv.Itoa(peerID))
	if err != nil {
		return nil, err
	}

	if !isFailed {
		return nil, nil
	}

	failCount, err := e.countConsecutiveFailures(ctx, peerID, window)
	if err != nil {
		return nil, err
	}

	if failCount < rule.ThresholdValue {
		return nil, nil
	}

	var hostname string
	err = e.database.QueryRowContext(ctx, `SELECT hostname FROM peers WHERE id = ?`, peerID).Scan(&hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer hostname: %w", err)
	}

	return &AlertEvent{
		Type:      AlertTypeBundleFailed,
		PeerID:    peerID,
		PeerName:  hostname,
		Value:     failCount,
		Timestamp: time.Now(),
		Severity:  rule.AlertType.DefaultSeverity(),
		Subject:   fmt.Sprintf("Bundle generation failed for peer %s", hostname),
		Message:   fmt.Sprintf("Peer %s has had %d consecutive bundle failures (threshold: %d)", hostname, failCount, rule.ThresholdValue),
		Metadata: map[string]interface{}{
			"failure_count":  failCount,
			"threshold":      rule.ThresholdValue,
			"window_minutes": rule.ThresholdWindowMinutes,
		},
	}, nil
}

// countConsecutiveFailures counts consecutive bundle failures for a peer.
func (e *ConditionEvaluator) countConsecutiveFailures(ctx context.Context, peerID int, window time.Duration) (int, error) {
	cutoff := time.Now().Add(-window)

	var count int
	err := e.database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM push_job_peers pjp
		JOIN push_jobs pj ON pjp.job_id = pj.id
		WHERE pjp.peer_id = ?
		AND pjp.status = 'failed'
		AND pj.created_at >= ?
	`, peerID, cutoff).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count failures for peer %d: %w", peerID, err)
	}

	return count, nil
}

// evaluateBlockedSpike evaluates the blocked_spike alert type.
// Threshold is the percentage increase in blocked traffic.
func (e *ConditionEvaluator) evaluateBlockedSpike(ctx context.Context, rule *AlertRule) (*AlertEvent, error) {
	if rule.PeerID != nil {
		return e.checkBlockedSpikeByID(ctx, rule, *rule.PeerID)
	}

	window := time.Duration(rule.ThresholdWindowMinutes) * time.Minute
	cutoff := time.Now().Add(-window)

	rows, err := e.database.QueryContext(ctx, `
		SELECT DISTINCT peer_id
		FROM firewall_logs
		WHERE (action = 'DROP' OR action = 'LOG_DROP')
		AND timestamp >= ?
	`, cutoff)
	if err != nil {
		return nil, fmt.Errorf("failed to query peers with blocked traffic: %w", err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			log.Error("failed to close rows", "error", cerr)
		}
	}()

	var peerIDs []int
	for rows.Next() {
		var peerID int
		if err := rows.Scan(&peerID); err != nil {
			return nil, fmt.Errorf("failed to scan peer_id: %w", err)
		}
		peerIDs = append(peerIDs, peerID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating peers: %w", err)
	}

	for _, peerID := range peerIDs {
		event, err := e.checkBlockedSpikeByID(ctx, rule, peerID)
		if err != nil {
			return nil, err
		}
		if event != nil {
			return event, nil
		}
	}

	return nil, nil
}

// checkBlockedSpikeByID checks if a specific peer has a blocked traffic spike.
func (e *ConditionEvaluator) checkBlockedSpikeByID(ctx context.Context, rule *AlertRule, peerID int) (*AlertEvent, error) {
	isSpike, percentage, err := e.CheckBlockedSpike(ctx, strconv.Itoa(peerID))
	if err != nil {
		return nil, err
	}

	if !isSpike || percentage < rule.ThresholdValue {
		return nil, nil
	}

	var hostname string
	err = e.database.QueryRowContext(ctx, `SELECT hostname FROM peers WHERE id = ?`, peerID).Scan(&hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to get peer hostname: %w", err)
	}

	return &AlertEvent{
		Type:      AlertTypeBlockedSpike,
		PeerID:    peerID,
		PeerName:  hostname,
		Value:     percentage,
		Timestamp: time.Now(),
		Severity:  rule.AlertType.DefaultSeverity(),
		Subject:   fmt.Sprintf("Blocked traffic spike detected on peer %s", hostname),
		Message:   fmt.Sprintf("Peer %s has a %d%% increase in blocked traffic (threshold: %d%%)", hostname, percentage, rule.ThresholdValue),
		Metadata: map[string]interface{}{
			"percentage_increase": percentage,
			"threshold":           rule.ThresholdValue,
			"window_minutes":      rule.ThresholdWindowMinutes,
		},
	}, nil
}

// evaluatePeerOnline evaluates the peer_online alert type.
// This is triggered when a peer comes back online after being offline.
func (e *ConditionEvaluator) evaluatePeerOnline(ctx context.Context, rule *AlertRule) (*AlertEvent, error) {
	// This alert type is typically triggered by a webhook/event, not polling
	// For now, return nil as this requires event-driven evaluation
	return nil, nil
}

// evaluateNewPeer evaluates the new_peer alert type.
// This is triggered when a new peer is registered.
func (e *ConditionEvaluator) evaluateNewPeer(ctx context.Context, rule *AlertRule) (*AlertEvent, error) {
	// This alert type is typically triggered by a webhook/event, not polling
	// For now, return nil as this requires event-driven evaluation
	return nil, nil
}

// CheckPeerOffline checks if a peer is offline and returns the duration.
// Returns true if the peer is offline, along with the duration offline.
func (e *ConditionEvaluator) CheckPeerOffline(ctx context.Context, peerID string) (bool, time.Duration) {

	var status string
	var lastHeartbeat sql.NullTime

	err := e.database.QueryRowContext(ctx, `
		SELECT status, last_heartbeat FROM peers WHERE id = ?
	`, peerID).Scan(&status, &lastHeartbeat)

	if err != nil {
		if err == sql.ErrNoRows {
			return false, 0
		}
		return false, 0
	}

	if status != "offline" {
		return false, 0
	}

	var duration time.Duration
	if lastHeartbeat.Valid {
		duration = time.Since(lastHeartbeat.Time)
	} else {
		duration = 24 * time.Hour // Default if no heartbeat
	}

	return true, duration
}

// CheckBundleFailed checks if bundle generation has failed for a peer.
// Returns true if there are recent bundle failures.
func (e *ConditionEvaluator) CheckBundleFailed(ctx context.Context, peerID string) (bool, error) {

	cutoff := time.Now().Add(-1 * time.Hour)

	var failCount int
	err := e.database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM push_job_peers pjp
		JOIN push_jobs pj ON pjp.job_id = pj.id
		WHERE pjp.peer_id = ?
		AND pjp.status = 'failed'
		AND pj.created_at >= ?
	`, peerID, cutoff).Scan(&failCount)

	if err != nil {
		return false, fmt.Errorf("failed to check bundle failures: %w", err)
	}

	return failCount > 0, nil
}

// CheckBlockedSpike checks for a spike in blocked traffic for a peer.
// Returns true if there's a spike, along with the percentage increase.
func (e *ConditionEvaluator) CheckBlockedSpike(ctx context.Context, peerID string) (bool, int, error) {

	now := time.Now()
	recentStart := now.Add(-5 * time.Minute)
	previousStart := now.Add(-10 * time.Minute)
	previousEnd := now.Add(-5 * time.Minute)

	var recentCount int
	err := e.database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM firewall_logs
		WHERE peer_id = ?
		AND (action = 'DROP' OR action = 'LOG_DROP')
		AND timestamp >= ?
	`, peerID, recentStart).Scan(&recentCount)

	if err != nil {
		return false, 0, fmt.Errorf("failed to count recent blocked traffic: %w", err)
	}

	var previousCount int
	err = e.database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM firewall_logs
		WHERE peer_id = ?
		AND (action = 'DROP' OR action = 'LOG_DROP')
		AND timestamp >= ? AND timestamp < ?
	`, peerID, previousStart, previousEnd).Scan(&previousCount)

	if err != nil {
		return false, 0, fmt.Errorf("failed to count previous blocked traffic: %w", err)
	}

	if previousCount == 0 {
		// If there was no previous traffic, any current traffic is a spike
		if recentCount > 10 {
			return true, 100, nil
		}
		return false, 0, nil
	}

	percentageIncrease := ((recentCount - previousCount) * 100) / previousCount
	if percentageIncrease < 0 {
		percentageIncrease = 0
	}

	// Consider it a spike if there's a meaningful increase (at least 50%)
	return percentageIncrease >= 50, percentageIncrease, nil
}
