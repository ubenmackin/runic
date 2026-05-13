// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"runic/internal/common/log"
	"runic/internal/db"
)

type SpikeDetector struct {
	logsDB  db.Querier
	mainDB  db.Querier
	service *Service
	logger  *slog.Logger

	lookupHostname PeerHostnameLookup

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once

	threshold       int
	windowMinutes   int
	throttleMinutes int

	// lastAlert tracks when the last spike alert was sent.
	// NOTE: This is in-memory state and is not persisted across restarts.
	// After a restart, the throttle window resets, which may result in
	// an additional alert being sent before the configured throttle period
	// would normally expire. This is acceptable for spike detection since
	// the alert is informational and the spike condition is re-evaluated
	// on each check cycle.
	lastAlert time.Time
}

// NewSpikeDetector creates a new spike detector. logsDB is the separate logs database for firewall_logs queries.
// mainDB is the main database for alert_rules and peers queries. The lookupHostname parameter is required for
// resolving peer IDs to hostnames and must not be nil.
func NewSpikeDetector(logsDB, mainDB db.Querier, service *Service, lookupHostname PeerHostnameLookup) *SpikeDetector {
	ctx, cancel := context.WithCancel(context.Background())
	return &SpikeDetector{
		logsDB:          logsDB,
		mainDB:          mainDB,
		service:         service,
		logger:          log.L().With("component", "spike_detector"),
		lookupHostname:  lookupHostname,
		ctx:             ctx,
		cancel:          cancel,
		stopCh:          make(chan struct{}),
		threshold:       100,
		windowMinutes:   5,
		throttleMinutes: 15,
	}
}

// SetThresholds sets the spike detection thresholds. This is primarily intended for testing.
func (d *SpikeDetector) SetThresholds(threshold, windowMinutes, throttleMinutes int) {
	d.threshold = threshold
	d.windowMinutes = windowMinutes
	d.throttleMinutes = throttleMinutes
}

func (d *SpikeDetector) Start() {
	d.logger.Info("starting spike detector", "threshold", d.threshold, "window", d.windowMinutes)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.run()
	}()
}

func (d *SpikeDetector) Stop() {
	d.stopOnce.Do(func() {
		close(d.stopCh)
	})
	d.wg.Wait()
	d.logger.Info("spike detector stopped")
}

func (d *SpikeDetector) run() {
	select {
	case <-d.ctx.Done():
		return
	case <-d.stopCh:
		return
	default:
	}
	d.loadThreshold()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.checkForSpike()
			d.loadThreshold()
		}
	}
}

func (d *SpikeDetector) loadThreshold() {
	if d.mainDB == nil {
		return
	}

	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel()

	var rule AlertRule
	err := d.mainDB.QueryRowContext(ctx, `
		SELECT threshold_value, threshold_window_minutes, throttle_minutes
		FROM alert_rules
		WHERE alert_type = ? AND enabled = 1
		LIMIT 1
	`, AlertTypeBlockedSpike).Scan(&rule.ThresholdValue, &rule.ThresholdWindowMinutes, &rule.ThrottleMinutes)

	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			d.logger.Warn("failed to load spike threshold", "error", err)
		}
		return
	}

	d.threshold = rule.ThresholdValue
	d.windowMinutes = rule.ThresholdWindowMinutes
	d.throttleMinutes = rule.ThrottleMinutes
}

func (d *SpikeDetector) checkForSpike() {
	// Guard against nil database - the detector requires a valid logs database to function.
	// If logsDB is nil, log a warning and return early rather than panicking.
	if d.logsDB == nil {
		d.logger.Warn("spike detector has nil logs database, skipping check")
		return
	}

	// Skip global spike detection when per-peer blocked_spike alert rules exist,
	// because the ConditionEvaluator already handles per-peer spike detection and
	// sending both global and per-peer alerts for the same underlying traffic
	// would produce duplicate notifications.
	if d.mainDB != nil {
		var perPeerCount int
		peerCtx, peerCancel := context.WithTimeout(d.ctx, 5*time.Second)
		err := d.mainDB.QueryRowContext(peerCtx, `
			SELECT COUNT(*) FROM alert_rules
			WHERE alert_type = ? AND enabled = 1 AND peer_id IS NOT NULL
		`, AlertTypeBlockedSpike).Scan(&perPeerCount)
		peerCancel()
		if err == nil && perPeerCount > 0 {
			d.logger.Debug("skipping global spike check because per-peer blocked_spike rules exist")
			return
		}
	}

	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()

	cutoff := time.Now().Add(-time.Duration(d.windowMinutes) * time.Minute)

	var count int
	err := d.logsDB.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM firewall_logs
		WHERE `+DropActionFilter+` AND timestamp >= ?
	`, cutoff).Scan(&count)

	if err != nil {
		d.logger.Error("failed to count blocked traffic", "error", err)
		return
	}

	d.logger.Debug("blocked traffic count", "count", count, "threshold", d.threshold)

	if count >= d.threshold {
		if time.Since(d.lastAlert) < time.Duration(d.throttleMinutes)*time.Minute {
			d.logger.Debug("spike alert throttled", "last_alert", d.lastAlert)
			return
		}

		d.logger.Info("blocked traffic spike detected", "count", count, "threshold", d.threshold)
		d.triggerSpikeAlert(ctx, count)
	}
}

func (d *SpikeDetector) triggerSpikeAlert(ctx context.Context, count int) {
	if d.service == nil {
		return
	}

	topIPs := d.getTopBlockedIPs(ctx)
	affectedPeers := d.getAffectedPeers(ctx)

	var topIPList []string
	for _, ip := range topIPs {
		topIPList = append(topIPList, ip.ip)
	}

	d.lastAlert = time.Now()

	if err := d.service.TriggerAlert(ctx, &AlertEvent{
		Type:    AlertTypeBlockedSpike,
		PeerID:  0, // global alert
		Subject: "Blocked Traffic Spike Detected",
		Message: fmt.Sprintf("%d packets blocked in %d minutes (threshold: %d)", count, d.windowMinutes, d.threshold),
		Value:   count,
		Metadata: map[string]interface{}{
			"blocked_count":  count,
			"threshold":      d.threshold,
			"window_minutes": d.windowMinutes,
			"top_source_ips": topIPList,
			"affected_peers": affectedPeers,
		},
	}); err != nil {
		d.logger.Error("failed to trigger spike alert", "error", err)
	}

	d.logger.Info("spike alert triggered", "count", count)
}

type topBlockedIP struct {
	ip    string
	count int
}

func (d *SpikeDetector) getTopBlockedIPs(ctx context.Context) []topBlockedIP {
	cutoff := time.Now().Add(-time.Duration(d.windowMinutes) * time.Minute)

	rows, err := d.logsDB.QueryContext(ctx, `
		SELECT source_ip, COUNT(*) as cnt
		FROM firewall_logs
		WHERE `+DropActionFilter+` AND timestamp >= ?
		GROUP BY source_ip
		ORDER BY cnt DESC
		LIMIT 5
	`, cutoff)
	if err != nil {
		d.logger.Error("failed to get top blocked IPs", "error", err)
		return nil
	}
	defer func() {
		if err := rows.Close(); err != nil {
			d.logger.Error("failed to close rows", "error", err)
		}
	}()

	var results []topBlockedIP
	for rows.Next() {
		var ip string
		var cnt int
		if err := rows.Scan(&ip, &cnt); err != nil {
			continue
		}
		results = append(results, topBlockedIP{ip: ip, count: cnt})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
	})

	return results
}

func (d *SpikeDetector) getAffectedPeers(ctx context.Context) []string {
	cutoff := time.Now().Add(-time.Duration(d.windowMinutes) * time.Minute)

	// Step 1: Get distinct peer_ids from firewall_logs (logs DB)
	peerRows, err := d.logsDB.QueryContext(ctx, `
		SELECT DISTINCT peer_id
		FROM firewall_logs
		WHERE `+DropActionFilter+` AND timestamp >= ?
		LIMIT 10
	`, cutoff)
	if err != nil {
		d.logger.Error("failed to get affected peer IDs", "error", err)
		return nil
	}
	defer func() {
		if err := peerRows.Close(); err != nil {
			d.logger.Error("failed to close peer rows", "error", err)
		}
	}()

	var peerIDs []int
	for peerRows.Next() {
		var peerID int
		if err := peerRows.Scan(&peerID); err != nil {
			continue
		}
		peerIDs = append(peerIDs, peerID)
	}

	if len(peerIDs) == 0 {
		return nil
	}

	// Step 2: Get hostnames using the injected lookup
	var results []string
	for _, peerID := range peerIDs {
		hostname, err := d.lookupHostname(ctx, peerID)
		if err != nil {
			continue
		}
		results = append(results, hostname)
	}

	return results
}
