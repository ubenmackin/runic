// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"runic/internal/common/log"
)

// SpikeDetector monitors firewall logs for blocked traffic spikes.
type SpikeDetector struct {
	database *sql.DB
	service  *Service
	logger   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	stopCh chan struct{}

	// Threshold config (can be updated)
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

// NewSpikeDetector creates a new spike detector.
func NewSpikeDetector(database *sql.DB, service *Service) *SpikeDetector {
	ctx, cancel := context.WithCancel(context.Background())
	return &SpikeDetector{
		database:        database,
		service:         service,
		logger:          log.L().With("component", "spike_detector"),
		ctx:             ctx,
		cancel:          cancel,
		stopCh:          make(chan struct{}),
		threshold:       100, // default threshold
		windowMinutes:   5,   // default window
		throttleMinutes: 15,  // default throttle
	}
}

// SetLogger sets a custom logger.
func (d *SpikeDetector) SetLogger(logger *slog.Logger) {
	d.logger = logger.With("component", "spike_detector")
}

// SetThresholds sets the threshold and window for spike detection.
func (d *SpikeDetector) SetThresholds(threshold, windowMinutes, throttleMinutes int) {
	d.threshold = threshold
	d.windowMinutes = windowMinutes
	d.throttleMinutes = throttleMinutes
}

// Start begins monitoring for blocked traffic spikes.
func (d *SpikeDetector) Start() {
	d.logger.Info("starting spike detector", "threshold", d.threshold, "window", d.windowMinutes)
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.run()
	}()
}

// Stop stops the spike detector.
func (d *SpikeDetector) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	d.logger.Info("spike detector stopped")
}

func (d *SpikeDetector) run() {
	// Load threshold from database
	d.loadThreshold()

	// Check every 1 minute
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
			// Reload threshold in case it changed
			d.loadThreshold()
		}
	}
}

func (d *SpikeDetector) loadThreshold() {
	ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
	defer cancel()

	var rule AlertRule
	err := d.database.QueryRowContext(ctx, `
		SELECT threshold_value, threshold_window_minutes, throttle_minutes
		FROM alert_rules
		WHERE alert_type = ? AND enabled = 1
		LIMIT 1
	`, AlertTypeBlockedSpike).Scan(&rule.ThresholdValue, &rule.ThresholdWindowMinutes, &rule.ThrottleMinutes)

	if err != nil {
		if err != sql.ErrNoRows {
			d.logger.Warn("failed to load spike threshold", "error", err)
		}
		return
	}

	d.threshold = rule.ThresholdValue
	d.windowMinutes = rule.ThresholdWindowMinutes
	d.throttleMinutes = rule.ThrottleMinutes
}

func (d *SpikeDetector) checkForSpike() {
	// Guard against nil database - the detector requires a valid database to function.
	// If database is nil, log a warning and return early rather than panicking.
	if d.database == nil {
		d.logger.Warn("spike detector has nil database, skipping check")
		return
	}

	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()

	// Count DROP events in the window
	var count int
	err := d.database.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp >= datetime('now', '-? minutes')
	`, d.windowMinutes).Scan(&count)

	if err != nil {
		d.logger.Error("failed to count blocked traffic", "error", err)
		return
	}

	d.logger.Debug("blocked traffic count", "count", count, "threshold", d.threshold)

	if count >= d.threshold {
		// Check throttle
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

	// Get top blocked IPs
	topIPs := d.getTopBlockedIPs(ctx)

	// Get affected peers
	affectedPeers := d.getAffectedPeers(ctx)

	// Extract IP addresses from topIPs
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

// topBlockedIP represents a blocked IP address with count.
type topBlockedIP struct {
	ip    string
	count int
}

func (d *SpikeDetector) getTopBlockedIPs(ctx context.Context) []topBlockedIP {
	rows, err := d.database.QueryContext(ctx, `
		SELECT source_ip, COUNT(*) as cnt
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp >= datetime('now', '-? minutes')
		GROUP BY source_ip
		ORDER BY cnt DESC
		LIMIT 5
	`, d.windowMinutes)
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

	// Sort by count descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
	})

	return results
}

func (d *SpikeDetector) getAffectedPeers(ctx context.Context) []string {
	rows, err := d.database.QueryContext(ctx, `
		SELECT DISTINCT p.hostname
		FROM firewall_logs fl
		JOIN peers p ON fl.peer_id = p.id
		WHERE fl.action = 'DROP' AND fl.timestamp >= datetime('now', '-? minutes')
		LIMIT 10
	`, d.windowMinutes)
	if err != nil {
		d.logger.Error("failed to get affected peers", "error", err)
		return nil
	}
	defer func() {
		if err := rows.Close(); err != nil {
			d.logger.Error("failed to close rows", "error", err)
		}
	}()

	var results []string
	for rows.Next() {
		var hostname string
		if err := rows.Scan(&hostname); err != nil {
			continue
		}
		results = append(results, hostname)
	}

	return results
}
