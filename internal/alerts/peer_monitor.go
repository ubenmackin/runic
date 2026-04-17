// Package alerts provides alert and notification functionality.
package alerts

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"runic/internal/common/log"
)

// PeerStatus represents the online/offline status of a peer.
type PeerStatus string

const (
	PeerStatusOnline  PeerStatus = "online"
	PeerStatusOffline PeerStatus = "offline"

	// DefaultGracePeriod is the default duration after startup during which
	// peer online alerts are suppressed to prevent false positives during server restart.
	DefaultGracePeriod = 5 * time.Minute
)

// peerInfo holds information about a peer.
type peerInfo struct {
	hostname      string
	ipAddress     string
	lastHeartbeat time.Time
}

// PeerMonitor monitors peer online/offline status and triggers alerts on state changes.
type PeerMonitor struct {
	database *sql.DB
	service  *Service
	logger   *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	stopCh chan struct{}

	peerStates       map[int]PeerStatus
	startTime        time.Time
	gracePeriod      time.Duration
	offlineAlertSent map[int]bool

	mu sync.RWMutex
}

// NewPeerMonitor creates a new peer monitor.
func NewPeerMonitor(database *sql.DB, service *Service) *PeerMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	return &PeerMonitor{
		database:         database,
		service:          service,
		logger:           log.L().With("component", "peer_monitor"),
		ctx:              ctx,
		cancel:           cancel,
		stopCh:           make(chan struct{}),
		peerStates:       make(map[int]PeerStatus),
		startTime:        time.Now(),
		gracePeriod:      DefaultGracePeriod,
		offlineAlertSent: make(map[int]bool),
	}
}

// SetLogger sets a custom logger for the peer monitor.
func (m *PeerMonitor) SetLogger(logger *slog.Logger) {
	m.logger = logger
}

// isInGracePeriod returns true if the monitor is still within the startup grace period.
// During this period, peer online alerts are suppressed to prevent false positives
// that occur when the server restarts and peers were already online.
func (m *PeerMonitor) isInGracePeriod() bool {
	return time.Since(m.startTime) < m.gracePeriod
}

// Start begins monitoring peer status.
func (m *PeerMonitor) Start() {
	m.logger.Info("starting peer monitor")
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		m.run()
	}()
}

// Stop stops the peer monitor.
func (m *PeerMonitor) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	m.logger.Info("peer monitor stopped")
}

func (m *PeerMonitor) run() {
	// Initial load of current peer states with retry logic
	// Max 3 retries with exponential backoff: 1s, 2s, 4s
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		err := m.loadPeerStates(m.ctx)
		if err == nil {
			break
		}
		m.logger.Error("failed to load initial peer states", "error", err, "attempt", i+1, "max_retries", maxRetries)
		if i < maxRetries-1 {
			backoff := time.Duration(1<<i) * time.Second
			m.logger.Info("retrying peer state load", "backoff", backoff)
			select {
			case <-time.After(backoff):
				continue
			case <-m.ctx.Done():
				return
			case <-m.stopCh:
				return
			}
		}
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkPeers()
		}
	}
}

func (m *PeerMonitor) loadPeerStates(ctx context.Context) error {
	rows, err := m.database.QueryContext(ctx, `
		SELECT id, last_heartbeat, is_manual
		FROM peers
		WHERE is_manual = 0
	`)
	if err != nil {
		return fmt.Errorf("failed to query peers: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			m.logger.Error("failed to close rows", "error", err)
		}
	}()

	m.mu.Lock()
	defer m.mu.Unlock()

	for rows.Next() {
		var id int
		var lastHeartbeat sql.NullTime
		var isManual bool
		if err := rows.Scan(&id, &lastHeartbeat, &isManual); err != nil {
			return fmt.Errorf("failed to scan peer: %w", err)
		}

		if !lastHeartbeat.Valid || lastHeartbeat.Time.Before(time.Now().Add(-90*time.Second)) {
			m.peerStates[id] = PeerStatusOffline
		} else {
			m.peerStates[id] = PeerStatusOnline
		}
	}

	return nil
}

func (m *PeerMonitor) checkPeers() {
	ctx, cancel := context.WithTimeout(m.ctx, 10*time.Second)
	defer cancel()

	offlineRows, err := m.database.QueryContext(ctx, `
		SELECT id, hostname, ip_address, last_heartbeat
		FROM peers
		WHERE is_manual = 0 AND (last_heartbeat IS NULL OR last_heartbeat < datetime('now', '-90 seconds'))
	`)
	if err != nil {
		m.logger.Error("failed to query offline peers", "error", err)
		return
	}
	defer func() {
		if err := offlineRows.Close(); err != nil {
			m.logger.Error("failed to close offline rows", "error", err)
		}
	}()

	offlinePeers := make(map[int]peerInfo)
	for offlineRows.Next() {
		var id int
		var hostname string
		var ipAddress sql.NullString
		var lastHeartbeat sql.NullTime
		if err := offlineRows.Scan(&id, &hostname, &ipAddress, &lastHeartbeat); err != nil {
			m.logger.Error("failed to scan offline peer", "error", err)
			continue
		}

		info := peerInfo{
			hostname: hostname,
		}
		if ipAddress.Valid {
			info.ipAddress = ipAddress.String
		}
		if lastHeartbeat.Valid {
			info.lastHeartbeat = lastHeartbeat.Time
		}

		offlinePeers[id] = info
	}

	m.mu.RLock()
	previousStates := make(map[int]PeerStatus)
	for k, v := range m.peerStates {
		previousStates[k] = v
	}
	m.mu.RUnlock()

	for peerID, info := range offlinePeers {
		prevStatus, wasOnline := previousStates[peerID]
		if wasOnline && prevStatus == PeerStatusOnline {
			// Peer transitioned from online to offline
			m.triggerPeerOfflineAlert(ctx, peerID, info)
		}
	}

	onlineRows, err := m.database.QueryContext(ctx, `
		SELECT id, hostname, last_heartbeat
		FROM peers
		WHERE is_manual = 0 AND last_heartbeat >= datetime('now', '-90 seconds')
	`)
	if err != nil {
		m.logger.Error("failed to query online peers", "error", err)
		return
	}
	defer func() {
		if err := onlineRows.Close(); err != nil {
			m.logger.Error("failed to close online rows", "error", err)
		}
	}()

	currentOnline := make(map[int]peerInfo)
	for onlineRows.Next() {
		var id int
		var hostname string
		var lastHeartbeat time.Time
		if err := onlineRows.Scan(&id, &hostname, &lastHeartbeat); err != nil {
			continue
		}
		currentOnline[id] = peerInfo{hostname: hostname, lastHeartbeat: lastHeartbeat}
	}

	for peerID := range previousStates {
		prevStatus := previousStates[peerID]
		if _, isOffline := offlinePeers[peerID]; !isOffline && prevStatus == PeerStatusOffline {
			if info, ok := currentOnline[peerID]; ok {
				m.triggerPeerOnlineAlert(ctx, peerID, info, prevStatus)
			}
		}
	}

	m.mu.Lock()
	m.peerStates = make(map[int]PeerStatus)
	for peerID := range offlinePeers {
		m.peerStates[peerID] = PeerStatusOffline
	}
	for peerID := range currentOnline {
		m.peerStates[peerID] = PeerStatusOnline
	}
	m.mu.Unlock()
}

func (m *PeerMonitor) triggerPeerOfflineAlert(ctx context.Context, peerID int, info peerInfo) {
	m.mu.Lock()
	alreadySent := m.offlineAlertSent[peerID]
	if alreadySent {
		m.mu.Unlock()
		m.logger.Debug("skipping duplicate offline alert", "peer_id", peerID)
		return
	}
	m.offlineAlertSent[peerID] = true
	m.mu.Unlock()

	m.logger.Info("peer went offline", "peer_id", peerID, "hostname", info.hostname)

	if m.service == nil {
		return
	}

	var offlineDuration string
	if !info.lastHeartbeat.IsZero() {
		offlineDuration = fmt.Sprintf("%.0f", time.Since(info.lastHeartbeat).Minutes())
	} else {
		offlineDuration = "unknown"
	}

	// Sanitize hostname before using in alert (defense in depth)
	sanitizedHostname, modified := SanitizeAlertInput(info.hostname, DefaultMaxHostnameLength)
	if modified {
		m.logger.Warn("hostname was sanitized in offline alert", "peer_id", peerID)
	}

	if err := m.service.TriggerAlert(ctx, &AlertEvent{
		Type:     AlertTypePeerOffline,
		PeerID:   peerID,
		PeerName: sanitizedHostname,
		Subject:  fmt.Sprintf("Peer Offline: %s", sanitizedHostname),
		Message:  fmt.Sprintf("The peer %s has gone offline.", sanitizedHostname),
		Metadata: map[string]interface{}{
			"peer_id":          peerID,
			"hostname":         sanitizedHostname,
			"ip_address":       info.ipAddress,
			"offline_duration": offlineDuration,
			"last_heartbeat":   info.lastHeartbeat,
		},
	}); err != nil {
		m.logger.Error("failed to trigger peer offline alert", "error", err, "peer_id", peerID)
	}
}

func (m *PeerMonitor) triggerPeerOnlineAlert(ctx context.Context, peerID int, info peerInfo, wasOffline PeerStatus) {
	m.logger.Info("peer came online", "peer_id", peerID, "hostname", info.hostname)

	m.mu.Lock()
	delete(m.offlineAlertSent, peerID)
	m.mu.Unlock()

	// Suppress online alerts during grace period to prevent false positives
	// when the server restarts and peers were already online
	if m.isInGracePeriod() {
		m.logger.Info("suppressing peer online alert during grace period", "peer_id", peerID)
		return
	}

	if m.service == nil {
		return
	}

	// Sanitize hostname before using in alert (defense in depth)
	sanitizedHostname, modified := SanitizeAlertInput(info.hostname, DefaultMaxHostnameLength)
	if modified {
		m.logger.Warn("hostname was sanitized in online alert", "peer_id", peerID)
	}

	if err := m.service.TriggerAlert(ctx, &AlertEvent{
		Type:     AlertTypePeerOnline,
		PeerID:   peerID,
		PeerName: sanitizedHostname,
		Subject:  fmt.Sprintf("Peer Online: %s", sanitizedHostname),
		Message:  fmt.Sprintf("The peer %s is back online.", sanitizedHostname),
		Metadata: map[string]interface{}{
			"peer_id":    peerID,
			"hostname":   sanitizedHostname,
			"ip_address": info.ipAddress,
		},
	}); err != nil {
		m.logger.Error("failed to trigger peer online alert", "error", err, "peer_id", peerID)
	}
}
