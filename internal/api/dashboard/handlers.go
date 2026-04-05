package dashboard

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"runic/internal/api/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
)

// Handler holds dependencies for dashboard handlers.
type Handler struct {
	DB *sql.DB
}

// NewHandler creates a new dashboard handler.
func NewHandler(db *sql.DB) *Handler {
	return &Handler{DB: db}
}

type ActivityItem struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	Protocol  string `json:"protocol"`
	Action    string `json:"action"`
	Hostname  string `json:"hostname,omitempty"`
}

type PeerHealth struct {
	Hostname      string `json:"hostname"`
	IP            string `json:"ip_address"`
	AgentVersion  string `json:"agent_version"`
	LastHeartbeat string `json:"last_heartbeat"`
	IsOnline      bool   `json:"is_online"`
	IsManual      bool   `json:"is_manual"`
}

type BlockedIP struct {
	SrcIP string `json:"src_ip"`
	Count int    `json:"count"`
}

type DashboardStats struct {
	TotalPeers       int            `json:"total_peers"`
	OnlinePeers      int            `json:"online_peers"`
	OfflinePeers     int            `json:"offline_peers"`
	ManualPeers      int            `json:"manual_peers"`
	TotalPolicies    int            `json:"total_policies"`
	BlockedLastHour  int            `json:"blocked_last_hour"`
	BlockedLast24h   int            `json:"blocked_last_24h"`
	RecentActivity   []ActivityItem `json:"recent_activity"`
	PeerHealth       []PeerHealth   `json:"peer_health"`
	TopBlockedSource []BlockedIP    `json:"top_blocked_sources"`
}

func (h *Handler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	var stats DashboardStats

	// Count peers
	rows, err := h.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM peers`)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&stats.TotalPeers); err != nil {
				log.Error("failed to scan peer count", "error", err)
			}
		}
	}

	// Count manual peers (is_manual = 1)
	rows2, err := h.DB.QueryContext(r.Context(), "SELECT COUNT(*) FROM peers WHERE is_manual = 1")
	if err == nil {
		defer rows2.Close()
		if rows2.Next() {
			if err := rows2.Scan(&stats.ManualPeers); err != nil {
				log.Error("failed to scan manual peer count", "error", err)
			}
		}
	}

	// Count online peers (status = 'online) - only agent peers (not manual)
	rows3, err := h.DB.QueryContext(r.Context(), fmt.Sprintf("SELECT COUNT(*) FROM peers WHERE is_manual = 0 AND last_heartbeat > datetime('now', '-%d seconds')", constants.OfflineThresholdSeconds))
	if err == nil {
		defer rows3.Close()
		if rows3.Next() {
			if err := rows3.Scan(&stats.OnlinePeers); err != nil {
				log.Error("failed to scan online peer count", "error", err)
			}
		}
	}

	// Calculate offline peers - only count agent peers (exclude manual peers since they don't send heartbeats)
	// Offline = Total - Manual - Online
	stats.OfflinePeers = stats.TotalPeers - stats.ManualPeers - stats.OnlinePeers

	// Count policies
	rows4, err := h.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM policies WHERE enabled = 1`)
	if err == nil {
		defer rows4.Close()
		if rows4.Next() {
			if err := rows4.Scan(&stats.TotalPolicies); err != nil {
				log.Error("failed to scan policy count", "error", err)
			}
		}
	}

	// Initialize slices to avoid null in JSON
	stats.RecentActivity = []ActivityItem{}
	stats.PeerHealth = []PeerHealth{}
	stats.TopBlockedSource = []BlockedIP{}

	// Get blocked events count for last hour and last 24 hours in a single query
	rows5, err := h.DB.QueryContext(r.Context(), `
		SELECT
		COALESCE(SUM(CASE WHEN timestamp > datetime('now', '-1 hour') THEN 1 ELSE 0 END), 0) as blocked_last_hour,
		COUNT(*) as blocked_last_24h
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')
	`)
	if err == nil {
		defer rows5.Close()
		if rows5.Next() {
			if err := rows5.Scan(&stats.BlockedLastHour, &stats.BlockedLast24h); err != nil {
				log.Error("failed to scan blocked counts", "error", err)
			}
		}
	}

	// Get recent activity - last 5 blocked events
	activityRows, err := h.DB.QueryContext(r.Context(), `
		SELECT fl.timestamp, fl.src_ip, fl.dst_ip, fl.protocol, fl.action, p.hostname
		FROM firewall_logs fl
		LEFT JOIN peers p ON fl.peer_id = p.id
		WHERE fl.action = 'DROP'
		ORDER BY fl.timestamp DESC
		LIMIT 5`)
	if err == nil {
		defer activityRows.Close()
		for activityRows.Next() {
			var item ActivityItem
			var hostname sql.NullString
			if err := activityRows.Scan(&item.Timestamp, &item.SrcIP, &item.DstIP, &item.Protocol, &item.Action, &hostname); err != nil {
				log.Error("failed to scan activity row", "error", err)
				continue
			}
			if hostname.Valid {
				item.Hostname = hostname.String
			}
			stats.RecentActivity = append(stats.RecentActivity, item)
		}
	}

	// Get peer health data
	peerRows, err := h.DB.QueryContext(r.Context(), `
		SELECT hostname, ip_address, agent_version, last_heartbeat, is_manual
		FROM peers
		ORDER BY hostname`)
	if err == nil {
		defer peerRows.Close()
		for peerRows.Next() {
			var ph PeerHealth
			var lastHeartbeat sql.NullString
			var agentVersion sql.NullString
			var isManual bool
			if err := peerRows.Scan(&ph.Hostname, &ph.IP, &agentVersion, &lastHeartbeat, &isManual); err != nil {
				log.Error("failed to scan peer health row", "error", err)
				continue
			}
			if agentVersion.Valid {
				ph.AgentVersion = agentVersion.String
			}
			if lastHeartbeat.Valid {
				ph.LastHeartbeat = lastHeartbeat.String
				// Parse the timestamp and check if within offline threshold
				if t, err := time.Parse("2006-01-02 15:04:05", lastHeartbeat.String); err == nil {
					ph.IsOnline = time.Since(t).Seconds() < float64(constants.OfflineThresholdSeconds)
				}
			}
			ph.IsManual = isManual
			stats.PeerHealth = append(stats.PeerHealth, ph)
		}
	}

	// Get top 5 blocked source IPs in last 24h
	topRows, err := h.DB.QueryContext(r.Context(), `
		SELECT src_ip, COUNT(*) as count
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')
		GROUP BY src_ip
		ORDER BY count DESC
		LIMIT 5`)
	if err == nil {
		defer topRows.Close()
		for topRows.Next() {
			var b BlockedIP
			if err := topRows.Scan(&b.SrcIP, &b.Count); err != nil {
				log.Error("failed to scan top blocked row", "error", err)
				continue
			}
			stats.TopBlockedSource = append(stats.TopBlockedSource, b)
		}
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{"data": stats})
}
