// Package dashboard provides API dashboard handlers.
package dashboard

import (
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/sync/errgroup"

	"runic/internal/api/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
)

// Handler holds dependencies for dashboard handlers.
type Handler struct {
	DB     db.Querier // Main database for peers, policies, etc.
	LogsDB db.Querier // Logs database for firewall_logs
}

// NewHandler creates a new dashboard handler.
func NewHandler(db db.Querier, logsDB db.Querier) *Handler {
	return &Handler{DB: db, LogsDB: logsDB}
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

	stats.RecentActivity = []ActivityItem{}
	stats.PeerHealth = []PeerHealth{}
	stats.TopBlockedSource = []BlockedIP{}

	// NOTE: These slices are appended to by goroutines below. This is safe because:
	// 1. Go's append to nil/pre-initialized slices is goroutine-safe (allocates new backing array)
	// 2. SQLite uses serialized write mode by default, preventing true parallel execution
	// 3. If migrating to PostgreSQL/MySQL, mutex protection would be needed

	// Combined COUNT query for peer/policy counts (4 queries -> 1 query)
	countQuery := fmt.Sprintf(`
SELECT
	(SELECT COUNT(*) FROM peers) as total_peers,
	(SELECT COUNT(*) FROM peers WHERE is_manual = 1) as manual_peers,
	(SELECT COUNT(*) FROM peers WHERE is_manual = 0 AND last_heartbeat > datetime('now', '-%d seconds')) as online_peers,
	(SELECT COUNT(*) FROM policies WHERE enabled = 1) as total_policies`,
		constants.OfflineThresholdSeconds)

	rows, err := h.DB.QueryContext(r.Context(), countQuery)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to query peer/policy counts", "error", err)
	} else {
		defer func() {
			if cerr := rows.Close(); cerr != nil {
				log.ErrorContext(r.Context(), "failed to close rows", "error", cerr)
			}
		}()
		if rows.Next() {
			if err := rows.Scan(&stats.TotalPeers, &stats.ManualPeers, &stats.OnlinePeers, &stats.TotalPolicies); err != nil {
				log.ErrorContext(r.Context(), "failed to scan peer/policy counts", "error", err)
			}
		}
	}

	// Calculate offline peers - only count agent peers (exclude manual peers since they don't send heartbeats)
	// Offline = Total - Manual - Online
	stats.OfflinePeers = stats.TotalPeers - stats.ManualPeers - stats.OnlinePeers

	// Get blocked events count for last hour and last 24 hours in a single query
	// Uses logs DB - source_ip instead of src_ip
	blockedRows, err := h.LogsDB.QueryContext(r.Context(), `
		SELECT
		COALESCE(SUM(CASE WHEN timestamp > datetime('now', '-1 hour') THEN 1 ELSE 0 END), 0) as blocked_last_hour,
		COUNT(*) as blocked_last_24h
		FROM firewall_logs
		WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')
		`)
	if err != nil {
		log.ErrorContext(r.Context(), "failed to query blocked counts", "error", err)
	} else {
		defer func() {
			if cerr := blockedRows.Close(); cerr != nil {
				log.ErrorContext(r.Context(), "failed to close rows", "error", cerr)
			}
		}()
		if blockedRows.Next() {
			if err := blockedRows.Scan(&stats.BlockedLastHour, &stats.BlockedLast24h); err != nil {
				log.ErrorContext(r.Context(), "failed to scan blocked counts", "error", err)
			}
		}
	}

	g, ctx := errgroup.WithContext(r.Context())

	// Uses logs DB - peer_hostname is already in the log entry, no JOIN needed
	g.Go(func() error {
		activityRows, err := h.LogsDB.QueryContext(ctx, `
			SELECT timestamp, source_ip, dest_ip, protocol, action, peer_hostname
			FROM firewall_logs
			WHERE action = 'DROP'
			ORDER BY timestamp DESC
			LIMIT 5`)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := activityRows.Close(); cerr != nil {
				log.Error("failed to close rows", "error", cerr)
			}
		}()

		for activityRows.Next() {
			var item ActivityItem
			var hostname sql.NullString
			if err := activityRows.Scan(&item.Timestamp, &item.SrcIP, &item.DstIP, &item.Protocol, &item.Action, &hostname); err != nil {
				return err
			}
			if hostname.Valid {
				item.Hostname = hostname.String
			}
			stats.RecentActivity = append(stats.RecentActivity, item)
		}
		return activityRows.Err()
	})

	g.Go(func() error {
		peerRows, err := h.DB.QueryContext(ctx, `
SELECT hostname, ip_address, agent_version, last_heartbeat, is_manual
FROM peers
ORDER BY hostname`)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := peerRows.Close(); cerr != nil {
				log.Error("failed to close rows", "error", cerr)
			}
		}()

		for peerRows.Next() {
			var ph PeerHealth
			var lastHeartbeat sql.NullString
			var agentVersion sql.NullString
			var isManual bool
			if err := peerRows.Scan(&ph.Hostname, &ph.IP, &agentVersion, &lastHeartbeat, &isManual); err != nil {
				return err
			}
			if agentVersion.Valid {
				ph.AgentVersion = agentVersion.String
			}
			if lastHeartbeat.Valid {
				ph.LastHeartbeat = lastHeartbeat.String
				if t, err := time.Parse("2006-01-02 15:04:05", lastHeartbeat.String); err == nil {
					ph.IsOnline = time.Since(t).Seconds() < float64(constants.OfflineThresholdSeconds)
				}
			}
			ph.IsManual = isManual
			stats.PeerHealth = append(stats.PeerHealth, ph)
		}
		return peerRows.Err()
	})

	// Uses logs DB - source_ip instead of src_ip
	g.Go(func() error {
		topRows, err := h.LogsDB.QueryContext(ctx, `
			SELECT source_ip, COUNT(*) as count
			FROM firewall_logs
			WHERE action = 'DROP' AND timestamp > datetime('now', '-24 hours')
			GROUP BY source_ip
			ORDER BY count DESC
			LIMIT 5`)
		if err != nil {
			return err
		}
		defer func() {
			if cerr := topRows.Close(); cerr != nil {
				log.Error("failed to close top rows", "error", cerr)
			}
		}()

		for topRows.Next() {
			var b BlockedIP
			if err := topRows.Scan(&b.SrcIP, &b.Count); err != nil {
				return err
			}
			stats.TopBlockedSource = append(stats.TopBlockedSource, b)
		}
		return topRows.Err()
	})

	if err := g.Wait(); err != nil {
		log.ErrorContext(r.Context(), "failed to query dashboard data", "error", err)
		// Continue with partial data rather than failing entirely
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{"data": stats})
}

// RegisterRoutes adds dashboard routes to the given router.
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.HandleDashboard).Methods("GET")
}
