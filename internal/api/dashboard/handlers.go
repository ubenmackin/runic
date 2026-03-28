package dashboard

import (
	"fmt"
	"net/http"

	"runic/internal/api/common"
	"runic/internal/common/constants"
	"runic/internal/common/log"
	"runic/internal/db"
)

type DashboardStats struct {
	TotalPeers      int `json:"total_peers"`
	OnlinePeers     int `json:"online_peers"`
	OfflinePeers    int `json:"offline_peers"`
	ManualPeers     int `json:"manual_peers"`
	TotalPolicies   int `json:"total_policies"`
	BlockedLastHour int `json:"blocked_last_hour"`
	BlockedLast24h  int `json:"blocked_last_24h"`
}

func HandleDashboard(w http.ResponseWriter, r *http.Request) {
	var stats DashboardStats

	// Count peers
	rows, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM peers`)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&stats.TotalPeers); err != nil {
				log.Error("failed to scan peer count", "error", err)
			}
		}
	}

	// Count manual peers (is_manual = 1)
	rows2, err := db.DB.QueryContext(r.Context(), "SELECT COUNT(*) FROM peers WHERE is_manual = 1")
	if err == nil {
		defer rows2.Close()
		if rows2.Next() {
			if err := rows2.Scan(&stats.ManualPeers); err != nil {
				log.Error("failed to scan manual peer count", "error", err)
			}
		}
	}

	// Count online peers (status = 'online) - only agent peers (not manual)
	rows3, err := db.DB.QueryContext(r.Context(), fmt.Sprintf("SELECT COUNT(*) FROM peers WHERE is_manual = 0 AND last_heartbeat > datetime('now', '-%d seconds')", constants.OfflineThresholdSeconds))
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
	rows4, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM policies WHERE enabled = 1`)
	if err == nil {
		defer rows4.Close()
		if rows4.Next() {
			if err := rows4.Scan(&stats.TotalPolicies); err != nil {
				log.Error("failed to scan policy count", "error", err)
			}
		}
	}

	// Placeholder blocked counts (would come from logs table)
	stats.BlockedLastHour = 0
	stats.BlockedLast24h = 0

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{"data": stats})
}
