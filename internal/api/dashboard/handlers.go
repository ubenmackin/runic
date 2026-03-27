package dashboard

import (
	"net/http"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/db"
)

type DashboardStats struct {
	TotalPeers      int `json:"total_peers"`
	OnlinePeers     int `json:"online_peers"`
	OfflinePeers    int `json:"offline_peers"`
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

	// Count online peers (status = 'online')
	rows2, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM peers WHERE last_heartbeat > datetime('now', '-90 seconds')`)
	if err == nil {
		defer rows2.Close()
		if rows2.Next() {
			if err := rows2.Scan(&stats.OnlinePeers); err != nil {
				log.Error("failed to scan online peer count", "error", err)
			}
		}
	}

	// Calculate offline peers AFTER online count is populated
	stats.OfflinePeers = stats.TotalPeers - stats.OnlinePeers

	// Count policies
	rows3, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM policies WHERE enabled = 1`)
	if err == nil {
		defer rows3.Close()
		if rows3.Next() {
			if err := rows3.Scan(&stats.TotalPolicies); err != nil {
				log.Error("failed to scan policy count", "error", err)
			}
		}
	}

	// Placeholder blocked counts (would come from logs table)
	stats.BlockedLastHour = 0
	stats.BlockedLast24h = 0

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{"data": stats})
}
