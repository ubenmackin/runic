package dashboard

import (
	"net/http"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/db"
)

type DashboardStats struct {
	TotalServers    int `json:"total_servers"`
	OnlineServers   int `json:"online_servers"`
	OfflineServers  int `json:"offline_servers"`
	TotalPolicies   int `json:"total_policies"`
	BlockedLastHour int `json:"blocked_last_hour"`
	BlockedLast24h  int `json:"blocked_last_24h"`
}

func HandleDashboard(w http.ResponseWriter, r *http.Request) {
	var stats DashboardStats

	// Count servers
	rows, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM servers`)
	if err == nil {
		defer rows.Close()
		if rows.Next() {
			if err := rows.Scan(&stats.TotalServers); err != nil {
				log.Error("failed to scan server count", "error", err)
			}
		}
	}

	// Count online servers (status = 'online')
	rows2, err := db.DB.QueryContext(r.Context(), `SELECT COUNT(*) FROM servers WHERE last_heartbeat > datetime('now', '-90 seconds')`)
	if err == nil {
		defer rows2.Close()
		if rows2.Next() {
			if err := rows2.Scan(&stats.OnlineServers); err != nil {
				log.Error("failed to scan online server count", "error", err)
			}
		}
	}

	// Calculate offline servers AFTER online count is populated
	stats.OfflineServers = stats.TotalServers - stats.OnlineServers

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
