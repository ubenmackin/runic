package logs

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"runic/internal/auth"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

// respondJSON responds with JSON data
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// respondError responds with a JSON error
func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}

// MakeLogsStreamHandler returns a handler that uses the given Hub
func MakeLogsStreamHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate WebSocket connection via token query parameter.
		// The browser WebSocket API does not support custom headers,
		// so the JWT is passed as ?token=...
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			http.Error(w, "Unauthorized: missing token", http.StatusUnauthorized)
			return
		}
		claims, err := auth.ValidateToken(tokenStr)
		if err != nil || claims == nil {
			http.Error(w, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}
		// Check revocation
		if auth.IsRevoked(r.Context(), claims.UniqueID) {
			http.Error(w, "Unauthorized: token revoked", http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			runiclog.Error("WebSocket upgrade failed", "error", err)
			return
		}

		client := &Client{
			hub:  hub,
			conn: conn,
			send: make(chan []byte, 256),
			filter: LogFilter{
				ServerID: r.URL.Query().Get("server_id"),
				Action:   r.URL.Query().Get("action"),
				SrcIP:    r.URL.Query().Get("src_ip"),
			},
		}
		if dstPort := r.URL.Query().Get("dst_port"); dstPort != "" {
			if p, err := strconv.Atoi(dstPort); err == nil {
				client.filter.DstPort = p
			}
		}

		client.hub.register <- client

		// Start read/write pumps
		go client.writePump()
		go client.readPump()
	}
}

// GetLogs handles GET /api/v1/logs for historical log queries.
func GetLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	serverID := r.URL.Query().Get("server_id")
	srcIP := r.URL.Query().Get("src_ip")
	dstPort := r.URL.Query().Get("dst_port")
	action := r.URL.Query().Get("action")
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 100
	offset := 0

	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
		limit = l
	}
	if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
		offset = o
	}

	// Build query
	var conditions []string
	var args []interface{}

	if serverID != "" {
		conditions = append(conditions, "fl.server_id = ?")
		args = append(args, serverID)
	}
	if srcIP != "" {
		conditions = append(conditions, "fl.src_ip LIKE ?")
		args = append(args, srcIP+"%")
	}
	if dstPort != "" {
		conditions = append(conditions, "fl.dst_port = ?")
		args = append(args, dstPort)
	}
	if action != "" {
		action = strings.ToUpper(action)
		conditions = append(conditions, "fl.action = ?")
		args = append(args, action)
	}
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			conditions = append(conditions, "fl.timestamp >= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			conditions = append(conditions, "fl.timestamp <= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Always join with servers to get hostname
	args = append(args, limit, offset)

	query := `SELECT fl.id, fl.server_id, s.hostname, fl.timestamp, fl.direction,
		fl.src_ip, fl.dst_ip, fl.protocol, fl.src_port, fl.dst_port, fl.action, fl.raw_line
		FROM firewall_logs fl
		JOIN servers s ON fl.server_id = s.id
		` + whereClause + `
		ORDER BY fl.timestamp DESC
		LIMIT ? OFFSET ?`

	rows, err := db.DB.QueryContext(ctx, query, args...)
	if err != nil {
		runiclog.ErrorContext(ctx, "Failed to query logs", "error", err)
		respondError(w, http.StatusInternalServerError, "failed to query logs")
		return
	}
	defer rows.Close()

	var logsData []models.LogEvent
	for rows.Next() {
		var ev models.LogEvent
		var direction sql.NullString
		var rawLine sql.NullString
		var srcPort, dstPort sql.NullInt64

		err := rows.Scan(
			&ev.ID, &ev.ServerID, &ev.Hostname, &ev.Timestamp, &direction,
			&ev.SrcIP, &ev.DstIP, &ev.Protocol, &srcPort, &dstPort, &ev.Action, &rawLine,
		)
		if err != nil {
			runiclog.ErrorContext(ctx, "Failed to scan log row", "error", err)
			continue
		}

		// Populate nullable fields from scanned values
		if direction.Valid {
			ev.Direction = direction.String
		}
		if rawLine.Valid {
			ev.RawLine = rawLine.String
		}
		if srcPort.Valid {
			ev.SrcPort = int(srcPort.Int64)
		}
		if dstPort.Valid {
			ev.DstPort = int(dstPort.Int64)
		}

		logsData = append(logsData, ev)
	}

	if logsData == nil {
		logsData = []models.LogEvent{}
	}

	// Get total count for pagination
	countQuery := `SELECT COUNT(*) FROM firewall_logs fl ` + whereClause
	countArgs := args[:len(args)-2] // Remove limit and offset
	var total int
	if err := db.DB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		runiclog.ErrorContext(ctx, "Failed to get log count", "error", err)
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logsData,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
