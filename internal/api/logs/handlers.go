// Package logs provides API logs handlers.
package logs

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiclog "runic/internal/common/log"
	"runic/internal/db"
	"runic/internal/models"
)

type Handler struct {
	LogsDB db.Querier
}

func NewHandler(logsDB db.Querier) *Handler {
	return &Handler{LogsDB: logsDB}
}

// MakeLogsStreamHandler returns a handler that uses the given Hub
func MakeLogsStreamHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate WebSocket connection: try cookie first (web UI),
		// then fall back to Sec-WebSocket-Protocol header (legacy agent WS).
		var tokenStr string
		if c, err := r.Cookie("runic_access_token"); err == nil && c.Value != "" {
			tokenStr = c.Value
		} else {
			subprotocols := r.Header.Values("Sec-WebSocket-Protocol")
			if len(subprotocols) > 0 {
				tokenStr = subprotocols[0]
			}
		}
		if tokenStr == "" {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}
		claims, err := auth.ValidateToken(tokenStr)
		if err != nil || claims == nil {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if auth.IsRevoked(r.Context(), claims.UniqueID) {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
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
				PeerID: r.URL.Query().Get("peer_id"),
				Action: r.URL.Query().Get("action"),
				SrcIP:  r.URL.Query().Get("src_ip"),
			},
		}
		if dstPort := r.URL.Query().Get("dst_port"); dstPort != "" {
			if p, err := strconv.Atoi(dstPort); err == nil {
				client.filter.DstPort = p
			}
		}

		client.hub.register <- client

		go client.writePump()
		go client.readPump()
	}
}

// GetLogs handles GET /api/v1/logs for historical log queries.
func (h *Handler) GetLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	peerID := r.URL.Query().Get("peer_id")
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

	// Build query - logs DB uses different column names
	var conditions []string
	var args []interface{}

	if peerID != "" {
		conditions = append(conditions, "peer_id = ?")
		args = append(args, peerID)
	}
	if srcIP != "" {
		conditions = append(conditions, "source_ip LIKE ?")
		args = append(args, srcIP+"%")
	}
	if dstPort != "" {
		conditions = append(conditions, "dest_port = ?")
		args = append(args, dstPort)
	}
	if action != "" {
		action = strings.ToUpper(action)
		conditions = append(conditions, "action = ?")
		args = append(args, action)
	}
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			conditions = append(conditions, "timestamp >= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			conditions = append(conditions, "timestamp <= ?")
			args = append(args, t.Format(time.RFC3339))
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Query logs DB - peer_hostname is already stored in the log entry
	args = append(args, limit, offset)

	query := `SELECT id, peer_id, peer_hostname, timestamp, event_type,
		source_ip, dest_ip, protocol, source_port, dest_port, action, details
		FROM firewall_logs
		` + whereClause + `
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?`

	rows, err := h.LogsDB.QueryContext(ctx, query, args...)
	if err != nil {
		runiclog.ErrorContext(ctx, "Failed to query logs", "error", err, "query", query)
		common.RespondError(w, http.StatusInternalServerError, "failed to query logs")
		return
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			runiclog.Warn("close err", "err", cErr)
		}
	}()

	var logsData []models.LogEvent
	for rows.Next() {
		var ev models.LogEvent
		var eventType, details sql.NullString
		var peerHostname sql.NullString
		var srcPort, dstPort sql.NullInt64

		err := rows.Scan(
			&ev.ID, &ev.PeerID, &peerHostname, &ev.Timestamp, &eventType,
			&ev.SrcIP, &ev.DstIP, &ev.Protocol, &srcPort, &dstPort, &ev.Action, &details,
		)
		if err != nil {
			runiclog.ErrorContext(ctx, "Failed to scan log row", "error", err)
			continue
		}

		// Populate nullable fields from scanned values
		if peerHostname.Valid {
			ev.PeerHostname = peerHostname.String
		}
		if eventType.Valid {
			ev.Direction = eventType.String
		}
		if details.Valid {
			ev.RawLine = details.String
		}
		if srcPort.Valid {
			ev.SrcPort = int(srcPort.Int64)
		}
		if dstPort.Valid {
			ev.DstPort = int(dstPort.Int64)
		}

		logsData = append(logsData, ev)
	}

	// Check for row iteration errors
	if err = rows.Err(); err != nil {
		runiclog.ErrorContext(ctx, "Error iterating log rows", "error", err)
	}

	logsData = common.EnsureSlice(logsData)

	countQuery := `SELECT COUNT(*) FROM firewall_logs ` + whereClause
	countArgs := args[:len(args)-2]
	var total int
	if err := h.LogsDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		runiclog.ErrorContext(ctx, "Failed to get log count", "error", err, "query", countQuery)
		// Set total to 0 instead of leaving it uninitialized
		total = 0
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logsData,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}
