package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	ic "runic/internal/common"
	"runic/internal/db"
	"runic/internal/models"
)

// LogsStore provides access to the firewall logs database.
type LogsStore struct {
	logsDB db.Querier // may be nil
}

// NewLogsStore creates a new LogsStore. logsDB may be nil if the logs database is not configured.
func NewLogsStore(logsDB db.Querier) *LogsStore {
	return &LogsStore{logsDB: logsDB}
}

// LogFilter holds optional filter criteria for log queries.
type LogFilter struct {
	PeerID  string
	SrcIP   string
	DstPort string
	Action  string
	From    string
	To      string
}

// ListLogsResult holds the result of a paginated log query.
type ListLogsResult struct {
	Logs  []models.LogEvent
	Total int
}

// ListLogs queries firewall logs with optional filters, returning paginated results.
// The total count reflects the number of rows matching the filter (ignoring limit/offset).
func (s *LogsStore) ListLogs(ctx context.Context, filter *LogFilter, limit, offset int) (*ListLogsResult, error) {
	if s.logsDB == nil {
		return &ListLogsResult{Logs: []models.LogEvent{}, Total: 0}, nil
	}
	if filter == nil {
		filter = &LogFilter{}
	}

	var conditions []string
	var args []interface{}

	if filter.PeerID != "" {
		conditions = append(conditions, "peer_id = ?")
		args = append(args, filter.PeerID)
	}
	if filter.SrcIP != "" {
		conditions = append(conditions, "source_ip LIKE ?")
		args = append(args, filter.SrcIP+"%")
	}
	if filter.DstPort != "" {
		conditions = append(conditions, "dest_port = ?")
		args = append(args, filter.DstPort)
	}
	if filter.Action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, strings.ToUpper(filter.Action))
	}
	if filter.From != "" {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.From)
	}
	if filter.To != "" {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.To)
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Query logs
	queryArgs := append([]interface{}{}, args...)
	queryArgs = append(queryArgs, limit, offset)
	query := `SELECT id, peer_id, peer_hostname, timestamp, event_type,
		source_ip, dest_ip, protocol, source_port, dest_port, action, details
		FROM firewall_logs
		` + whereClause + `
		ORDER BY timestamp DESC
		LIMIT ? OFFSET ?`

	rows, err := s.logsDB.QueryContext(ctx, query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query firewall logs: %w", err)
	}
	defer func() {
		if cErr := rows.Close(); cErr != nil {
			_ = cErr
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
			return nil, fmt.Errorf("scan firewall log row: %w", err)
		}

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

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate firewall log rows: %w", err)
	}

	logsData = ic.EnsureSlice(logsData)

	// Count query (same filters, no limit/offset)
	countQuery := `SELECT COUNT(*) FROM firewall_logs ` + whereClause
	countArgs := args
	var total int
	if err := s.logsDB.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count firewall logs: %w", err)
	}

	return &ListLogsResult{Logs: logsData, Total: total}, nil
}
