// Package logs provides API logs handlers.
package logs

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"runic/internal/api/common"
	"runic/internal/auth"
	runiclog "runic/internal/common/log"
	"runic/internal/store"
)

// LogsStore is defined as an interface here for testability.
type LogsStore interface {
	ListLogs(ctx context.Context, filter *store.LogFilter, limit, offset int) (*store.ListLogsResult, error)
}

// TokenRevoker checks if a token has been revoked.
type TokenRevoker interface {
	IsTokenRevoked(ctx context.Context, uniqueID string) (bool, error)
}

type Handler struct {
	Store      LogsStore
	TokenStore TokenRevoker
}

func NewHandler(logsStore LogsStore, tokenStore TokenRevoker) *Handler {
	return &Handler{Store: logsStore, TokenStore: tokenStore}
}

func MakeLogsStreamHandler(hub *Hub, tokenStore TokenRevoker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Authenticate WebSocket connection: try cookie first (web UI),
		// then fall back to Sec-WebSocket-Protocol header (agent WS clients).
		// The Sec-WebSocket-Protocol header may contain comma-separated values;
		// we use the first token-like value as the bearer token.
		var tokenStr string
		if c, err := r.Cookie("runic_access_token"); err == nil && c.Value != "" {
			tokenStr = c.Value
		} else {
			for _, proto := range r.Header.Values("Sec-WebSocket-Protocol") {
				// Header may contain comma-separated protocol values
				if first := strings.SplitN(proto, ",", 2)[0]; strings.TrimSpace(first) != "" {
					tokenStr = strings.TrimSpace(first)
					break
				}
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

		if revoked, err := tokenStore.IsTokenRevoked(r.Context(), claims.UniqueID); err != nil || revoked {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			runiclog.Error("WebSocket upgrade failed", "error", err)
			return
		}

		peerIDStr := r.URL.Query().Get("peer_id")

		client := &Client{
			hub:  hub,
			conn: conn,
			send: make(chan []byte, 256),
			filter: LogFilter{
				PeerID: peerIDStr,
				Action: r.URL.Query().Get("action"),
				SrcIP:  r.URL.Query().Get("src_ip"),
			},
		}
		if peerIDStr != "" {
			if n, err := strconv.Atoi(peerIDStr); err == nil {
				client.filterPeerID = n
			} else {
				client.filterPeerID = -1
			}
		} else {
			client.filterPeerID = -1
		}
		if dstPort := r.URL.Query().Get("dst_port"); dstPort != "" {
			if p, err := strconv.Atoi(dstPort); err == nil {
				client.filter.DstPort = p
			}
		}

		select {
		case client.hub.register <- client:
		case <-r.Context().Done():
			_ = conn.Close()
			return
		}

		go client.writePump()
		go client.readPump()
	}
}

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

	// Build filter
	var fromTime, toTime string
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			fromTime = t.Format(time.RFC3339)
		} else {
			runiclog.WarnContext(ctx, "Invalid 'from' time parameter, ignoring", "from", fromStr, "error", err)
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			toTime = t.Format(time.RFC3339)
		} else {
			runiclog.WarnContext(ctx, "Invalid 'to' time parameter, ignoring", "to", toStr, "error", err)
		}
	}

	filter := store.LogFilter{
		PeerID:  peerID,
		SrcIP:   srcIP,
		DstPort: dstPort,
		Action:  action,
		From:    fromTime,
		To:      toTime,
	}

	result, err := h.Store.ListLogs(ctx, &filter, limit, offset)
	if err != nil {
		runiclog.ErrorContext(ctx, "Failed to query logs", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to query logs")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   result.Logs,
		"total":  result.Total,
		"limit":  limit,
		"offset": offset,
	})
}
