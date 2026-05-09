// Package logs provides API logs handlers.
package logs

import (
	"context"
	"net/http"
	"strconv"
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

		if revoked, err := tokenStore.IsTokenRevoked(r.Context(), claims.UniqueID); err != nil || revoked {
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
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			toTime = t.Format(time.RFC3339)
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
