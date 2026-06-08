package logs

import (
	"context"
	"encoding/json"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"runic/internal/common/constants"
	runiclog "runic/internal/common/log"
	"runic/internal/models"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		originURL, err := url.Parse(origin)
		if err != nil {
			return false
		}
		requestHost := r.Host
		if h, _, err := net.SplitHostPort(requestHost); err == nil {
			requestHost = h
		}
		return originURL.Hostname() == requestHost || originURL.Host == r.Host // Also allow exact match for compatibility
	},
}

type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

type Client struct {
	hub          *Hub
	conn         *websocket.Conn
	send         chan []byte
	filter       LogFilter
	filterPeerID int // -1 means no filter; parsed once from filter.PeerID at construction

	closeSendOnce sync.Once // ensures client.send is closed exactly once
}

type LogFilter struct {
	PeerID  string
	Action  string
	SrcIP   string
	DstPort int
}

func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

func (h *Hub) Run(ctx context.Context) {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.closeSendOnce.Do(func() { close(client.send) })
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					client.closeSendOnce.Do(func() { close(client.send) })
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

// Broadcast sends a log event to all connected clients that match the event's filter.
// NOTE: Unlike Hub.Run's broadcast channel case (which evicts slow consumers),
// this method silently drops messages for slow consumers without evicting them.
// This matches the SSEHub behavior in events/hub.go (NotifyPushJobProgress etc.)
// which also drops messages silently. Both approaches are intentional — the direct
// Broadcast method is called from a hot path (firewall log ingestion) where eviction
// would add latency, while Run's broadcast channel is used for internal hub messaging.
func (h *Hub) Broadcast(event *models.LogEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		runiclog.Error("Failed to marshal log event", "error", err)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for client := range h.clients {
		if client.matchesFilter(event) {
			select {
			case client.send <- data:
			default:
				if rand.Float64() < 0.01 { // 1% sample to avoid log storms
					runiclog.Warn("dropping log event for slow client",
						"peer_id_filter", client.filter.PeerID)
				}
			}
		}
	}
}

func (c *Client) matchesFilter(ev *models.LogEvent) bool {
	if c.filterPeerID >= 0 && ev.PeerID != c.filterPeerID {
		return false
	}
	f := c.filter
	if f.Action != "" && ev.Action != f.Action {
		return false
	}
	if f.SrcIP != "" && ev.SrcIP != f.SrcIP {
		return false
	}
	if f.DstPort != 0 && ev.DstPort != f.DstPort {
		return false
	}
	return true
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		if err := c.conn.Close(); err != nil {
			runiclog.Warn("close err", "err", err)
		}
	}()
	// ReadLimit(512) limits the maximum size of a control message (pong, etc.)
	// to 512 bytes. We only read control frames from clients (no data messages),
	// so this is a generous limit that prevents memory exhaustion from oversized frames.
	c.conn.SetReadLimit(512)
	// The initial read deadline is set once here; the PongHandler below
	// resets it on every received pong, keeping the connection alive as long
	// as the client sends pings. This is functionally correct — if the client
	// doesn't send pings, the connection times out after 60s of read inactivity.
	if err := c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
		runiclog.Warn("err", "err", err)
	}
	c.conn.SetPongHandler(func(string) error {
		if err := c.conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			runiclog.Warn("err", "err", err)
		}
		return nil
	})
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(constants.WebSocketPingInterval)
	defer func() {
		ticker.Stop()
		if err := c.conn.Close(); err != nil {
			runiclog.Warn("close err", "err", err)
		}
	}()
	for {
		select {
		case message, ok := <-c.send:
			if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				runiclog.Warn("err", "err", err)
			}
			if !ok {
				if err := c.conn.WriteMessage(websocket.CloseMessage, []byte{}); err != nil {
					runiclog.Warn("err", "err", err)
				}
				return
			}
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			if _, err := w.Write(message); err != nil {
				runiclog.Warn("err", "err", err)
			}
			if err := w.Close(); err != nil {
				return
			}
		case <-ticker.C:
			if err := c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				runiclog.Warn("err", "err", err)
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
