package logs

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
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

// Hub streams log events to WebSocket clients with a slow-consumer policy:
// messages for slow consumers are dropped without evicting them and counted
// in DroppedCount. Both the Run broadcast-channel path and the direct
// Broadcast method drop (never evict), matching the SSEHub trySend behavior.
// Drops are sampled to the log (1% of drops) via a counter to avoid log
// storms without requiring a seeded RNG.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
	// sendMu serializes channel sends against closes so a sender holding
	// a copied client reference never races with a concurrent close.
	// The client map is copied under mu, then the send or close proceeds
	// under sendMu. Sends hold RLock (allowing concurrent sends) while
	// closes hold Lock.
	sendMu  sync.RWMutex
	dropped atomic.Uint64
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
		register:   make(chan *Client, 64),
		unregister: make(chan *Client, 64),
	}
}

// DroppedCount reports the number of log events dropped for slow consumers.
func (h *Hub) DroppedCount() uint64 {
	return h.dropped.Load()
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
			_, ok := h.clients[client]
			if ok {
				delete(h.clients, client)
			}
			h.mu.Unlock()
			if ok {
				h.sendMu.Lock()
				client.closeSendOnce.Do(func() { close(client.send) })
				h.sendMu.Unlock()
			}

		case message := <-h.broadcast:
			h.mu.RLock()
			clients := make([]*Client, 0, len(h.clients))
			for client := range h.clients {
				clients = append(clients, client)
			}
			h.mu.RUnlock()
			for _, client := range clients {
				if !h.sendToClient(client, message) {
					if h.dropped.Add(1)%100 == 1 {
						runiclog.Warn("dropping log event for slow client",
							"peer_id_filter", client.filter.PeerID)
					}
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

// Broadcast sends a log event to all connected clients that match the event's filter.
// The client set is copied under RLock so slow consumers never block
// registration, unregistration, or other broadcasters. Messages for slow
// consumers are dropped without evicting them and counted in DroppedCount.
// This matches the SSEHub behavior in events/hub.go (NotifyPushJobProgress etc.)
// which also drops messages silently, and matches the Run broadcast channel
// path which likewise drops without evicting.
func (h *Hub) Broadcast(event *models.LogEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		runiclog.Error("Failed to marshal log event", "error", err)
		return
	}
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for client := range h.clients {
		clients = append(clients, client)
	}
	h.mu.RUnlock()
	for _, client := range clients {
		if !client.matchesFilter(event) {
			continue
		}
		if !h.sendToClient(client, data) {
			if h.dropped.Add(1)%100 == 1 { // 1% sample to avoid log storms
				runiclog.Warn("dropping log event for slow client",
					"peer_id_filter", client.filter.PeerID)
			}
		}
	}
}

// sendToClient performs a non-blocking send to a single client, serialized
// against concurrent closes via sendMu. It reports whether the message was
// delivered. A send on a concurrently closed channel panics; the panic is
// recovered and reported as undelivered.
func (h *Hub) sendToClient(client *Client, message []byte) (sent bool) {
	h.sendMu.RLock()
	defer h.sendMu.RUnlock()
	defer func() {
		if recover() != nil {
			sent = false
		}
	}()
	select {
	case client.send <- message:
		return true
	default:
		return false
	}
}

// evict removes a client from the hub and closes its send channel.
// The map mutation happens under mu; the close happens under sendMu.Lock
// so it is serialized against concurrent sends. It is used for explicit
// disconnects and as a non-blocking fallback when the unregister channel
// cannot be used (for example, when Run has already exited). Slow consumers
// are never evicted; their messages are dropped instead (see Hub policy).
func (h *Hub) evict(client *Client) {
	h.mu.Lock()
	if _, ok := h.clients[client]; !ok {
		h.mu.Unlock()
		return
	}
	delete(h.clients, client)
	h.mu.Unlock()
	h.sendMu.Lock()
	client.closeSendOnce.Do(func() { close(client.send) })
	h.sendMu.Unlock()
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
		select {
		case c.hub.unregister <- c:
		default:
			c.hub.evict(c)
		}
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
