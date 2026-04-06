package logs

import (
	"context"
	"encoding/json"
	"net/http"
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
			return true // Same-origin requests (no Origin header)
		}
		// Allow same-origin only (both http and https)
		return origin == "http://"+r.Host ||
			origin == "https://"+r.Host
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
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	filter LogFilter
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
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()

		case <-ctx.Done():
			return
		}
	}
}

func (h *Hub) Broadcast(event *models.LogEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		runiclog.Error("Failed to marshal log event", "error", err)
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for client := range h.clients {
		if client.matchesFilter(event) {
			select {
			case client.send <- data:
			default:
			}
		}
	}
}

func (c *Client) matchesFilter(ev *models.LogEvent) bool {
	f := c.filter
	if f.PeerID != "" && ev.PeerID != f.PeerID {
		return false
	}
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
	c.conn.SetReadLimit(512)
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
