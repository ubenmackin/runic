// Package dashboard provides API dashboard handlers.
package dashboard

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/sync/errgroup"

	"runic/internal/api/common"
	"runic/internal/common/log"
	"runic/internal/models"
)

type DashboardStore interface {
	GetPeerAndPolicyCounts(ctx context.Context) (int, int, int, int, error)
	GetBlockedCounts(ctx context.Context) (int, int, error)
	GetRecentActivity(ctx context.Context, limit int) ([]models.ActivityItem, error)
	GetPeerHealth(ctx context.Context) ([]models.PeerHealth, error)
	GetTopBlockedSources(ctx context.Context, limit int) ([]models.BlockedIP, error)
}

type Handler struct {
	Store DashboardStore
}

func NewHandler(store DashboardStore) *Handler {
	return &Handler{Store: store}
}

func (h *Handler) HandleDashboard(w http.ResponseWriter, r *http.Request) {
	var stats models.DashboardStats

	stats.RecentActivity = []models.ActivityItem{}
	stats.PeerHealth = []models.PeerHealth{}
	stats.TopBlockedSource = []models.BlockedIP{}

	// Using errgroup to fetch data concurrently from the store
	g, ctx := errgroup.WithContext(r.Context())
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var hadErrors atomic.Bool

	g.Go(func() error {
		var err error
		stats.TotalPeers, stats.ManualPeers, stats.OnlinePeers, stats.TotalPolicies, err = h.Store.GetPeerAndPolicyCounts(ctx)
		if err != nil {
			hadErrors.Store(true)
			log.ErrorContext(ctx, "failed to get peer/policy counts", "error", err)
		}
		offline := stats.TotalPeers - stats.ManualPeers - stats.OnlinePeers
		if offline < 0 {
			offline = 0
		}
		stats.OfflinePeers = offline
		return nil // Don't fail entire request for one metric
	})

	g.Go(func() error {
		var err error
		stats.BlockedLastHour, stats.BlockedLast24h, err = h.Store.GetBlockedCounts(ctx)
		if err != nil {
			hadErrors.Store(true)
			log.ErrorContext(ctx, "failed to get blocked counts", "error", err)
		}
		return nil
	})

	g.Go(func() error {
		var err error
		stats.RecentActivity, err = h.Store.GetRecentActivity(ctx, 5)
		if err != nil {
			hadErrors.Store(true)
			log.ErrorContext(ctx, "failed to get recent activity", "error", err)
		}
		return nil
	})

	g.Go(func() error {
		var err error
		stats.PeerHealth, err = h.Store.GetPeerHealth(ctx)
		if err != nil {
			hadErrors.Store(true)
			log.ErrorContext(ctx, "failed to get peer health", "error", err)
		}
		return nil
	})

	g.Go(func() error {
		var err error
		stats.TopBlockedSource, err = h.Store.GetTopBlockedSources(ctx, 5)
		if err != nil {
			hadErrors.Store(true)
			log.ErrorContext(ctx, "failed to get top blocked sources", "error", err)
		}
		return nil
	})

	_ = g.Wait() // Errors are logged inside goroutines, continue with partial data

	if hadErrors.Load() {
		stats.Degraded = true
		w.Header().Set("X-Dashboard-Degraded", "true")
	}
	common.RespondJSON(w, http.StatusOK, map[string]interface{}{"data": stats})
}

func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("", h.HandleDashboard).Methods("GET")
}
