// Package logcleanup provides a background worker for cleaning up old logs.
package logcleanup

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"runic/internal/common/log"
)

type Worker struct {
	db       *sql.DB
	logsDB   *sql.DB
	interval time.Duration
}

func NewWorker(db *sql.DB, logsDB *sql.DB) *Worker {
	return &Worker{
		db:       db,
		logsDB:   logsDB,
		interval: 24 * time.Hour, // Run once per day
	}
}

// Start begins the cleanup worker. It runs immediately on startup, then every interval.
func (w *Worker) Start(ctx context.Context) {
	// Run once immediately on startup
	w.runCleanup(ctx)

	// Then run periodically
	go func() {
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.runCleanup(ctx)
			}
		}
	}()
}

func (w *Worker) runCleanup(ctx context.Context) {
	var retentionDays int
	err := w.db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'log_retention_days'").Scan(&retentionDays)
	if errors.Is(err, sql.ErrNoRows) {
		retentionDays = 30 // default
	} else if err != nil {
		log.ErrorContext(ctx, "Failed to get log_retention_days for cleanup", "error", err)
		return
	}

	// -1 = unlimited, 0 = disabled (don't store logs)
	if retentionDays == -1 || retentionDays == 0 {
		log.DebugContext(ctx, "Log cleanup skipped", "retention_days", retentionDays)
		return
	}

	// Check if logsDB is available
	if w.logsDB == nil {
		log.ErrorContext(ctx, "LogsDB not initialized for cleanup")
		return
	}

	// Delete logs older than retention days
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Format("2006-01-02 15:04:05")

	// Delete in batches to avoid locking
	totalDeleted := 0
	batchSize := 1000

	for {
		result, err := w.logsDB.ExecContext(ctx,
			"DELETE FROM firewall_logs WHERE id IN (SELECT id FROM firewall_logs WHERE timestamp < ? LIMIT ?)",
			cutoff, batchSize,
		)
		if err != nil {
			log.ErrorContext(ctx, "Failed to delete old logs", "error", err)
			break
		}

		rowsAffected, err := result.RowsAffected()
		if err != nil {
			log.ErrorContext(ctx, "Failed to get rows affected", "error", err)
			break
		}
		if rowsAffected == 0 {
			break
		}

		totalDeleted += int(rowsAffected)
		log.DebugContext(ctx, "Deleted batch of old logs", "count", rowsAffected, "total", totalDeleted)

		// Small pause between batches to reduce database load
		time.Sleep(10 * time.Millisecond)
	}

	if totalDeleted > 0 {
		log.InfoContext(ctx, "Log cleanup completed", "deleted", totalDeleted, "retention_days", retentionDays)
	}
}
