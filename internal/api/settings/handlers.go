// Package settings provides API settings handlers.
package settings

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"

	"runic/internal/api/common"
	"runic/internal/common/log"

	"github.com/gorilla/mux"
)

type Handler struct {
	DB *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{DB: db}
}

type LogSettings struct {
	RetentionDays   int    `json:"retention_days"`
	RetentionLabel  string `json:"retention_label"`
	LogCount        int    `json:"log_count"`
	EstimatedSizeMB int    `json:"estimated_size_mb"`
}

// GetLogSettings returns current log retention settings and stats
func (h *Handler) GetLogSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var retentionDays int
	err := h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'log_retention_days'").Scan(&retentionDays)
	if err == sql.ErrNoRows {
		retentionDays = 30 // default
	} else if err != nil {
		log.ErrorContext(ctx, "Failed to get log_retention_days", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get log settings")
		return
	}

	// Get log count
	var logCount int
	err = h.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&logCount)
	if err != nil {
		logCount = 0
	}

	// Estimate size (average ~500 bytes per log entry)
	estimatedSizeMB := (logCount * 500) / (1024 * 1024)

	// Get human-readable label
	retentionLabel := getRetentionLabel(retentionDays)

	common.RespondJSON(w, http.StatusOK, LogSettings{
		RetentionDays:   retentionDays,
		RetentionLabel:  retentionLabel,
		LogCount:        logCount,
		EstimatedSizeMB: estimatedSizeMB,
	})
}

// UpdateLogSettings updates log retention settings
func (h *Handler) UpdateLogSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		RetentionDays int `json:"retention_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	// Validate: -1 for unlimited, 0 for disabled, 1-9999 for custom days
	if req.RetentionDays < -1 || req.RetentionDays > 9999 {
		common.RespondError(w, http.StatusBadRequest, "retention_days must be -1 (unlimited), 0 (disabled), or 1-9999")
		return
	}

	_, err := h.DB.ExecContext(ctx,
		"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('log_retention_days', ?, CURRENT_TIMESTAMP)",
		req.RetentionDays,
	)
	if err != nil {
		log.ErrorContext(ctx, "Failed to update log_retention_days", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to update log settings")
		return
	}

	log.InfoContext(ctx, "Updated log retention", "days", req.RetentionDays)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"retention_days":  req.RetentionDays,
		"retention_label": getRetentionLabel(req.RetentionDays),
	})
}

// ClearAllLogs deletes all firewall logs
func (h *Handler) ClearAllLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	result, err := h.DB.ExecContext(ctx, "DELETE FROM firewall_logs")
	if err != nil {
		log.ErrorContext(ctx, "Failed to clear logs", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to clear logs")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		log.ErrorContext(ctx, "Failed to get rows affected", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to clear logs")
		return
	}
	log.InfoContext(ctx, "Cleared all logs", "count", rowsAffected)

	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": rowsAffected,
	})
}

// RegisterRoutes adds settings routes to the given router
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/logs", h.GetLogSettings).Methods("GET")
	r.HandleFunc("/logs", h.UpdateLogSettings).Methods("PUT")
}

func getRetentionLabel(days int) string {
	switch days {
	case -1:
		return "Unlimited"
	case 0:
		return "Disabled"
	case 1:
		return "1 Day"
	case 14:
		return "14 Days"
	case 30:
		return "30 Days"
	case 90:
		return "90 Days"
	case 365:
		return "365 Days"
	default:
		return strconv.Itoa(days) + " Days"
	}
}
