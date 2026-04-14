// Package settings provides API settings handlers.
package settings

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"runic/internal/api/common"
	"runic/internal/common/log"

	"github.com/gorilla/mux"
)

type Handler struct {
	DB         *sql.DB
	LogsDB     *sql.DB
	logsDBPath string
}

func NewHandler(db *sql.DB, logsDB *sql.DB, logsDBPath string) *Handler {
	return &Handler{DB: db, LogsDB: logsDB, logsDBPath: logsDBPath}
}

type LogSettings struct {
	RetentionDays   int    `json:"retention_days"`
	RetentionLabel  string `json:"retention_label"`
	LogCount        int    `json:"log_count"`
	EstimatedSizeMB int    `json:"estimated_size_mb"`
	LogsDBPath      string `json:"logs_db_path"`
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

	// Get log count from logs database
	var logCount int
	if h.LogsDB != nil {
		err = h.LogsDB.QueryRowContext(ctx, "SELECT COUNT(*) FROM firewall_logs").Scan(&logCount)
		if err != nil {
			logCount = 0
		}
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
		LogsDBPath:      h.logsDBPath,
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

	if h.LogsDB == nil {
		log.ErrorContext(ctx, "LogsDB not initialized")
		common.RespondError(w, http.StatusInternalServerError, "logs database not available")
		return
	}

	result, err := h.LogsDB.ExecContext(ctx, "DELETE FROM firewall_logs")
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

// GetInstanceSettings returns the instance URL configuration.
func (h *Handler) GetInstanceSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var instanceURL sql.NullString
	err := h.DB.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = 'instance_url'").Scan(&instanceURL)
	if err != nil && err != sql.ErrNoRows {
		common.RespondError(w, http.StatusInternalServerError, "failed to get instance settings")
		return
	}

	url := ""
	if instanceURL.Valid {
		url = instanceURL.String
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"url": url})
}

// UpdateInstanceSettings updates the instance URL configuration.
func (h *Handler) UpdateInstanceSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate URL format and scheme
	if req.URL != "" {
		parsed, err := url.Parse(req.URL)
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid URL format")
			return
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			common.RespondError(w, http.StatusBadRequest, "URL must use http or https scheme")
			return
		}
		if len(req.URL) > 2048 {
			common.RespondError(w, http.StatusBadRequest, "URL exceeds maximum length of 2048 characters")
			return
		}
	}

	_, err := h.DB.ExecContext(ctx,
		"INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES ('instance_url', ?, CURRENT_TIMESTAMP)",
		req.URL,
	)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to update instance settings")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"url": req.URL})
}

// RegisterRoutes adds settings routes to the given router
func (h *Handler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/logs", h.GetLogSettings).Methods("GET")
	r.HandleFunc("/logs", h.UpdateLogSettings).Methods("PUT")
	r.HandleFunc("/instance", h.GetInstanceSettings).Methods("GET")
	r.HandleFunc("/instance", h.UpdateInstanceSettings).Methods("PUT")
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
