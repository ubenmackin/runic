// Package settings provides API settings handlers.
package settings

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/gorilla/mux"

	"runic/internal/api/common"
	"runic/internal/common/log"
)

// SettingsStore is defined as an interface here for testability.
type SettingsStore interface {
	GetSystemConfigInt(ctx context.Context, key string, defaultVal int) (int, error)
	GetLogCount(ctx context.Context) (int, error)
	SetSystemConfig(ctx context.Context, key, value string) error
	ClearAllLogs(ctx context.Context) (int64, error)
	GetNullableSystemConfig(ctx context.Context, key string) (string, error)
}

type Handler struct {
	Store      SettingsStore
	logsDBPath string
}

func NewHandler(s SettingsStore, logsDBPath string) *Handler {
	return &Handler{Store: s, logsDBPath: logsDBPath}
}

type LogSettings struct {
	RetentionDays   int    `json:"retention_days"`
	RetentionLabel  string `json:"retention_label"`
	LogCount        int    `json:"log_count"`
	EstimatedSizeMB int    `json:"estimated_size_mb"`
	LogsDBPath      string `json:"logs_db_path"`
}

func (h *Handler) GetLogSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	retentionDays, err := h.Store.GetSystemConfigInt(ctx, "log_retention_days", 30)
	if err != nil {
		log.ErrorContext(ctx, "Failed to get log_retention_days", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get log settings")
		return
	}

	logCount, err := h.Store.GetLogCount(ctx)
	if err != nil {
		log.WarnContext(ctx, "Failed to count logs", "error", err)
		logCount = 0
	}

	estimatedSizeMB := (logCount * 500) / (1024 * 1024)

	common.RespondJSON(w, http.StatusOK, LogSettings{
		RetentionDays:   retentionDays,
		RetentionLabel:  getRetentionLabel(retentionDays),
		LogCount:        logCount,
		EstimatedSizeMB: estimatedSizeMB,
		LogsDBPath:      h.logsDBPath,
	})
}

func (h *Handler) UpdateLogSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.RetentionDays < -1 || req.RetentionDays > 9999 {
		common.RespondError(w, http.StatusBadRequest, "retention_days must be -1 (unlimited), 0 (disabled), or 1-9999")
		return
	}

	if err := h.Store.SetSystemConfig(ctx, "log_retention_days", strconv.Itoa(req.RetentionDays)); err != nil {
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

func (h *Handler) ClearAllLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	deleted, err := h.Store.ClearAllLogs(ctx)
	if err != nil {
		log.ErrorContext(ctx, "Failed to clear logs", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to clear logs")
		return
	}

	log.InfoContext(ctx, "Cleared all logs", "count", deleted)
	common.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"deleted": deleted,
	})
}

func (h *Handler) GetInstanceSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	instanceURL, err := h.Store.GetNullableSystemConfig(ctx, "instance_url")
	if err != nil {
		log.ErrorContext(ctx, "Failed to get instance_url", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to get instance settings")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"url": instanceURL})
}

func (h *Handler) UpdateInstanceSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

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

	if err := h.Store.SetSystemConfig(ctx, "instance_url", req.URL); err != nil {
		log.ErrorContext(ctx, "Failed to update instance settings", "error", err)
		common.RespondError(w, http.StatusInternalServerError, "failed to update instance settings")
		return
	}

	common.RespondJSON(w, http.StatusOK, map[string]string{"url": req.URL})
}

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
