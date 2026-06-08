// Package common provides shared utilities and constants.
package common

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"runic/internal/common/log"
)

func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Error("failed to encode json response", "error", err)
	}
}

func RespondError(w http.ResponseWriter, status int, msg string) {
	RespondJSON(w, status, map[string]string{"error": msg})
}

func ParseIDParam(r *http.Request, name string) (int, error) {
	vars := mux.Vars(r)
	return strconv.Atoi(vars[name])
}

func ParseUintSafe(s string) (uint64, error) {
	return strconv.ParseUint(s, 10, 64)
}

// GetClientIP extracts the client IP from the request, checking the
// X-Forwarded-For header (first entry), then X-Real-IP, and finally
// falling back to r.RemoteAddr. This is used for rate limiting so that
// clients behind a reverse proxy are identified by their true IP.
//
// TODO: trust of X-Forwarded-For / X-Real-IP is unconditional. In
// production deployments where the server is reachable directly from
// untrusted clients (i.e. not behind a reverse proxy that strips these
// headers), an attacker can spoof the header to evade per-IP rate
// limiting or to attribute requests to a victim IP. When a
// trusted-proxies configuration is added to the project, gate the
// header lookups on an allowlist (similar to nginx's
// `set_real_ip_from`); until then we accept the current behavior to
// preserve compatibility with existing reverse-proxy deployments.
func GetClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For may contain multiple IPs; the first is the original client.
		if ip := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0]); ip != "" {
			return ip
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}
	return r.RemoteAddr
}
