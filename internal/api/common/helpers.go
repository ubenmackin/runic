// Package common provides shared utilities and constants.
package common

import (
	"encoding/json"
	"net"
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
//
// Security-sensitive auth endpoints (login, setup, refresh, logout,
// agent register) do NOT use this helper for rate-limiting decisions:
// they key on RemoteAddrIP and strip these headers at the route level
// (see stripSpoofableProxyHeaders and middleware.StrictMiddleware), so
// header rotation cannot bypass the login sliding window or the
// per-username+per-IP account lockout. This helper remains for
// proxy-compatible, non-auth rate limiting (downloads, etc.) and for
// non-security logging only.
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

// RemoteAddrIP returns the host portion of r.RemoteAddr (stripping any port)
// while ignoring X-Forwarded-For and X-Real-IP entirely. Use this for
// security-sensitive rate limiting (login, setup, refresh, logout, agent
// re-registration) where the headers above are attacker-controlled on direct
// exposure and would let a caller rotate bucket keys per request to bypass
// per-IP limits and per-username+per-IP account lockout. Keying on
// RemoteAddr is spoof-proof at the TCP layer; the trade-off is that clients
// behind a shared reverse proxy share one bucket, which is acceptable for
// rare operations like login/registration (5-10/min).
func RemoteAddrIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		return host
	}
	return r.RemoteAddr
}
