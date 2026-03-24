package servers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"runic/internal/api/agents"
	"runic/internal/api/common"
	"runic/internal/db"
	"runic/internal/engine"
)

// Server is the JSON representation of a server for API responses.
type Server struct {
	ID        int    `json:"id"`
	Hostname  string `json:"hostname"`
	IP        string `json:"ip_address"`
	HasDocker bool   `json:"has_docker"`
}

func GetServers(w http.ResponseWriter, r *http.Request) {
	if db.DB == nil {
		common.RespondError(w, http.StatusInternalServerError, "database not initialized")
		return
	}
	rows, err := db.DB.QueryContext(r.Context(),
		"SELECT id, hostname, ip_address, has_docker FROM servers")
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, "failed to query servers")
		return
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var s Server
		if err := rows.Scan(&s.ID, &s.Hostname, &s.IP, &s.HasDocker); err != nil {
			common.RespondError(w, http.StatusInternalServerError, "failed to scan server")
			return
		}
		servers = append(servers, s)
	}
	if servers == nil {
		servers = []Server{}
	}
	common.RespondJSON(w, http.StatusOK, servers)
}

func CreateServer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		AgentKey  string `json:"agent_key"`
		HasDocker bool   `json:"has_docker"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		common.RespondError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if input.Hostname == "" || input.IPAddress == "" || input.AgentKey == "" {
		common.RespondError(w, http.StatusBadRequest, "hostname, ip_address, and agent_key are required")
		return
	}

	// Generate HMAC key for the server
	hmacKey := agents.GenerateHMACKey()

	result, err := db.DB.ExecContext(r.Context(),
		`INSERT INTO servers (hostname, ip_address, agent_key, hmac_key, has_docker) VALUES (?, ?, ?, ?, ?)`,
		input.Hostname, input.IPAddress, input.AgentKey, hmacKey, input.HasDocker)
	if err != nil {
		common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create server: %v", err))
		return
	}

	id, _ := result.LastInsertId()
	common.RespondJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// MakeCompileServerHandler injects the Compiler dependency for server rule compilation.
func MakeCompileServerHandler(compiler *engine.Compiler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := common.ParseIDParam(r, "id")
		if err != nil {
			common.RespondError(w, http.StatusBadRequest, "invalid server ID")
			return
		}

		bundle, err := compiler.CompileAndStore(r.Context(), id)
		if err != nil {
			common.RespondError(w, http.StatusInternalServerError, fmt.Sprintf("compilation failed: %v", err))
			return
		}

		common.RespondJSON(w, http.StatusOK, map[string]interface{}{
			"version": bundle.Version,
			"hmac":    bundle.HMAC,
			"size":    len(bundle.RulesContent),
		})
	}
}
