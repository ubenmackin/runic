package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"runic/internal/common"
	"runic/internal/common/log"
)

// BackupRequest represents the backup data sent from agent to server.
type BackupRequest struct {
	IPTablesBackup string `json:"iptables_backup"`
	IPSetList      string `json:"ipset_list"`
}

// PostBackup sends the iptables backup and ipset data to the control plane.
func PostBackup(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, backupContent, ipsetContent string) error {
	body := BackupRequest{
		IPTablesBackup: backupContent,
		IPSetList:      ipsetContent,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal backup request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/agent/backup/%s", controlPlaneURL, hostID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create backup request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "runic-agent/"+version)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("post backup: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return &common.HTTPStatusError{StatusCode: resp.StatusCode, Method: "POST", URL: url}
	}

	log.Info("Backup posted to control plane", "host_id", hostID)
	return nil
}
