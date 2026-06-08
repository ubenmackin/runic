package transport

import (
	"context"
	"fmt"

	"runic/internal/common"
	"runic/internal/common/log"
)

type BackupRequest struct {
	IPTablesBackup string `json:"iptables_backup"`
	IPSetList      string `json:"ipset_list"`
}

func PostBackup(ctx context.Context, client common.HTTPClient, controlPlaneURL, hostID, token, version string, backupContent, ipsetContent string) error {
	body := BackupRequest{
		IPTablesBackup: backupContent,
		IPSetList:      ipsetContent,
	}

	url := fmt.Sprintf("%s/api/v1/agent/backup/%s", controlPlaneURL, hostID)

	resp, err := common.DoJSONRequest(ctx, client, "POST", url, body, token, "runic-agent/"+version)
	if err != nil {
		return fmt.Errorf("post backup: %w", err)
	}
	_ = resp.Body.Close()

	log.Info("Backup posted to control plane", "host_id", hostID)
	return nil
}
