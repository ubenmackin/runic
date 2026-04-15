package db

import (
	"context"
	"fmt"
)

// PushJob represents an async push-all-rules job.
type PushJob struct {
	ID          string
	InitiatedBy string
	TotalPeers  int
	Succeeded   int
	Failed      int
	Status      string
	CreatedAt   string
	CompletedAt string
}

// PushJobPeer tracks per-peer status within a push job.
type PushJobPeer struct {
	PeerID       int
	Hostname     string
	Status       string
	ErrorMessage string
}

// CreatePushJob inserts a new push job record.
func CreatePushJob(ctx context.Context, database Querier, jobID, initiatedBy string, totalPeers int) error {
	_, err := database.ExecContext(ctx, `
		INSERT INTO push_jobs (id, initiated_by, total_peers, succeeded_count, failed_count, status)
		VALUES (?, ?, ?, 0, 0, 'pending')
	`, jobID, initiatedBy, totalPeers)
	if err != nil {
		return fmt.Errorf("create push job %s: %w", jobID, err)
	}
	return nil
}

// CreatePushJobPeersT is the transaction-based version that requires DB (Beginner+Querier).
func CreatePushJobPeersT(ctx context.Context, database DB, jobID string, peers []struct {
	ID       int
	Hostname string
}) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin push job peers tx: %w", err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			fmt.Printf("rollback err: %v\n", err)
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO push_job_peers (job_id, peer_id, peer_hostname, status)
		VALUES (?, ?, ?, 'pending')
	`)
	if err != nil {
		return fmt.Errorf("prepare push job peers stmt: %w", err)
	}
	defer func() {
		if cErr := stmt.Close(); cErr != nil {
			fmt.Printf("close stmt failed: %v", cErr)
		}
	}()

	for _, p := range peers {
		if _, err := stmt.ExecContext(ctx, jobID, p.ID, p.Hostname); err != nil {
			return fmt.Errorf("insert push job peer %d: %w", p.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit push job peers tx: %w", err)
	}
	return nil
}

// GetPushJob fetches a single push job by ID.
func GetPushJob(ctx context.Context, database Querier, jobID string) (PushJob, error) {
	var job PushJob
	err := database.QueryRowContext(ctx, `
		SELECT id, initiated_by, total_peers, succeeded_count, failed_count, status,
		COALESCE(created_at, ''), COALESCE(completed_at, '')
		FROM push_jobs WHERE id = ?
	`, jobID).Scan(&job.ID, &job.InitiatedBy, &job.TotalPeers, &job.Succeeded, &job.Failed,
		&job.Status, &job.CreatedAt, &job.CompletedAt)
	if err != nil {
		return PushJob{}, fmt.Errorf("get push job %s: %w", jobID, err)
	}
	return job, nil
}

// GetPushJobWithPeers fetches a job and all its peer records.
func GetPushJobWithPeers(ctx context.Context, database Querier, jobID string) (PushJob, []PushJobPeer, error) {
	job, err := GetPushJob(ctx, database, jobID)
	if err != nil {
		return PushJob{}, nil, err
	}

	rows, err := database.QueryContext(ctx, `
		SELECT peer_id, peer_hostname, status, COALESCE(error_message, '')
		FROM push_job_peers WHERE job_id = ?
	`, jobID)
	if err != nil {
		return PushJob{}, nil, fmt.Errorf("query push job peers for %s: %w", jobID, err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			fmt.Printf("close err: %v\n", err)
		}
	}()

	var peers []PushJobPeer
	for rows.Next() {
		var p PushJobPeer
		if err := rows.Scan(&p.PeerID, &p.Hostname, &p.Status, &p.ErrorMessage); err != nil {
			return PushJob{}, nil, fmt.Errorf("scan push job peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		return PushJob{}, nil, fmt.Errorf("iterate push job peers: %w", err)
	}

	return job, peers, nil
}

// UpdatePushJobStatus updates just the status field of a push job.
func UpdatePushJobStatus(ctx context.Context, database Querier, jobID, status string) error {
	_, err := database.ExecContext(ctx,
		"UPDATE push_jobs SET status = ? WHERE id = ?",
		status, jobID)
	if err != nil {
		return fmt.Errorf("update push job %s status to %s: %w", jobID, status, err)
	}
	return nil
}

// FinalizePushJob sets completed_at and updates the final status based on counts.
// If failed_count > 0, status becomes 'completed_with_errors'; otherwise 'completed'.
func FinalizePushJob(ctx context.Context, database Querier, jobID string) error {
	_, err := database.ExecContext(ctx, `
		UPDATE push_jobs
		SET completed_at = CURRENT_TIMESTAMP,
		status = CASE WHEN failed_count > 0 THEN 'completed_with_errors' ELSE 'completed' END
		WHERE id = ?
	`, jobID)
	if err != nil {
		return fmt.Errorf("finalize push job %s: %w", jobID, err)
	}
	return nil
}

// FinalizePushJobWithCounts atomically updates counts and finalizes the job.
// This combines FinalizePushJob into a single UPDATE to prevent stale counts
// if the process crashes between the two calls.
func FinalizePushJobWithCounts(ctx context.Context, database Querier, jobID string, succeeded, failed int) error {
	_, err := database.ExecContext(ctx, `
		UPDATE push_jobs
		SET completed_at = CURRENT_TIMESTAMP,
		status = CASE WHEN ? > 0 THEN 'completed_with_errors' ELSE 'completed' END,
		succeeded_count = ?,
		failed_count = ?
		WHERE id = ?
	`, failed, succeeded, failed, jobID)
	if err != nil {
		return fmt.Errorf("finalize push job %s with counts: %w", jobID, err)
	}
	return nil
}

// UpdatePushJobPeerStatus updates a single peer's status in the job.
// If errMsg is empty, error_message is set to NULL.
func UpdatePushJobPeerStatus(ctx context.Context, database Querier, jobID string, peerID int, status string, errMsg string) error {
	var err error
	if errMsg == "" {
		_, err = database.ExecContext(ctx, `
			UPDATE push_job_peers SET status = ?, error_message = NULL WHERE job_id = ? AND peer_id = ?
		`, status, jobID, peerID)
	} else {
		_, err = database.ExecContext(ctx, `
			UPDATE push_job_peers SET status = ?, error_message = ? WHERE job_id = ? AND peer_id = ?
		`, status, errMsg, jobID, peerID)
	}
	if err != nil {
		return fmt.Errorf("update push job peer %d status to %s: %w", peerID, status, err)
	}
	return nil
}
