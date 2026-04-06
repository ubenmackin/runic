package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestCreatePushJob(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		jobID       string
		initiatedBy string
		totalPeers  int
		wantErr     error
		checkJob    func(*testing.T, PushJob)
	}{
		{
			name:        "successfully create push job with pending status",
			jobID:       "job-001",
			initiatedBy: "admin",
			totalPeers:  5,
			wantErr:     nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.ID != "job-001" {
					t.Errorf("expected ID 'job-001', got %s", job.ID)
				}
				if job.InitiatedBy != "admin" {
					t.Errorf("expected InitiatedBy 'admin', got %s", job.InitiatedBy)
				}
				if job.TotalPeers != 5 {
					t.Errorf("expected TotalPeers 5, got %d", job.TotalPeers)
				}
				if job.Status != "pending" {
					t.Errorf("expected status 'pending', got %s", job.Status)
				}
				if job.Succeeded != 0 {
					t.Errorf("expected Succeeded 0, got %d", job.Succeeded)
				}
				if job.Failed != 0 {
					t.Errorf("expected Failed 0, got %d", job.Failed)
				}
			},
		},
		{
			name:        "create push job with zero peers",
			jobID:       "job-002",
			initiatedBy: "system",
			totalPeers:  0,
			wantErr:     nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.TotalPeers != 0 {
					t.Errorf("expected TotalPeers 0, got %d", job.TotalPeers)
				}
			},
		},
		{
			name:        "create push job with large peer count",
			jobID:       "job-003",
			initiatedBy: "admin",
			totalPeers:  1000,
			wantErr:     nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.TotalPeers != 1000 {
					t.Errorf("expected TotalPeers 1000, got %d", job.TotalPeers)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreatePushJob(ctx, db, tt.jobID, tt.initiatedBy, tt.totalPeers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify job was created correctly
			job, err := GetPushJob(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job: %v", err)
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestCreatePushJobPeersT(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// First create a push job
	jobID := "job-peers-001"
	if err := CreatePushJob(ctx, db, jobID, "admin", 3); err != nil {
		t.Fatalf("failed to create push job: %v", err)
	}

	// Create peer records in the peers table (required for FK constraint)
	_, err := db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-1.example.com", "192.168.1.10", "linux", "x86_64", true, "key1", "hmac1", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 1: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-2.example.com", "192.168.1.20", "linux", "x86_64", true, "key2", "hmac2", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 2: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-3.example.com", "192.168.1.30", "linux", "x86_64", true, "key3", "hmac3", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 3: %v", err)
	}

	// Create job for empty peer list test case
	if err := CreatePushJob(ctx, db, "job-empty-peers", "admin", 0); err != nil {
		t.Fatalf("failed to create empty peer job: %v", err)
	}

	tests := []struct {
		name  string
		jobID string
		peers []struct {
			ID       int
			Hostname string
		}
		wantErr    error
		checkPeers func(*testing.T, []PushJobPeer)
	}{
		{
			name:  "successfully insert multiple peer records",
			jobID: jobID,
			peers: []struct {
				ID       int
				Hostname string
			}{
				{ID: 1, Hostname: "peer-1.example.com"},
				{ID: 2, Hostname: "peer-2.example.com"},
				{ID: 3, Hostname: "peer-3.example.com"},
			},
			wantErr: nil,
			checkPeers: func(t *testing.T, peers []PushJobPeer) {
				if len(peers) != 3 {
					t.Errorf("expected 3 peers, got %d", len(peers))
				}
				for i, p := range peers {
					if p.Status != "pending" {
						t.Errorf("peer %d: expected status 'pending', got %s", i, p.Status)
					}
					if p.PeerID != i+1 {
						t.Errorf("peer %d: expected ID %d, got %d", i, i+1, p.PeerID)
					}
				}
			},
		},
		{
			name:  "insert empty peer list",
			jobID: "job-empty-peers",
			peers: []struct {
				ID       int
				Hostname string
			}{},
			wantErr: nil,
			checkPeers: func(t *testing.T, peers []PushJobPeer) {
				if len(peers) != 0 {
					t.Errorf("expected 0 peers, got %d", len(peers))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreatePushJobPeersT(ctx, db, tt.jobID, tt.peers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify peers were inserted
			_, peers, err := GetPushJobWithPeers(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job with peers: %v", err)
			}

			if tt.checkPeers != nil {
				tt.checkPeers(t, peers)
			}
		})
	}
}

func TestCreatePushJobPeersT_Rollback(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test that transaction rolls back on failure by using an invalid job_id
	// that doesn't exist (foreign key constraint would fail)
	invalidPeers := []struct {
		ID       int
		Hostname string
	}{
		{ID: 1, Hostname: "peer-fail"},
	}

	// This should fail because there's no push_job with this ID
	err := CreatePushJobPeersT(ctx, db, "non-existent-job", invalidPeers)
	if err == nil {
		t.Error("expected error due to foreign key constraint, got nil")
	}

	// Verify no peer records were inserted
	rows, err := db.QueryContext(ctx, "SELECT COUNT(*) FROM push_job_peers")
	if err != nil {
		t.Fatalf("failed to query: %v", err)
	}
	defer rows.Close()

	var count int
	if rows.Next() {
		if err := rows.Scan(&count); err != nil {
			t.Fatalf("failed to scan: %v", err)
		}
	}
	if count != 0 {
		t.Errorf("expected 0 peer records after rollback, got %d", count)
	}
}

func TestGetPushJob(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create test job
	if err := CreatePushJob(ctx, db, "get-job-001", "admin", 5); err != nil {
		t.Fatalf("failed to create test job: %v", err)
	}

	tests := []struct {
		name     string
		jobID    string
		wantErr  error
		checkJob func(*testing.T, PushJob)
	}{
		{
			name:    "successfully fetch existing job",
			jobID:   "get-job-001",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.ID != "get-job-001" {
					t.Errorf("expected ID 'get-job-001', got %s", job.ID)
				}
				if job.TotalPeers != 5 {
					t.Errorf("expected TotalPeers 5, got %d", job.TotalPeers)
				}
			},
		},
		{
			name:    "return error for non-existent job",
			jobID:   "non-existent-job",
			wantErr: sql.ErrNoRows,
			checkJob: func(t *testing.T, job PushJob) {
				// Empty struct returned
				if job.ID != "" {
					t.Errorf("expected empty job, got ID %s", job.ID)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job, err := GetPushJob(ctx, db, tt.jobID)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestGetPushJobWithPeers(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create test job with peers
	jobID := "get-job-peers-001"
	if err := CreatePushJob(ctx, db, jobID, "admin", 3); err != nil {
		t.Fatalf("failed to create test job: %v", err)
	}

	// Create peers in the database (required for FK)
	_, err := db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"node-10.local", "192.168.1.10", "linux", "x86_64", true, "key10", "hmac10", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 10: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"node-20.local", "192.168.1.20", "linux", "x86_64", true, "key20", "hmac20", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 20: %v", err)
	}

	// Use peer IDs 1 and 2 (auto-incremented from inserts above)
	peers := []struct {
		ID       int
		Hostname string
	}{
		{ID: 1, Hostname: "node-10.local"},
		{ID: 2, Hostname: "node-20.local"},
	}
	if err := CreatePushJobPeersT(ctx, db, jobID, peers); err != nil {
		t.Fatalf("failed to create peer records: %v", err)
	}

	tests := []struct {
		name     string
		jobID    string
		wantErr  error
		checkJob func(*testing.T, PushJob, []PushJobPeer)
	}{
		{
			name:    "fetch job with all peer records",
			jobID:   jobID,
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob, peers []PushJobPeer) {
				if job.ID != jobID {
					t.Errorf("expected job ID %s, got %s", jobID, job.ID)
				}
				if len(peers) != 2 {
					t.Errorf("expected 2 peers, got %d", len(peers))
				}
				// Verify peer IDs are 1 and 2 (auto-incremented)
				if len(peers) > 0 && peers[0].PeerID != 1 {
					t.Errorf("expected first peer ID 1, got %d", peers[0].PeerID)
				}
			},
		},
		{
			name:    "return empty peers slice when no peers",
			jobID:   "job-no-peers",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob, peers []PushJobPeer) {
				if len(peers) != 0 {
					t.Errorf("expected 0 peers, got %d", len(peers))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For "job-no-peers" test case, create the job first
			if tt.jobID == "job-no-peers" {
				if err := CreatePushJob(ctx, db, tt.jobID, "admin", 0); err != nil {
					t.Fatalf("failed to create test job: %v", err)
				}
			}

			job, peers, err := GetPushJobWithPeers(ctx, db, tt.jobID)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job, peers)
			}
		})
	}
}

func TestUpdatePushJobStatus(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create test job
	jobID := "update-status-001"
	if err := CreatePushJob(ctx, db, jobID, "admin", 5); err != nil {
		t.Fatalf("failed to create test job: %v", err)
	}

	tests := []struct {
		name     string
		jobID    string
		status   string
		wantErr  error
		checkJob func(*testing.T, PushJob)
	}{
		{
			name:    "successfully update status to running",
			jobID:   jobID,
			status:  "running",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "running" {
					t.Errorf("expected status 'running', got %s", job.Status)
				}
			},
		},
		{
			name:    "successfully update status to completed",
			jobID:   jobID,
			status:  "completed",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed" {
					t.Errorf("expected status 'completed', got %s", job.Status)
				}
			},
		},
		{
			name:    "successfully update status to failed",
			jobID:   jobID,
			status:  "failed",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "failed" {
					t.Errorf("expected status 'failed', got %s", job.Status)
				}
			},
		},
		{
			name:    "update non-existent job returns no error (no rows affected)",
			jobID:   "non-existent-job",
			status:  "running",
			wantErr: nil,
			checkJob: func(t *testing.T, job PushJob) {
				// No-op, no error expected
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdatePushJobStatus(ctx, db, tt.jobID, tt.status)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify status was updated
			job, err := GetPushJob(ctx, db, tt.jobID)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("failed to get push job: %v", err)
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestUpdatePushJobCounts(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create test job
	jobID := "update-counts-001"
	if err := CreatePushJob(ctx, db, jobID, "admin", 10); err != nil {
		t.Fatalf("failed to create test job: %v", err)
	}

	tests := []struct {
		name      string
		jobID     string
		succeeded int
		failed    int
		wantErr   error
		checkJob  func(*testing.T, PushJob)
	}{
		{
			name:      "successfully update succeeded and failed counts",
			jobID:     jobID,
			succeeded: 8,
			failed:    2,
			wantErr:   nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Succeeded != 8 {
					t.Errorf("expected Succeeded 8, got %d", job.Succeeded)
				}
				if job.Failed != 2 {
					t.Errorf("expected Failed 2, got %d", job.Failed)
				}
			},
		},
		{
			name:      "update counts to zero",
			jobID:     jobID,
			succeeded: 0,
			failed:    0,
			wantErr:   nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Succeeded != 0 {
					t.Errorf("expected Succeeded 0, got %d", job.Succeeded)
				}
				if job.Failed != 0 {
					t.Errorf("expected Failed 0, got %d", job.Failed)
				}
			},
		},
		{
			name:      "update counts to all succeeded",
			jobID:     jobID,
			succeeded: 10,
			failed:    0,
			wantErr:   nil,
			checkJob: func(t *testing.T, job PushJob) {
				if job.Succeeded != 10 {
					t.Errorf("expected Succeeded 10, got %d", job.Succeeded)
				}
				if job.Failed != 0 {
					t.Errorf("expected Failed 0, got %d", job.Failed)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdatePushJobCounts(ctx, db, tt.jobID, tt.succeeded, tt.failed)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify counts were updated
			job, err := GetPushJob(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job: %v", err)
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestUpdatePushJobPeerStatus(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create test job with peers
	jobID := "update-peer-status-001"
	if err := CreatePushJob(ctx, db, jobID, "admin", 3); err != nil {
		t.Fatalf("failed to create test job: %v", err)
	}

	// Create peers in the database (required for FK)
	_, err := db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-100", "192.168.1.100", "linux", "x86_64", true, "key100", "hmac100", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 100: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-200", "192.168.1.200", "linux", "x86_64", true, "key200", "hmac200", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 200: %v", err)
	}

	// Use peer IDs 1 and 2 (auto-incremented from inserts above)
	peers := []struct {
		ID       int
		Hostname string
	}{
		{ID: 1, Hostname: "peer-100"},
		{ID: 2, Hostname: "peer-200"},
	}
	if err := CreatePushJobPeersT(ctx, db, jobID, peers); err != nil {
		t.Fatalf("failed to create peer records: %v", err)
	}

	tests := []struct {
		name      string
		jobID     string
		peerID    int
		status    string
		errMsg    string
		wantErr   error
		checkPeer func(*testing.T, PushJobPeer)
	}{
		{
			name:    "successfully update peer status without error message",
			jobID:   jobID,
			peerID:  1,
			status:  "applied",
			errMsg:  "",
			wantErr: nil,
			checkPeer: func(t *testing.T, p PushJobPeer) {
				if p.Status != "applied" {
					t.Errorf("expected status 'applied', got %s", p.Status)
				}
				if p.ErrorMessage != "" {
					t.Errorf("expected empty error message, got %s", p.ErrorMessage)
				}
			},
		},
		{
			name:    "successfully update peer status with error message",
			jobID:   jobID,
			peerID:  2,
			status:  "failed",
			errMsg:  "connection refused",
			wantErr: nil,
			checkPeer: func(t *testing.T, p PushJobPeer) {
				if p.Status != "failed" {
					t.Errorf("expected status 'failed', got %s", p.Status)
				}
				if p.ErrorMessage != "connection refused" {
					t.Errorf("expected error message 'connection refused', got %s", p.ErrorMessage)
				}
			},
		},
		{
			name:    "clear error message when errMsg is empty",
			jobID:   jobID,
			peerID:  2,
			status:  "applied",
			errMsg:  "",
			wantErr: nil,
			checkPeer: func(t *testing.T, p PushJobPeer) {
				if p.Status != "applied" {
					t.Errorf("expected status 'applied', got %s", p.Status)
				}
				if p.ErrorMessage != "" {
					t.Errorf("expected empty error message, got %s", p.ErrorMessage)
				}
			},
		},
		{
			name:    "update non-existent peer returns no error",
			jobID:   jobID,
			peerID:  999,
			status:  "applied",
			errMsg:  "",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := UpdatePushJobPeerStatus(ctx, db, tt.jobID, tt.peerID, tt.status, tt.errMsg)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify peer status was updated
			_, peers, err := GetPushJobWithPeers(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job with peers: %v", err)
			}

			var foundPeer *PushJobPeer
			for i := range peers {
				if peers[i].PeerID == tt.peerID {
					foundPeer = &peers[i]
					break
				}
			}

			if tt.checkPeer != nil && foundPeer != nil {
				tt.checkPeer(t, *foundPeer)
			}
		})
	}
}

func TestFinalizePushJob(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		jobID       string
		setupCounts func(*testing.T, *sql.DB, string, int, int)
		wantStatus  string
		checkJob    func(*testing.T, PushJob)
	}{
		{
			name:        "sets completed_at timestamp and status to completed when failed_count = 0",
			jobID:       "finalize-001",
			setupCounts: func(t *testing.T, db *sql.DB, jobID string, succeeded, failed int) {},
			wantStatus:  "completed",
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed" {
					t.Errorf("expected status 'completed', got %s", job.Status)
				}
				if job.CompletedAt == "" {
					t.Error("expected completed_at to be set")
				}
			},
		},
		{
			name:  "sets status to completed_with_errors when failed_count > 0",
			jobID: "finalize-002",
			setupCounts: func(t *testing.T, db *sql.DB, jobID string, succeeded, failed int) {
				if err := UpdatePushJobCounts(ctx, db, jobID, 8, 2); err != nil {
					t.Fatalf("failed to update counts: %v", err)
				}
			},
			wantStatus: "completed_with_errors",
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed_with_errors" {
					t.Errorf("expected status 'completed_with_errors', got %s", job.Status)
				}
				if job.CompletedAt == "" {
					t.Error("expected completed_at to be set")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create job
			if err := CreatePushJob(ctx, db, tt.jobID, "admin", 10); err != nil {
				t.Fatalf("failed to create test job: %v", err)
			}

			// Setup counts if needed
			if tt.setupCounts != nil {
				tt.setupCounts(t, db, tt.jobID, 10, 0)
			}

			// Finalize the job
			err := FinalizePushJob(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify finalization
			job, err := GetPushJob(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job: %v", err)
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestFinalizePushJobWithCounts(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name       string
		jobID      string
		succeeded  int
		failed     int
		wantStatus string
		checkJob   func(*testing.T, PushJob)
	}{
		{
			name:       "atomically updates counts and finalizes with all succeeded",
			jobID:      "finalize-atomic-001",
			succeeded:  10,
			failed:     0,
			wantStatus: "completed",
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed" {
					t.Errorf("expected status 'completed', got %s", job.Status)
				}
				if job.Succeeded != 10 {
					t.Errorf("expected Succeeded 10, got %d", job.Succeeded)
				}
				if job.Failed != 0 {
					t.Errorf("expected Failed 0, got %d", job.Failed)
				}
				if job.CompletedAt == "" {
					t.Error("expected completed_at to be set")
				}
			},
		},
		{
			name:       "atomically updates counts and finalizes with some failed",
			jobID:      "finalize-atomic-002",
			succeeded:  7,
			failed:     3,
			wantStatus: "completed_with_errors",
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed_with_errors" {
					t.Errorf("expected status 'completed_with_errors', got %s", job.Status)
				}
				if job.Succeeded != 7 {
					t.Errorf("expected Succeeded 7, got %d", job.Succeeded)
				}
				if job.Failed != 3 {
					t.Errorf("expected Failed 3, got %d", job.Failed)
				}
				if job.CompletedAt == "" {
					t.Error("expected completed_at to be set")
				}
			},
		},
		{
			name:       "atomically updates counts to zero",
			jobID:      "finalize-atomic-003",
			succeeded:  0,
			failed:     0,
			wantStatus: "completed",
			checkJob: func(t *testing.T, job PushJob) {
				if job.Status != "completed" {
					t.Errorf("expected status 'completed', got %s", job.Status)
				}
				if job.CompletedAt == "" {
					t.Error("expected completed_at to be set")
				}
			},
		},
		{
			name:       "finalize non-existent job returns no error",
			jobID:      "non-existent-job",
			succeeded:  0,
			failed:     0,
			wantStatus: "",
			checkJob: func(t *testing.T, job PushJob) {
				// No-op, no error expected
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create job if it doesn't start with "non-existent"
			if tt.jobID != "non-existent-job" {
				if err := CreatePushJob(ctx, db, tt.jobID, "admin", 10); err != nil {
					t.Fatalf("failed to create test job: %v", err)
				}
			}

			// Finalize with counts
			err := FinalizePushJobWithCounts(ctx, db, tt.jobID, tt.succeeded, tt.failed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// If job doesn't exist, just return
			if tt.jobID == "non-existent-job" {
				return
			}

			// Verify finalization
			job, err := GetPushJob(ctx, db, tt.jobID)
			if err != nil {
				t.Fatalf("failed to get push job: %v", err)
			}

			if tt.checkJob != nil {
				tt.checkJob(t, job)
			}
		})
	}
}

func TestListPushJobs(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Create multiple test jobs in different order
	jobs := []struct {
		jobID       string
		initiatedBy string
		order       int // Used to control creation order
	}{
		{jobID: "list-job-001", initiatedBy: "admin", order: 1},
		{jobID: "list-job-002", initiatedBy: "system", order: 2},
		{jobID: "list-job-003", initiatedBy: "admin", order: 3},
		{jobID: "list-job-004", initiatedBy: "user", order: 4},
		{jobID: "list-job-005", initiatedBy: "system", order: 5},
	}

	// Create jobs in specific order
	for _, j := range jobs {
		if err := CreatePushJob(ctx, db, j.jobID, j.initiatedBy, 5); err != nil {
			t.Fatalf("failed to create test job %s: %v", j.jobID, err)
		}
	}

	tests := []struct {
		name      string
		limit     int
		wantCount int
		checkJobs func(*testing.T, []PushJob)
	}{
		{
			name:      "return jobs ordered by created_at DESC",
			limit:     10,
			wantCount: 5,
			checkJobs: func(t *testing.T, jobs []PushJob) {
				if len(jobs) != 5 {
					t.Errorf("expected 5 jobs, got %d", len(jobs))
				}
				// Verify order is descending (newest first)
				if len(jobs) >= 2 && jobs[0].CreatedAt < jobs[1].CreatedAt {
					t.Error("expected jobs ordered by created_at DESC")
				}
			},
		},
		{
			name:      "respect limit parameter",
			limit:     3,
			wantCount: 3,
			checkJobs: func(t *testing.T, jobs []PushJob) {
				if len(jobs) != 3 {
					t.Errorf("expected 3 jobs, got %d", len(jobs))
				}
			},
		},
		{
			name:      "limit of zero returns empty",
			limit:     0,
			wantCount: 0,
			checkJobs: func(t *testing.T, jobs []PushJob) {
				if len(jobs) != 0 {
					t.Errorf("expected 0 jobs with limit 0, got %d", len(jobs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobs, err := ListPushJobs(ctx, db, tt.limit)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(jobs) != tt.wantCount {
				t.Errorf("expected %d jobs, got %d", tt.wantCount, len(jobs))
			}

			if tt.checkJobs != nil {
				tt.checkJobs(t, jobs)
			}
		})
	}
}

func TestListPushJobs_EmptyDB(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test on empty database
	jobs, err := ListPushJobs(ctx, db, 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs on empty DB, got %d", len(jobs))
	}
}

func TestPushJobLifecycle(t *testing.T) {
	// Integration test covering the full push job lifecycle
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	jobID := "lifecycle-job-001"

	// 1. Create a new push job
	err := CreatePushJob(ctx, db, jobID, "admin", 5)
	if err != nil {
		t.Fatalf("CreatePushJob failed: %v", err)
	}

	// 2. Verify initial state
	job, err := GetPushJob(ctx, db, jobID)
	if err != nil {
		t.Fatalf("GetPushJob failed: %v", err)
	}
	if job.Status != "pending" {
		t.Errorf("expected initial status 'pending', got %s", job.Status)
	}
	if job.Succeeded != 0 || job.Failed != 0 {
		t.Errorf("expected initial counts (0, 0), got (%d, %d)", job.Succeeded, job.Failed)
	}

	// Create peer records in the database (required for FK)
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-1", "192.168.1.1", "linux", "x86_64", true, "key1", "hmac1", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 1: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-2", "192.168.1.2", "linux", "x86_64", true, "key2", "hmac2", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 2: %v", err)
	}
	_, err = db.Exec(`INSERT INTO peers (hostname, ip_address, os_type, arch, has_docker, agent_key, hmac_key, is_manual, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"peer-3", "192.168.1.3", "linux", "x86_64", true, "key3", "hmac3", 1, "online")
	if err != nil {
		t.Fatalf("failed to create peer 3: %v", err)
	}

	// 3. Add peers to the job
	peers := []struct {
		ID       int
		Hostname string
	}{
		{ID: 1, Hostname: "peer-1"},
		{ID: 2, Hostname: "peer-2"},
		{ID: 3, Hostname: "peer-3"},
	}
	err = CreatePushJobPeersT(ctx, db, jobID, peers)
	if err != nil {
		t.Fatalf("CreatePushJobPeersT failed: %v", err)
	}

	// 4. Verify peers were added
	_, peerList, err := GetPushJobWithPeers(ctx, db, jobID)
	if err != nil {
		t.Fatalf("GetPushJobWithPeers failed: %v", err)
	}
	if len(peerList) != 3 {
		t.Errorf("expected 3 peers, got %d", len(peerList))
	}

	// 5. Update job status to running
	err = UpdatePushJobStatus(ctx, db, jobID, "running")
	if err != nil {
		t.Fatalf("UpdatePushJobStatus failed: %v", err)
	}

	job, _ = GetPushJob(ctx, db, jobID)
	if job.Status != "running" {
		t.Errorf("expected status 'running', got %s", job.Status)
	}

	// 6. Update peer statuses as they complete
	err = UpdatePushJobPeerStatus(ctx, db, jobID, 1, "applied", "")
	if err != nil {
		t.Fatalf("UpdatePushJobPeerStatus failed: %v", err)
	}
	err = UpdatePushJobPeerStatus(ctx, db, jobID, 2, "applied", "")
	if err != nil {
		t.Fatalf("UpdatePushJobPeerStatus failed: %v", err)
	}
	err = UpdatePushJobPeerStatus(ctx, db, jobID, 3, "failed", "timeout")
	if err != nil {
		t.Fatalf("UpdatePushJobPeerStatus failed: %v", err)
	}

	// 7. Finalize the job with counts
	err = FinalizePushJobWithCounts(ctx, db, jobID, 2, 1)
	if err != nil {
		t.Fatalf("FinalizePushJobWithCounts failed: %v", err)
	}

	// 8. Verify final state
	job, err = GetPushJob(ctx, db, jobID)
	if err != nil {
		t.Fatalf("GetPushJob failed: %v", err)
	}
	if job.Status != "completed_with_errors" {
		t.Errorf("expected final status 'completed_with_errors', got %s", job.Status)
	}
	if job.Succeeded != 2 {
		t.Errorf("expected succeeded count 2, got %d", job.Succeeded)
	}
	if job.Failed != 1 {
		t.Errorf("expected failed count 1, got %d", job.Failed)
	}
	if job.CompletedAt == "" {
		t.Error("expected completed_at to be set")
	}

	// 9. List jobs and verify our job is in the list
	jobs, err := ListPushJobs(ctx, db, 10)
	if err != nil {
		t.Fatalf("ListPushJobs failed: %v", err)
	}
	found := false
	for _, j := range jobs {
		if j.ID == jobID {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected job to appear in list")
	}
}
