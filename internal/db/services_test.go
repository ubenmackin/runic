package db

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGetService(t *testing.T) {
	db, cleanup := SetupTestDB(t)
	defer cleanup()

	ctx := context.Background()

	// Insert test service with all fields
	_, err := db.Exec(`
		INSERT INTO services (name, ports, source_ports, protocol, description, direction_hint, is_system, no_conntrack)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, "http", "80,443", "1024:65535", "tcp", "HTTP and HTTPS", "ingress", 1, 0)
	if err != nil {
		t.Fatalf("failed to insert test service: %v", err)
	}

	tests := []struct {
		name      string
		serviceID int
		wantErr   error
	}{
		{
			name:      "successfully fetch existing service",
			serviceID: 1,
			wantErr:   nil,
		},
		{
			name:      "return error for non-existent service",
			serviceID: 999,
			wantErr:   sql.ErrNoRows,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := GetService(ctx, db, tt.serviceID)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify all fields for success case
			if tt.serviceID == 1 {
				if svc.ID != 1 {
					t.Errorf("expected ID 1, got %d", svc.ID)
				}
				if svc.Name != "http" {
					t.Errorf("expected Name 'http', got %q", svc.Name)
				}
				if svc.Ports != "80,443" {
					t.Errorf("expected Ports '80,443', got %q", svc.Ports)
				}
				if svc.SourcePorts != "1024:65535" {
					t.Errorf("expected SourcePorts '1024:65535', got %q", svc.SourcePorts)
				}
				if svc.Protocol != "tcp" {
					t.Errorf("expected Protocol 'tcp', got %q", svc.Protocol)
				}
				if svc.Description != "HTTP and HTTPS" {
					t.Errorf("expected Description 'HTTP and HTTPS', got %q", svc.Description)
				}
				if svc.DirectionHint != "ingress" {
					t.Errorf("expected DirectionHint 'ingress', got %q", svc.DirectionHint)
				}
				if !svc.IsSystem {
					t.Errorf("expected IsSystem true, got %v", svc.IsSystem)
				}
			}
		})
	}
}
