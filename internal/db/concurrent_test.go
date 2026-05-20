package db

import (
	"context"
	"fmt"
	"sync"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrentReads(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Insert test data (agent_key must be unique)
	for i := 1; i <= 50; i++ {
		_, err := database.ExecContext(ctx,
			"INSERT INTO peers (hostname, ip_address, agent_key, hmac_key, is_manual) VALUES (?, ?, ?, ?, 0)",
			fmt.Sprintf("peer-%d", i), fmt.Sprintf("10.0.0.%d", i), fmt.Sprintf("key-%d", i), fmt.Sprintf("hmac-%d", i))
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	// Launch 50 concurrent readers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := database.QueryContext(ctx, "SELECT id, hostname FROM peers")
			if err != nil {
				errCh <- err
				return
			}
			count := 0
			for rows.Next() {
				count++
			}
			rows.Close()
			if count != 50 {
				errCh <- fmt.Errorf("expected 50 rows, got %d", count)
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent read error: %v", err)
	}
}

func TestConcurrentWrites(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	var wg sync.WaitGroup
	errCh := make(chan error, 50)

	// Launch 20 concurrent writers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := database.ExecContext(ctx,
				"INSERT INTO groups (name, description) VALUES (?, ?)",
				fmt.Sprintf("group-concurrent-%d", idx), "concurrent test")
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent write error: %v", err)
	}

	// Verify all rows were inserted
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups WHERE name LIKE 'group-concurrent-%'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 20, count, "All 20 groups should be inserted")
}

func TestConcurrentReadWrite(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Pre-populate some data
	for i := 0; i < 10; i++ {
		_, err := database.ExecContext(ctx,
			"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
			fmt.Sprintf("svc-%d", i), "80", "tcp")
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 60)

	// Concurrent readers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := database.QueryContext(ctx, "SELECT id, name FROM services")
			if err != nil {
				errCh <- err
				return
			}
			for rows.Next() {
				// drain rows
			}
			rows.Close()
		}()
	}

	// Concurrent writers
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := database.ExecContext(ctx,
				"INSERT INTO services (name, ports, protocol) VALUES (?, ?, ?)",
				fmt.Sprintf("concurrent-svc-%d", idx), "443", "tcp")
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	// Concurrent updaters
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := database.ExecContext(ctx,
				"UPDATE services SET ports = ? WHERE id = ?",
				"8080", (idx%10)+1)
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent read/write error: %v", err)
	}

	// Verify data integrity: all services should still exist
	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM services").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 30, count, "Expected 10 original + 20 concurrent services = 30")
}

func TestConcurrentTransactions(t *testing.T) {
	database, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	// Launch concurrent transactions that each insert a group
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tx, err := database.BeginTx(ctx, nil)
			if err != nil {
				errCh <- err
				return
			}

			_, err = tx.ExecContext(ctx,
				"INSERT INTO groups (name, description) VALUES (?, ?)",
				fmt.Sprintf("tx-group-%d", idx), "transactional test")
			if err != nil {
				errCh <- err
				tx.Rollback()
				return
			}

			if err := tx.Commit(); err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent transaction error: %v", err)
	}

	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups WHERE name LIKE 'tx-group-%'").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 20, count, "All 20 transactional groups should be committed")
}

func TestConcurrentDBWrapperOperations(t *testing.T) {
	rawDB, cleanup := SetupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	database := New(rawDB)

	// Pre-populate
	for i := 0; i < 10; i++ {
		_, err := database.ExecContext(ctx,
			"INSERT INTO groups (name) VALUES (?)", fmt.Sprintf("wrapper-group-%d", i))
		require.NoError(t, err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 40)

	// Concurrent reads through wrapper
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, err := database.QueryContext(ctx, "SELECT id, name FROM groups")
			if err != nil {
				errCh <- err
				return
			}
			for rows.Next() {
			}
			rows.Close()
		}()
	}

	// Concurrent writes through wrapper
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := database.ExecContext(ctx,
				"INSERT INTO groups (name) VALUES (?)",
				fmt.Sprintf("concurrent-wrapper-%d", idx))
			if err != nil {
				errCh <- err
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Errorf("concurrent wrapper operation error: %v", err)
	}

	var count int
	err := database.QueryRowContext(ctx, "SELECT COUNT(*) FROM groups").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 30, count, "Expected 10 original + 20 concurrent = 30 groups")
}
