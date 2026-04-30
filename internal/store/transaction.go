// Package store provides data access layer for groups, policies, and transactions.
package store

import (
	"context"
	"database/sql"
	"fmt"

	"runic/internal/db"
)

// RunInTx executes a function within a transaction. It abstracts the boilerplate of
// beginning the transaction, rolling back on error, and committing on success.
func RunInTx(ctx context.Context, database db.Beginner, fn func(tx *sql.Tx) error) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}

	// Always defer a rollback. If the transaction was already committed,
	// Rollback returns sql.ErrTxDone and we ignore it.
	defer func() {
		_ = tx.Rollback()
	}()

	if err := fn(tx); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}

	return nil
}
