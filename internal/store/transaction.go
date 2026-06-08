// Package store provides data access layer for groups, policies, and transactions.
package store

import (
	"context"
	"database/sql"
	"fmt"

	ic "runic/internal/common"
	"runic/internal/db"
)

// execUpdate executes an UPDATE statement and returns notFoundErr if no rows were affected.
// The querier can be a *sql.Tx (for transactional use) or a db.DB (for direct use).
func execUpdate(ctx context.Context, q db.Querier, query string, notFoundErr error, args ...interface{}) error {
	result, err := q.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("exec update: %w", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return notFoundErr
	}
	return nil
}

// softDelete marks an entity as pending-delete in the specified table.
// Returns notFoundErr if the entity does not exist or is already soft-deleted.
// Returns an error if the table is not in the db allowedTables safelist.
func softDelete(ctx context.Context, q db.Querier, table string, id int, notFoundErr error) error {
	if !db.IsAllowedTable(table) {
		return fmt.Errorf("softDelete: table %q not in safelist", table)
	}
	query := fmt.Sprintf("UPDATE %s SET is_pending_delete = 1 WHERE id = ? AND is_pending_delete = 0", table)
	return execUpdate(ctx, q, query, notFoundErr, id)
}

// getNameByID returns the name column value for a given table and ID.
// whereSuffix is appended to the WHERE clause (e.g. " AND is_pending_delete = 0").
// errLabel is used in the error message (e.g. "group" → "get group name by id").
func getNameByID(ctx context.Context, q db.Querier, table string, id int, whereSuffix, errLabel string) (string, error) {
	var name string
	err := q.QueryRowContext(ctx, "SELECT name FROM "+table+" WHERE id = ?"+whereSuffix, id).Scan(&name)
	if err != nil {
		return "", fmt.Errorf("get %s name by id: %w", errLabel, err)
	}
	return name, nil
}

// queryRows executes a query, iterates rows with a scan function, checks rows.Err(),
// and returns an EnsureSlice'd result. This eliminates the repetitive query→defer→loop→rows.Err()
// boilerplate pattern.
func queryRows[T any](ctx context.Context, q db.Querier, query string, args []interface{}, errLabel string, scanFn func(rows *sql.Rows) (T, error)) ([]T, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query %s: %w", errLabel, err)
	}
	defer func() { _ = rows.Close() }()

	var results []T
	for rows.Next() {
		item, err := scanFn(rows)
		if err != nil {
			return nil, fmt.Errorf("scan %s: %w", errLabel, err)
		}
		results = append(results, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows error %s: %w", errLabel, err)
	}
	return ic.EnsureSlice(results), nil
}

// RunInTx is a thin shim over db.RunInTx that adapts the (ctx, tx) callback
// signature to (tx). The canonical helper lives in internal/db to ensure
// all packages share the same transaction lifecycle and rollback error
// handling. Kept for backward compatibility with the (tx) signature used
// throughout internal/api and internal/store.
func RunInTx(ctx context.Context, database db.Beginner, fn func(tx *sql.Tx) error) error {
	return db.RunInTx(ctx, database, func(ctx context.Context, tx *sql.Tx) error {
		return fn(tx)
	})
}
