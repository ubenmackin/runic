package db

import (
	"context"
	"database/sql"
)

// Querier is the interface for database operations.
// *sql.DB and *sql.Tx both satisfy this interface.
type Querier interface {
	// Context variants (modern, preferred)
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)

	// Non-context variants (for legacy code)
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// Beginner is the interface for database types that can start transactions.
// Handlers that need transactions should accept this interface (or both Querier and Beginner).
type Beginner interface {
	BeginTx(ctx context.Context, opts *sql.TxOptions) (*sql.Tx, error)
}

// DB is the combined interface for both querying and transactions.
// *sql.DB satisfies this interface.
type DB interface {
	Querier
	Beginner
}
