package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"runic/internal/common"
	"runic/internal/db"
	"runic/internal/models"
)

type UserStore struct {
	db db.Querier
}

func NewUserStore(database db.Querier) *UserStore {
	return &UserStore{db: database}
}

func (s *UserStore) ListUsers(ctx context.Context, page, perPage int) ([]models.UserRow, int, error) {
	// Get total count
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	offset := (page - 1) * perPage
	rows, err := s.db.QueryContext(ctx,
		"SELECT id, username, COALESCE(email, ''), role, created_at FROM users ORDER BY id LIMIT ? OFFSET ?",
		perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("query users: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var users []models.UserRow
	for rows.Next() {
		var u models.UserRow
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows error: %w", err)
	}
	return common.EnsureSlice(users), total, nil
}

func (s *UserStore) GetUserByID(ctx context.Context, id int) (models.UserRow, error) {
	var u models.UserRow
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, COALESCE(email, ''), role, created_at FROM users WHERE id = ?", id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		return u, fmt.Errorf("query user by id: %w", err)
	}
	return u, nil
}

func (s *UserStore) GetUserByUsername(ctx context.Context, username string) (models.UserRow, error) {
	var u models.UserRow
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, COALESCE(email, ''), role, created_at FROM users WHERE username = ?", username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.Role, &u.CreatedAt)
	if err != nil {
		return u, fmt.Errorf("query user by username: %w", err)
	}
	return u, nil
}

// GetCredentials returns the credentials (id, username, password_hash) for
// a user. This must never be exposed directly in an API response.
func (s *UserStore) GetCredentials(ctx context.Context, username string) (models.UserCredentials, error) {
	var c models.UserCredentials
	err := s.db.QueryRowContext(ctx,
		"SELECT id, username, password_hash FROM users WHERE username = ?", username,
	).Scan(&c.ID, &c.Username, &c.PasswordHash)
	if err != nil {
		return c, fmt.Errorf("query credentials: %w", err)
	}
	return c, nil
}

func (s *UserStore) UserExists(ctx context.Context, username string) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx,
		"SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username,
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check user exists: %w", err)
	}
	return exists, nil
}

func (s *UserStore) CountUsers(ctx context.Context) (int, error) {
	return s.CountUsersTx(ctx, s.db)
}

// CountAdmins returns the number of users with the 'admin' role.
func (s *UserStore) CountAdmins(ctx context.Context) (int, error) {
	var count int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM users WHERE role = 'admin'").Scan(&count); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return count, nil
}

// CountUsersTx counts users using the provided Querier (supports transaction usage).
func (s *UserStore) CountUsersTx(ctx context.Context, q db.Querier) (int, error) {
	var count int
	if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

// CreateUser inserts a new user. passwordHash must already be a bcrypt hash.
// The email is normalized (trimmed, lower-cased) via common.NormalizeEmail
// and rejected with common.ErrInvalidEmail when non-empty but malformed, so
// direct store callers get the same guarantees as the API handler layer.
func (s *UserStore) CreateUser(ctx context.Context, q db.Querier, username, passwordHash, email, role string) (int64, error) {
	if q == nil {
		q = s.db
	}
	email = common.NormalizeEmail(email)
	if email != "" && !common.ValidateEmail(email) {
		return 0, fmt.Errorf("create user %w: %q", common.ErrInvalidEmail, email)
	}
	result, err := q.ExecContext(ctx,
		"INSERT INTO users (username, password_hash, email, role) VALUES (?, ?, ?, ?)",
		username, passwordHash, email, role)
	if err != nil {
		return 0, fmt.Errorf("insert user: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("get insert id: %w", err)
	}
	return id, nil
}

// UpdateUserFields specifies which fields to update. Only non-zero / non-empty values are applied to the query.
type UpdateUserFields struct {
	Email        string
	Role         string
	PasswordHash string // pre-hashed; empty = do not update password
}

// UpdateUser updates a user by ID. Returns sql.ErrNoRows if no row was affected.
// A non-empty email is normalized (trimmed, lower-cased) and validated; a
// malformed address fails with common.ErrInvalidEmail. A whitespace-only
// address normalizes to empty and is treated as no update, matching the
// empty-means-untouched convention for the other fields.
func (s *UserStore) UpdateUser(ctx context.Context, id int, fields UpdateUserFields) error {
	var setClauses []string
	var args []interface{}

	if fields.Email != "" {
		fields.Email = common.NormalizeEmail(fields.Email)
		if fields.Email != "" {
			if !common.ValidateEmail(fields.Email) {
				return fmt.Errorf("update user %w: %q", common.ErrInvalidEmail, fields.Email)
			}
			setClauses = append(setClauses, "email = ?")
			args = append(args, fields.Email)
		}
	}
	if fields.Role != "" {
		setClauses = append(setClauses, "role = ?")
		args = append(args, fields.Role)
	}
	if fields.PasswordHash != "" {
		setClauses = append(setClauses, "password_hash = ?")
		args = append(args, fields.PasswordHash)
	}

	if len(setClauses) == 0 {
		return nil // nothing to update
	}

	args = append(args, id)
	query := "UPDATE users SET " + strings.Join(setClauses, ", ") + " WHERE id = ?"

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update user: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// DeleteUser deletes a user by ID. Returns sql.ErrNoRows if no row was affected.
func (s *UserStore) DeleteUser(ctx context.Context, id int) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM users WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return sql.ErrNoRows
	}
	return nil
}
