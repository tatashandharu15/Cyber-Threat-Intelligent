// Package store is the User service's data-access layer over the core_platform
// identity tables (owned by the Auth service) plus the user_directory_linkages
// table this service owns. All tenant-scoped reads and writes run inside
// DB.WithTenant so the RLS tenant_isolation policies apply.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/user-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Sentinel errors returned by the store and mapped to HTTP responses by the API
// layer (via the service layer).
var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a write violates a uniqueness constraint, such as
	// creating a user with a duplicate email within a tenant.
	ErrConflict = errors.New("conflict")
)

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the user-directory schema migrations. The migrations table is
// distinct from the Auth service's so each service tracks its own DDL history.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "core_platform.schema_migrations_user")
}

// ListUsers returns a page of users within the tenant ordered by email.
func (s *Store) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]domain.User, error) {
	var users []domain.User
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, email, display_name, status, mfa_enabled
			   FROM core_platform.users
			  ORDER BY email
			  LIMIT $1 OFFSET $2`, limit, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u domain.User
			if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.MFAEnabled); err != nil {
				return err
			}
			users = append(users, u)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	return users, nil
}

// GetUser looks up a user by id within the tenant.
func (s *Store) GetUser(ctx context.Context, tenantID, id string) (*domain.User, error) {
	var u domain.User
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, display_name, status, mfa_enabled
			   FROM core_platform.users WHERE id = $1`, id).
			Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.MFAEnabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	return &u, nil
}

// CreateUser inserts a new user within the tenant and returns it. A duplicate email
// within the tenant surfaces as ErrConflict.
func (s *Store) CreateUser(ctx context.Context, tenantID, email, displayName, passwordHash, status string) (*domain.User, error) {
	var u domain.User
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO core_platform.users (tenant_id, email, display_name, password_hash, status)
			 VALUES ($1, $2, $3, $4, $5)
			 RETURNING id, tenant_id, email, display_name, status, mfa_enabled`,
			tenantID, email, displayName, passwordHash, status).
			Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.MFAEnabled)
	})
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}
	return &u, nil
}

// UpdateUser updates the display name and status of a user within the tenant.
func (s *Store) UpdateUser(ctx context.Context, tenantID, id, displayName, status string) (*domain.User, error) {
	var u domain.User
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`UPDATE core_platform.users
			    SET display_name = $2, status = $3
			  WHERE id = $1
			 RETURNING id, tenant_id, email, display_name, status, mfa_enabled`,
			id, displayName, status).
			Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.MFAEnabled)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}
	return &u, nil
}

// AssignRole grants a role to a user within the tenant. It is idempotent.
func (s *Store) AssignRole(ctx context.Context, tenantID, userID, roleID string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO core_platform.user_roles (user_id, role_id, tenant_id)
			 VALUES ($1, $2, $3)
			 ON CONFLICT (user_id, role_id) DO NOTHING`,
			userID, roleID, tenantID)
		return err
	})
}

// RemoveRole revokes a role from a user within the tenant. It is idempotent.
func (s *Store) RemoveRole(ctx context.Context, tenantID, userID, roleID string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM core_platform.user_roles WHERE user_id = $1 AND role_id = $2`,
			userID, roleID)
		return err
	})
}

// ListRolesForUser returns the role names assigned to a user within the tenant.
func (s *Store) ListRolesForUser(ctx context.Context, tenantID, userID string) ([]string, error) {
	var names []string
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT r.name
			   FROM core_platform.user_roles ur
			   JOIN core_platform.roles r ON r.id = ur.role_id
			  WHERE ur.user_id = $1
			  ORDER BY r.name`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				return err
			}
			names = append(names, name)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list roles for user: %w", err)
	}
	return names, nil
}

// GetDirectoryLinkage returns the directory linkage for a user within the tenant,
// or ErrNotFound if none exists.
func (s *Store) GetDirectoryLinkage(ctx context.Context, tenantID, userID string) (*domain.DirectoryLinkage, error) {
	var l domain.DirectoryLinkage
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, user_id, directory_type, directory_ref, status
			   FROM core_platform.user_directory_linkages WHERE user_id = $1`, userID).
			Scan(&l.ID, &l.TenantID, &l.UserID, &l.DirectoryType, &l.DirectoryRef, &l.Status)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get directory linkage: %w", err)
	}
	return &l, nil
}

// UpsertDirectoryLinkage creates or replaces the directory linkage for a user within
// the tenant. A user has at most one linkage, so an existing one is updated in place.
func (s *Store) UpsertDirectoryLinkage(ctx context.Context, tenantID, userID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	var l domain.DirectoryLinkage
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE core_platform.user_directory_linkages
			    SET directory_type = $3, directory_ref = $4
			  WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID, dirType, dirRef)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return tx.QueryRow(ctx,
				`INSERT INTO core_platform.user_directory_linkages (tenant_id, user_id, directory_type, directory_ref)
				 VALUES ($1, $2, $3, $4)
				 RETURNING id, tenant_id, user_id, directory_type, directory_ref, status`,
				tenantID, userID, dirType, dirRef).
				Scan(&l.ID, &l.TenantID, &l.UserID, &l.DirectoryType, &l.DirectoryRef, &l.Status)
		}
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, user_id, directory_type, directory_ref, status
			   FROM core_platform.user_directory_linkages WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID).
			Scan(&l.ID, &l.TenantID, &l.UserID, &l.DirectoryType, &l.DirectoryRef, &l.Status)
	})
	if err != nil {
		return nil, fmt.Errorf("upsert directory linkage: %w", err)
	}
	return &l, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
