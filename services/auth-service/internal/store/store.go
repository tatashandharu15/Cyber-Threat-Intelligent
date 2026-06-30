// Package store is the Auth service's data-access layer over the core_platform
// identity tables. All tenant-scoped reads run inside DB.WithTenant so the RLS
// policies apply.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/auth-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a requested row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the identity schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "core_platform.schema_migrations")
}

// GetTenantBySlug looks up a tenant by its slug. Tenants are not tenant-scoped so
// this runs without a tenant context.
func (s *Store) GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	var t domain.Tenant
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, slug, display_name, status FROM core_platform.tenants WHERE slug = $1`, slug).
			Scan(&t.ID, &t.Slug, &t.DisplayName, &t.Status)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get tenant by slug: %w", err)
	}
	return &t, nil
}

// GetUserByEmail looks up a user within the given tenant.
func (s *Store) GetUserByEmail(ctx context.Context, tenantID, email string) (*domain.User, error) {
	var u domain.User
	var passwordHash, mfaSecret *string
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, display_name, status, password_hash,
			        mfa_enabled, mfa_method, mfa_secret
			   FROM core_platform.users WHERE email = $1`, email).
			Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status,
				&passwordHash, &u.MFAEnabled, &u.MFAMethod, &mfaSecret)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by email: %w", err)
	}
	if passwordHash != nil {
		u.PasswordHash = *passwordHash
	}
	if mfaSecret != nil {
		u.MFASecret = *mfaSecret
	}
	return &u, nil
}

// GetUserByID looks up a user within the given tenant.
func (s *Store) GetUserByID(ctx context.Context, tenantID, userID string) (*domain.User, error) {
	var u domain.User
	var passwordHash, mfaSecret *string
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, email, display_name, status, password_hash,
			        mfa_enabled, mfa_method, mfa_secret
			   FROM core_platform.users WHERE id = $1`, userID).
			Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status,
				&passwordHash, &u.MFAEnabled, &u.MFAMethod, &mfaSecret)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user by id: %w", err)
	}
	if passwordHash != nil {
		u.PasswordHash = *passwordHash
	}
	if mfaSecret != nil {
		u.MFASecret = *mfaSecret
	}
	return &u, nil
}

// GetAuthorization assembles the role names and permission strings granted to a
// user. Permissions are formatted as "resource:action" for the JWT claim.
func (s *Store) GetAuthorization(ctx context.Context, tenantID, userID string) (*domain.Authorization, error) {
	authz := &domain.Authorization{}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		roleRows, err := tx.Query(ctx,
			`SELECT r.name
			   FROM core_platform.user_roles ur
			   JOIN core_platform.roles r ON r.id = ur.role_id
			  WHERE ur.user_id = $1
			  ORDER BY r.name`, userID)
		if err != nil {
			return err
		}
		defer roleRows.Close()
		for roleRows.Next() {
			var name string
			if err := roleRows.Scan(&name); err != nil {
				return err
			}
			authz.Roles = append(authz.Roles, name)
		}
		if err := roleRows.Err(); err != nil {
			return err
		}

		permRows, err := tx.Query(ctx,
			`SELECT DISTINCT p.resource || ':' || p.action AS perm
			   FROM core_platform.user_roles ur
			   JOIN core_platform.role_permissions rp ON rp.role_id = ur.role_id
			   JOIN core_platform.permissions p ON p.id = rp.permission_id
			  WHERE ur.user_id = $1
			  ORDER BY perm`, userID)
		if err != nil {
			return err
		}
		defer permRows.Close()
		for permRows.Next() {
			var perm string
			if err := permRows.Scan(&perm); err != nil {
				return err
			}
			authz.Permissions = append(authz.Permissions, perm)
		}
		return permRows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("get authorization: %w", err)
	}
	return authz, nil
}

// CreateSession persists a new session record for an issued token.
func (s *Store) CreateSession(ctx context.Context, tenantID, userID, jti string, expiresAt time.Time, ip, ua string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var ipArg any
		if ip != "" {
			ipArg = ip
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO core_platform.sessions (tenant_id, user_id, jti, expires_at, ip_address, user_agent)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			tenantID, userID, jti, expiresAt, ipArg, nullify(ua))
		return err
	})
}

// SessionActive reports whether a session with the given jti exists, is not
// revoked, and has not expired.
func (s *Store) SessionActive(ctx context.Context, tenantID, jti string) (bool, error) {
	var active bool
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(
			    SELECT 1 FROM core_platform.sessions
			     WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW())`, jti).
			Scan(&active)
	})
	if err != nil {
		return false, fmt.Errorf("session active: %w", err)
	}
	return active, nil
}

// RevokeSession marks a session revoked. It is idempotent.
func (s *Store) RevokeSession(ctx context.Context, tenantID, jti string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE core_platform.sessions SET revoked_at = NOW()
			  WHERE jti = $1 AND revoked_at IS NULL`, jti)
		return err
	})
}

// TouchLastLogin records a successful authentication time for a user.
func (s *Store) TouchLastLogin(ctx context.Context, tenantID, userID string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE core_platform.users SET last_login_at = NOW() WHERE id = $1`, userID)
		return err
	})
}

func nullify(s string) any {
	if s == "" {
		return nil
	}
	return s
}
