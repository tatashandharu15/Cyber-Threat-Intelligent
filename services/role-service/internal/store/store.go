// Package store is the Role service's data-access layer over the core_platform
// identity tables (roles, permissions, role_permissions, user_roles) owned by
// the Auth service. Tenant-scoped reads and writes run inside DB.WithTenant so
// the RLS tenant_isolation policy applies; the global permission catalog and the
// role_permissions association table (neither of which is tenant-scoped) are
// accessed with DB.WithoutTenant.
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
	"github.com/siberindo/cti/services/role-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Sentinel errors returned by the store and mapped to HTTP responses by the API
// layer (via the service layer).
var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a write violates a uniqueness constraint, such
	// as creating a role whose name already exists within the tenant, or assigning
	// a role a user already holds.
	ErrConflict = errors.New("conflict")
	// ErrImmutableSystemRole is returned when a write targets a system role (a role
	// with a nil tenant_id / role_type 'system'). System roles are managed by the
	// Auth service and are immutable through this API.
	ErrImmutableSystemRole = errors.New("system role is immutable")
)

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the Role service migrations. The migrations table is distinct
// from the Auth service's so each service tracks its own DDL history; the Role
// service does not own the identity DDL (see migrations/0001_role.sql).
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "core_platform.schema_migrations_role")
}

const roleCols = `id, tenant_id, name, role_type, description, created_at, updated_at`

func scanRole(row pgx.Row) (*domain.Role, error) {
	var r domain.Role
	if err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.RoleType, &r.Description, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRoles returns the roles visible to a tenant. The RLS policy on
// core_platform.roles returns system roles (tenant_id IS NULL) plus this
// tenant's own roles.
func (s *Store) ListRoles(ctx context.Context, tenantID string) ([]domain.Role, error) {
	var roles []domain.Role
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+roleCols+` FROM core_platform.roles ORDER BY role_type, name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRole(rows)
			if err != nil {
				return err
			}
			roles = append(roles, *r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	return roles, nil
}

// GetRole returns one role visible to the tenant (its own roles plus system
// roles). It returns ErrNotFound if no such role exists or it belongs to another
// tenant (the RLS policy hides it).
func (s *Store) GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error) {
	var out *domain.Role
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM core_platform.roles WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}
	return out, nil
}

// CreateRole inserts a tenant role (tenant_id = the tenant, role_type='tenant')
// and returns it. A duplicate (name, tenant_id) surfaces as ErrConflict.
func (s *Store) CreateRole(ctx context.Context, tenantID, name string, description *string) (*domain.Role, error) {
	var out *domain.Role
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanRole(tx.QueryRow(ctx,
			`INSERT INTO core_platform.roles (tenant_id, name, role_type, description)
			 VALUES ($1, $2, 'tenant', $3)
			 RETURNING `+roleCols, tenantID, name, description))
		return err
	})
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}
	return out, nil
}

// UpdateRole updates the name and/or description of a tenant role and returns the
// updated row. nil fields are left unchanged. A system role cannot be updated and
// returns ErrImmutableSystemRole; a missing/foreign role returns ErrNotFound. A
// rename colliding with an existing role surfaces as ErrConflict.
func (s *Store) UpdateRole(ctx context.Context, tenantID, id string, name, description *string) (*domain.Role, error) {
	var out *domain.Role
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM core_platform.roles WHERE id = $1`, id))
		if err != nil {
			return err
		}
		if cur.IsSystem() {
			return ErrImmutableSystemRole
		}
		out, err = scanRole(tx.QueryRow(ctx,
			`UPDATE core_platform.roles
			    SET name = COALESCE($2, name),
			        description = COALESCE($3, description)
			  WHERE id = $1
			 RETURNING `+roleCols, id, name, description))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if errors.Is(err, ErrImmutableSystemRole) {
		return nil, ErrImmutableSystemRole
	}
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}
	return out, nil
}

// DeleteRole removes a tenant role. A system role cannot be deleted and returns
// ErrImmutableSystemRole; a missing/foreign role returns ErrNotFound.
func (s *Store) DeleteRole(ctx context.Context, tenantID, id string) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		cur, err := scanRole(tx.QueryRow(ctx, `SELECT `+roleCols+` FROM core_platform.roles WHERE id = $1`, id))
		if err != nil {
			return err
		}
		if cur.IsSystem() {
			return ErrImmutableSystemRole
		}
		_, err = tx.Exec(ctx, `DELETE FROM core_platform.roles WHERE id = $1`, id)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if errors.Is(err, ErrImmutableSystemRole) {
		return ErrImmutableSystemRole
	}
	if err != nil {
		return fmt.Errorf("delete role: %w", err)
	}
	return nil
}

// AssignUserRole grants a role to a user within the tenant. A duplicate
// assignment surfaces as ErrConflict.
func (s *Store) AssignUserRole(ctx context.Context, tenantID, userID, roleID string) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO core_platform.user_roles (user_id, role_id, tenant_id)
			 VALUES ($1, $2, $3)`, userID, roleID, tenantID)
		return err
	})
	if isUniqueViolation(err) {
		return ErrConflict
	}
	if err != nil {
		return fmt.Errorf("assign user role: %w", err)
	}
	return nil
}

// RemoveUserRole revokes a role from a user within the tenant. It is idempotent.
func (s *Store) RemoveUserRole(ctx context.Context, tenantID, userID, roleID string) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM core_platform.user_roles WHERE user_id = $1 AND role_id = $2`, userID, roleID)
		return err
	})
	if err != nil {
		return fmt.Errorf("remove user role: %w", err)
	}
	return nil
}

// ListUserRoles returns the roles assigned to a user within the tenant.
func (s *Store) ListUserRoles(ctx context.Context, tenantID, userID string) ([]domain.Role, error) {
	var roles []domain.Role
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT r.id, r.tenant_id, r.name, r.role_type, r.description, r.created_at, r.updated_at
			   FROM core_platform.user_roles ur
			   JOIN core_platform.roles r ON r.id = ur.role_id
			  WHERE ur.user_id = $1
			  ORDER BY r.role_type, r.name`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRole(rows)
			if err != nil {
				return err
			}
			roles = append(roles, *r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list user roles: %w", err)
	}
	return roles, nil
}

const permCols = `id, resource, action, description, created_at`

// ListPermissions returns the global permission catalog. Permissions are not
// tenant-scoped (no RLS), so the read runs without a tenant context.
func (s *Store) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	var perms []domain.Permission
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+permCols+` FROM core_platform.permissions ORDER BY resource, action`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.Permission
			if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description, &p.CreatedAt); err != nil {
				return err
			}
			perms = append(perms, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}
	return perms, nil
}

// PermissionExists reports whether a permission with the given id exists in the
// global catalog. Permissions are not tenant-scoped.
func (s *Store) PermissionExists(ctx context.Context, permissionID string) (bool, error) {
	var exists bool
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM core_platform.permissions WHERE id = $1)`, permissionID).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("permission exists: %w", err)
	}
	return exists, nil
}

// GrantPermission associates a permission with a role. It is idempotent
// (ON CONFLICT DO NOTHING). The role_permissions table is not tenant-scoped, so
// the caller must first verify (via GetRole within the tenant) that the role
// belongs to the tenant before granting, to prevent cross-tenant edits.
func (s *Store) GrantPermission(ctx context.Context, roleID, permissionID string) error {
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO core_platform.role_permissions (role_id, permission_id)
			 VALUES ($1, $2)
			 ON CONFLICT (role_id, permission_id) DO NOTHING`, roleID, permissionID)
		return err
	})
	if err != nil {
		return fmt.Errorf("grant permission: %w", err)
	}
	return nil
}

// RevokePermission removes a permission from a role. It is idempotent. As with
// GrantPermission the caller must first verify the role belongs to the tenant.
func (s *Store) RevokePermission(ctx context.Context, roleID, permissionID string) error {
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`DELETE FROM core_platform.role_permissions WHERE role_id = $1 AND permission_id = $2`,
			roleID, permissionID)
		return err
	})
	if err != nil {
		return fmt.Errorf("revoke permission: %w", err)
	}
	return nil
}

// ListRolePermissions returns the permissions granted to a role, joined to the
// catalog. The role_permissions and permissions tables are not tenant-scoped, so
// the caller must first verify the role belongs to the tenant.
func (s *Store) ListRolePermissions(ctx context.Context, roleID string) ([]domain.Permission, error) {
	var perms []domain.Permission
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT p.id, p.resource, p.action, p.description, p.created_at
			   FROM core_platform.role_permissions rp
			   JOIN core_platform.permissions p ON p.id = rp.permission_id
			  WHERE rp.role_id = $1
			  ORDER BY p.resource, p.action`, roleID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p domain.Permission
			if err := rows.Scan(&p.ID, &p.Resource, &p.Action, &p.Description, &p.CreatedAt); err != nil {
				return err
			}
			perms = append(perms, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}
	return perms, nil
}

// isUniqueViolation reports whether err is a Postgres unique-constraint violation
// (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
