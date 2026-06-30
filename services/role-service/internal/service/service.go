// Package service implements the Role service's business logic: RBAC role
// lifecycle, permission grants, and user-role assignments over the core_platform
// identity tables. It enforces the platform rules that the management API may
// only create tenant roles and that system roles are immutable. The service is
// synchronous and has no Kafka dependency (correct per the frozen event catalog).
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/siberindo/cti/services/role-service/internal/domain"
	"github.com/siberindo/cti/services/role-service/internal/store"
)

// ValidationError carries a human-readable validation message.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func newValidation(format string, a ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, a...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

var (
	// ErrNotFound, ErrConflict, and ErrImmutableSystemRole are re-exported from the
	// store for the API layer.
	ErrNotFound            = store.ErrNotFound
	ErrConflict            = store.ErrConflict
	ErrImmutableSystemRole = store.ErrImmutableSystemRole
)

// Store is the persistence contract.
type Store interface {
	ListRoles(ctx context.Context, tenantID string) ([]domain.Role, error)
	GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error)
	CreateRole(ctx context.Context, tenantID, name string, description *string) (*domain.Role, error)
	UpdateRole(ctx context.Context, tenantID, id string, name, description *string) (*domain.Role, error)
	DeleteRole(ctx context.Context, tenantID, id string) error
	AssignUserRole(ctx context.Context, tenantID, userID, roleID string) error
	RemoveUserRole(ctx context.Context, tenantID, userID, roleID string) error
	ListUserRoles(ctx context.Context, tenantID, userID string) ([]domain.Role, error)

	ListPermissions(ctx context.Context) ([]domain.Permission, error)
	PermissionExists(ctx context.Context, permissionID string) (bool, error)
	GrantPermission(ctx context.Context, roleID, permissionID string) error
	RevokePermission(ctx context.Context, roleID, permissionID string) error
	ListRolePermissions(ctx context.Context, roleID string) ([]domain.Permission, error)
}

// Service holds the Role business logic dependencies.
type Service struct {
	store Store
	log   *slog.Logger
}

// New constructs a Service.
func New(s Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: s, log: log}
}

// ListRoles returns the roles visible to a tenant (system roles plus the tenant's
// own roles).
func (s *Service) ListRoles(ctx context.Context, tenantID string) ([]domain.Role, error) {
	return s.store.ListRoles(ctx, tenantID)
}

// GetRole returns one role visible to the tenant.
func (s *Service) GetRole(ctx context.Context, tenantID, id string) (*domain.Role, error) {
	return s.store.GetRole(ctx, tenantID, id)
}

// CreateRoleInput carries the fields for a new tenant role.
type CreateRoleInput struct {
	Name        string
	Description *string
}

// CreateRole validates input and creates a tenant role. role_type is always
// forced to "tenant" by the store: the management API cannot mint system roles.
// A name colliding with an existing role surfaces as ErrConflict (enforced by the
// database's unique index on (name, tenant_id)).
func (s *Service) CreateRole(ctx context.Context, tenantID string, in CreateRoleInput) (*domain.Role, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, newValidation("name is required")
	}
	if len(name) > 128 {
		return nil, newValidation("name must be at most 128 characters")
	}
	if isReservedName(name) {
		// Reserved names belong to system roles managed by the Auth service. The
		// database's separate unique index on system role names is the
		// authoritative guard; this is a fast-path rejection with a clear signal.
		return nil, ErrConflict
	}
	return s.store.CreateRole(ctx, tenantID, name, in.Description)
}

// UpdateRoleInput carries the mutable fields of a role; nil leaves a field as-is.
type UpdateRoleInput struct {
	Name        *string
	Description *string
}

// UpdateRole updates a tenant role's name and/or description. A system role is
// immutable and yields ErrImmutableSystemRole.
func (s *Service) UpdateRole(ctx context.Context, tenantID, id string, in UpdateRoleInput) (*domain.Role, error) {
	if in.Name != nil {
		trimmed := strings.TrimSpace(*in.Name)
		if trimmed == "" {
			return nil, newValidation("name must not be empty")
		}
		if len(trimmed) > 128 {
			return nil, newValidation("name must be at most 128 characters")
		}
		in.Name = &trimmed
	}
	role, err := s.resolveTenantRole(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if role.IsSystem() {
		return nil, ErrImmutableSystemRole
	}
	return s.store.UpdateRole(ctx, tenantID, id, in.Name, in.Description)
}

// DeleteRole removes a tenant role. A system role is immutable and yields
// ErrImmutableSystemRole.
func (s *Service) DeleteRole(ctx context.Context, tenantID, id string) error {
	role, err := s.resolveTenantRole(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if role.IsSystem() {
		return ErrImmutableSystemRole
	}
	return s.store.DeleteRole(ctx, tenantID, id)
}

// ListRolePermissions returns the permissions granted to a role. The role must be
// resolvable within the tenant.
func (s *Service) ListRolePermissions(ctx context.Context, tenantID, roleID string) ([]domain.Permission, error) {
	if _, err := s.resolveTenantRole(ctx, tenantID, roleID); err != nil {
		return nil, err
	}
	return s.store.ListRolePermissions(ctx, roleID)
}

// GrantPermission grants a permission to a tenant role. The role must be a
// non-system role resolvable within the tenant, and the permission must exist in
// the global catalog.
func (s *Service) GrantPermission(ctx context.Context, tenantID, roleID, permissionID string) error {
	if strings.TrimSpace(permissionID) == "" {
		return newValidation("permission_id is required")
	}
	role, err := s.resolveTenantRole(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if role.IsSystem() {
		return ErrImmutableSystemRole
	}
	exists, err := s.store.PermissionExists(ctx, permissionID)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	return s.store.GrantPermission(ctx, roleID, permissionID)
}

// RevokePermission removes a permission from a tenant role. The role must be a
// non-system role resolvable within the tenant.
func (s *Service) RevokePermission(ctx context.Context, tenantID, roleID, permissionID string) error {
	if strings.TrimSpace(permissionID) == "" {
		return newValidation("permission_id is required")
	}
	role, err := s.resolveTenantRole(ctx, tenantID, roleID)
	if err != nil {
		return err
	}
	if role.IsSystem() {
		return ErrImmutableSystemRole
	}
	return s.store.RevokePermission(ctx, roleID, permissionID)
}

// ListPermissions returns the global permission catalog.
func (s *Service) ListPermissions(ctx context.Context) ([]domain.Permission, error) {
	return s.store.ListPermissions(ctx)
}

// ListUserRoles returns the roles assigned to a user within the tenant.
func (s *Service) ListUserRoles(ctx context.Context, tenantID, userID string) ([]domain.Role, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, newValidation("user id is required")
	}
	return s.store.ListUserRoles(ctx, tenantID, userID)
}

// AssignUserRole grants a role to a user within the tenant. The role must be
// resolvable within the tenant (its own roles plus system roles); a duplicate
// assignment surfaces as ErrConflict.
func (s *Service) AssignUserRole(ctx context.Context, tenantID, userID, roleID string) error {
	if strings.TrimSpace(userID) == "" {
		return newValidation("user id is required")
	}
	if strings.TrimSpace(roleID) == "" {
		return newValidation("role_id is required")
	}
	if _, err := s.resolveTenantRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	return s.store.AssignUserRole(ctx, tenantID, userID, roleID)
}

// RemoveUserRole revokes a role from a user within the tenant. The role must be
// resolvable within the tenant.
func (s *Service) RemoveUserRole(ctx context.Context, tenantID, userID, roleID string) error {
	if strings.TrimSpace(userID) == "" {
		return newValidation("user id is required")
	}
	if strings.TrimSpace(roleID) == "" {
		return newValidation("role_id is required")
	}
	if _, err := s.resolveTenantRole(ctx, tenantID, roleID); err != nil {
		return err
	}
	return s.store.RemoveUserRole(ctx, tenantID, userID, roleID)
}

// resolveTenantRole loads a role visible to the tenant, returning ErrNotFound if
// it does not exist or belongs to another tenant. It is the cross-tenant guard
// used before any role-permission or user-role mutation, since the
// role_permissions and user_roles paths touch tables whose RLS does not, on its
// own, prevent referencing a foreign role id.
func (s *Service) resolveTenantRole(ctx context.Context, tenantID, roleID string) (*domain.Role, error) {
	role, err := s.store.GetRole(ctx, tenantID, roleID)
	if err != nil {
		return nil, err
	}
	return role, nil
}

// isReservedName reports whether name is a well-known system role name. It is a
// defensive aid; the database's separate unique indexes for system and tenant
// role names are the authoritative guard.
func isReservedName(name string) bool {
	return reservedRoleNames[strings.ToLower(strings.TrimSpace(name))]
}
