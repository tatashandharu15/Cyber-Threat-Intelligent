// Package service implements the User service's business logic: provisioning user
// accounts, managing their role assignments, and maintaining directory linkages.
// All operations are tenant-scoped; the tenant id originates from the caller's JWT
// claim and is threaded through to the store so RLS applies.
package service

import (
	"context"
	"errors"
	"strings"

	"github.com/siberindo/cti/services/user-service/internal/domain"
	"github.com/siberindo/cti/services/user-service/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// ErrValidation is returned when caller-supplied input fails validation. Store
// errors (ErrNotFound, ErrConflict) are passed through unchanged so the API layer
// can map them to the correct status codes.
var ErrValidation = errors.New("validation error")

const minPasswordLength = 8

// Store is the persistence contract the service depends on. Defining it here keeps
// the service unit-testable with an in-memory fake.
type Store interface {
	ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]domain.User, error)
	GetUser(ctx context.Context, tenantID, id string) (*domain.User, error)
	CreateUser(ctx context.Context, tenantID, email, displayName, passwordHash, status string) (*domain.User, error)
	UpdateUser(ctx context.Context, tenantID, id, displayName, status string) (*domain.User, error)
	AssignRole(ctx context.Context, tenantID, userID, roleID string) error
	RemoveRole(ctx context.Context, tenantID, userID, roleID string) error
	ListRolesForUser(ctx context.Context, tenantID, userID string) ([]string, error)
	GetDirectoryLinkage(ctx context.Context, tenantID, userID string) (*domain.DirectoryLinkage, error)
	UpsertDirectoryLinkage(ctx context.Context, tenantID, userID, dirType, dirRef string) (*domain.DirectoryLinkage, error)
}

// Service holds dependencies for user-management operations.
type Service struct {
	store Store
}

// New constructs a Service.
func New(store Store) *Service { return &Service{store: store} }

// CreateUser validates the input, hashes the password, and provisions a new user
// within the tenant. The email is lowercased and trimmed before storage.
func (s *Service) CreateUser(ctx context.Context, tenantID, email, displayName, password, status string) (*domain.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" || !strings.Contains(email, "@") {
		return nil, ErrValidation
	}
	if len(password) < minPasswordLength {
		return nil, ErrValidation
	}
	if status == "" {
		status = "active"
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return s.store.CreateUser(ctx, tenantID, email, displayName, string(hash), status)
}

// ListUsers returns a page of users within the tenant.
func (s *Service) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]domain.User, error) {
	return s.store.ListUsers(ctx, tenantID, limit, offset)
}

// GetUser returns a single user within the tenant.
func (s *Service) GetUser(ctx context.Context, tenantID, id string) (*domain.User, error) {
	return s.store.GetUser(ctx, tenantID, id)
}

// UpdateUser updates a user's display name and status within the tenant. The current
// values are loaded first so unset fields are preserved.
func (s *Service) UpdateUser(ctx context.Context, tenantID, id string, displayName, status *string) (*domain.User, error) {
	current, err := s.store.GetUser(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	newName := current.DisplayName
	if displayName != nil {
		if strings.TrimSpace(*displayName) == "" {
			return nil, ErrValidation
		}
		newName = *displayName
	}
	newStatus := current.Status
	if status != nil {
		if strings.TrimSpace(*status) == "" {
			return nil, ErrValidation
		}
		newStatus = *status
	}
	return s.store.UpdateUser(ctx, tenantID, id, newName, newStatus)
}

// AssignRole grants a role to a user within the tenant.
func (s *Service) AssignRole(ctx context.Context, tenantID, userID, roleID string) error {
	if strings.TrimSpace(roleID) == "" {
		return ErrValidation
	}
	return s.store.AssignRole(ctx, tenantID, userID, roleID)
}

// RemoveRole revokes a role from a user within the tenant.
func (s *Service) RemoveRole(ctx context.Context, tenantID, userID, roleID string) error {
	if strings.TrimSpace(roleID) == "" {
		return ErrValidation
	}
	return s.store.RemoveRole(ctx, tenantID, userID, roleID)
}

// ListRolesForUser returns the role names assigned to a user within the tenant.
func (s *Service) ListRolesForUser(ctx context.Context, tenantID, userID string) ([]string, error) {
	return s.store.ListRolesForUser(ctx, tenantID, userID)
}

// GetDirectoryLinkage returns the directory linkage for a user within the tenant.
func (s *Service) GetDirectoryLinkage(ctx context.Context, tenantID, userID string) (*domain.DirectoryLinkage, error) {
	return s.store.GetDirectoryLinkage(ctx, tenantID, userID)
}

// validDirectoryTypes is the set of directory types accepted by SetDirectoryLinkage,
// mirroring the CHECK constraint on the table.
var validDirectoryTypes = map[string]bool{
	"azure_ad": true,
	"ldap":     true,
	"okta":     true,
	"manual":   true,
}

// SetDirectoryLinkage creates or replaces the directory linkage for a user within the
// tenant after validating the directory type and reference.
func (s *Service) SetDirectoryLinkage(ctx context.Context, tenantID, userID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	dirType = strings.TrimSpace(dirType)
	dirRef = strings.TrimSpace(dirRef)
	if !validDirectoryTypes[dirType] || dirRef == "" {
		return nil, ErrValidation
	}
	return s.store.UpsertDirectoryLinkage(ctx, tenantID, userID, dirType, dirRef)
}

// Re-export store sentinels so callers depend on a single package. These keep the
// API layer's error mapping aligned with what the service surfaces.
var (
	// ErrNotFound mirrors store.ErrNotFound.
	ErrNotFound = store.ErrNotFound
	// ErrConflict mirrors store.ErrConflict.
	ErrConflict = store.ErrConflict
)
