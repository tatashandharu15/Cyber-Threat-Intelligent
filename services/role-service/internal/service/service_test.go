package service

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/siberindo/cti/services/role-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests. It models the core_platform
// identity tables closely enough to exercise the service's RBAC rules.
type fakeStore struct {
	roles       map[string]*domain.Role       // roleID -> role
	permissions map[string]*domain.Permission // permissionID -> permission
	rolePerms   map[string]map[string]bool    // roleID -> set(permissionID)
	userRoles   map[string]map[string]bool    // userID -> set(roleID)
	seq         int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		roles:       map[string]*domain.Role{},
		permissions: map[string]*domain.Permission{},
		rolePerms:   map[string]map[string]bool{},
		userRoles:   map[string]map[string]bool{},
	}
}

func (f *fakeStore) addSystemRole(id, name string) {
	f.roles[id] = &domain.Role{ID: id, TenantID: nil, Name: name, RoleType: "system", CreatedAt: time.Now(), UpdatedAt: time.Now()}
}

func (f *fakeStore) addPermission(id, resource, action string) {
	f.permissions[id] = &domain.Permission{ID: id, Resource: resource, Action: action, CreatedAt: time.Now()}
}

func (f *fakeStore) ListRoles(_ context.Context, tenantID string) ([]domain.Role, error) {
	out := []domain.Role{}
	for _, r := range f.roles {
		if r.TenantID == nil || *r.TenantID == tenantID {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeStore) GetRole(_ context.Context, tenantID, id string) (*domain.Role, error) {
	r, ok := f.roles[id]
	if !ok {
		return nil, ErrNotFound
	}
	// RLS: a tenant sees system roles plus its own.
	if r.TenantID != nil && *r.TenantID != tenantID {
		return nil, ErrNotFound
	}
	cp := *r
	return &cp, nil
}

func (f *fakeStore) CreateRole(_ context.Context, tenantID, name string, description *string) (*domain.Role, error) {
	for _, r := range f.roles {
		if r.Name == name && r.TenantID != nil && *r.TenantID == tenantID {
			return nil, ErrConflict
		}
	}
	f.seq++
	id := "role-" + strconv.Itoa(f.seq)
	tid := tenantID
	r := &domain.Role{ID: id, TenantID: &tid, Name: name, RoleType: "tenant", Description: description, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	f.roles[id] = r
	cp := *r
	return &cp, nil
}

func (f *fakeStore) UpdateRole(_ context.Context, tenantID, id string, name, description *string) (*domain.Role, error) {
	r, ok := f.roles[id]
	if !ok || (r.TenantID != nil && *r.TenantID != tenantID) {
		return nil, ErrNotFound
	}
	if r.IsSystem() {
		return nil, ErrImmutableSystemRole
	}
	if name != nil {
		r.Name = *name
	}
	if description != nil {
		r.Description = description
	}
	cp := *r
	return &cp, nil
}

func (f *fakeStore) DeleteRole(_ context.Context, tenantID, id string) error {
	r, ok := f.roles[id]
	if !ok || (r.TenantID != nil && *r.TenantID != tenantID) {
		return ErrNotFound
	}
	if r.IsSystem() {
		return ErrImmutableSystemRole
	}
	delete(f.roles, id)
	return nil
}

func (f *fakeStore) AssignUserRole(_ context.Context, _, userID, roleID string) error {
	if f.userRoles[userID] == nil {
		f.userRoles[userID] = map[string]bool{}
	}
	if f.userRoles[userID][roleID] {
		return ErrConflict
	}
	f.userRoles[userID][roleID] = true
	return nil
}

func (f *fakeStore) RemoveUserRole(_ context.Context, _, userID, roleID string) error {
	if f.userRoles[userID] != nil {
		delete(f.userRoles[userID], roleID)
	}
	return nil
}

func (f *fakeStore) ListUserRoles(_ context.Context, tenantID, userID string) ([]domain.Role, error) {
	out := []domain.Role{}
	for roleID := range f.userRoles[userID] {
		if r, ok := f.roles[roleID]; ok {
			out = append(out, *r)
		}
	}
	return out, nil
}

func (f *fakeStore) ListPermissions(_ context.Context) ([]domain.Permission, error) {
	out := []domain.Permission{}
	for _, p := range f.permissions {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fakeStore) PermissionExists(_ context.Context, permissionID string) (bool, error) {
	_, ok := f.permissions[permissionID]
	return ok, nil
}

func (f *fakeStore) GrantPermission(_ context.Context, roleID, permissionID string) error {
	if f.rolePerms[roleID] == nil {
		f.rolePerms[roleID] = map[string]bool{}
	}
	f.rolePerms[roleID][permissionID] = true
	return nil
}

func (f *fakeStore) RevokePermission(_ context.Context, roleID, permissionID string) error {
	if f.rolePerms[roleID] != nil {
		delete(f.rolePerms[roleID], permissionID)
	}
	return nil
}

func (f *fakeStore) ListRolePermissions(_ context.Context, roleID string) ([]domain.Permission, error) {
	out := []domain.Permission{}
	for pid := range f.rolePerms[roleID] {
		if p, ok := f.permissions[pid]; ok {
			out = append(out, *p)
		}
	}
	return out, nil
}

func newSvc() (*Service, *fakeStore) {
	st := newFakeStore()
	return New(st, nil), st
}

const tenant = "tenant-1"

func TestCreateRoleForcesTenantType(t *testing.T) {
	svc, _ := newSvc()
	role, err := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "incident-responder"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.RoleType != "tenant" {
		t.Fatalf("expected role_type tenant, got %s", role.RoleType)
	}
	if role.TenantID == nil || *role.TenantID != tenant {
		t.Fatalf("expected tenant_id %s, got %v", tenant, role.TenantID)
	}
}

func TestCreateRoleEmptyNameValidation(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "   "}); !IsValidation(err) {
		t.Fatalf("expected validation error for empty name, got %v", err)
	}
}

func TestCreateRoleDuplicateConflict(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "auditor"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "auditor"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate, got %v", err)
	}
}

func TestCreateRoleReservedNameConflict(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "tenant_admin"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for reserved name, got %v", err)
	}
}

func TestUpdateSystemRoleIsImmutable(t *testing.T) {
	svc, st := newSvc()
	st.addSystemRole("sys-1", "platform_admin")
	name := "renamed"
	if _, err := svc.UpdateRole(context.Background(), tenant, "sys-1", UpdateRoleInput{Name: &name}); !errors.Is(err, ErrImmutableSystemRole) {
		t.Fatalf("expected ErrImmutableSystemRole, got %v", err)
	}
}

func TestDeleteSystemRoleIsImmutable(t *testing.T) {
	svc, st := newSvc()
	st.addSystemRole("sys-1", "platform_admin")
	if err := svc.DeleteRole(context.Background(), tenant, "sys-1"); !errors.Is(err, ErrImmutableSystemRole) {
		t.Fatalf("expected ErrImmutableSystemRole, got %v", err)
	}
}

func TestGrantPermissionToTenantRoleThenList(t *testing.T) {
	svc, st := newSvc()
	st.addPermission("perm-1", "finding", "read")
	role, _ := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "analyst-lite"})

	if err := svc.GrantPermission(context.Background(), tenant, role.ID, "perm-1"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	perms, err := svc.ListRolePermissions(context.Background(), tenant, role.ID)
	if err != nil {
		t.Fatalf("list role permissions: %v", err)
	}
	found := false
	for _, p := range perms {
		if p.ID == "perm-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected granted permission in list, got %+v", perms)
	}
}

func TestGrantPermissionUnknownPermissionNotFound(t *testing.T) {
	svc, _ := newSvc()
	role, _ := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "analyst-lite"})
	if err := svc.GrantPermission(context.Background(), tenant, role.ID, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown permission, got %v", err)
	}
}

func TestGrantPermissionOnSystemRoleIsImmutable(t *testing.T) {
	svc, st := newSvc()
	st.addSystemRole("sys-1", "platform_admin")
	st.addPermission("perm-1", "finding", "read")
	if err := svc.GrantPermission(context.Background(), tenant, "sys-1", "perm-1"); !errors.Is(err, ErrImmutableSystemRole) {
		t.Fatalf("expected ErrImmutableSystemRole, got %v", err)
	}
}

func TestAssignUserRoleThenList(t *testing.T) {
	svc, _ := newSvc()
	role, _ := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "analyst-lite"})

	if err := svc.AssignUserRole(context.Background(), tenant, "user-1", role.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}
	roles, err := svc.ListUserRoles(context.Background(), tenant, "user-1")
	if err != nil {
		t.Fatalf("list user roles: %v", err)
	}
	found := false
	for _, r := range roles {
		if r.ID == role.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected assigned role in list, got %+v", roles)
	}
}

func TestAssignUserRoleDuplicateConflict(t *testing.T) {
	svc, _ := newSvc()
	role, _ := svc.CreateRole(context.Background(), tenant, CreateRoleInput{Name: "analyst-lite"})
	if err := svc.AssignUserRole(context.Background(), tenant, "user-1", role.ID); err != nil {
		t.Fatalf("first assign: %v", err)
	}
	if err := svc.AssignUserRole(context.Background(), tenant, "user-1", role.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate assignment, got %v", err)
	}
}

func TestAssignUserRoleUnknownRoleNotFound(t *testing.T) {
	svc, _ := newSvc()
	if err := svc.AssignUserRole(context.Background(), tenant, "user-1", "ghost-role"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for unknown role, got %v", err)
	}
}
