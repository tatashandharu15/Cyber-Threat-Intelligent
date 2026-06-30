package service

import (
	"context"
	"errors"
	"testing"

	"github.com/siberindo/cti/services/user-service/internal/domain"
	"github.com/siberindo/cti/services/user-service/internal/store"
	"golang.org/x/crypto/bcrypt"
)

// fakeStore is an in-memory Store for unit tests (no database).
type fakeStore struct {
	users    map[string]*domain.User              // id -> user
	emails   map[string]bool                      // tenantID|email -> exists (uniqueness)
	roles    map[string]map[string]bool           // userID -> set of roleID
	linkages map[string]*domain.DirectoryLinkage  // userID -> linkage
	nextID   int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		users:    map[string]*domain.User{},
		emails:   map[string]bool{},
		roles:    map[string]map[string]bool{},
		linkages: map[string]*domain.DirectoryLinkage{},
	}
}

func (f *fakeStore) ListUsers(_ context.Context, tenantID string, limit, offset int) ([]domain.User, error) {
	var out []domain.User
	for _, u := range f.users {
		if u.TenantID == tenantID {
			out = append(out, *u)
		}
	}
	if offset >= len(out) {
		return nil, nil
	}
	end := offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[offset:end], nil
}

func (f *fakeStore) GetUser(_ context.Context, tenantID, id string) (*domain.User, error) {
	if u, ok := f.users[id]; ok && u.TenantID == tenantID {
		cp := *u
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) CreateUser(_ context.Context, tenantID, email, displayName, passwordHash, status string) (*domain.User, error) {
	key := tenantID + "|" + email
	if f.emails[key] {
		return nil, store.ErrConflict
	}
	f.nextID++
	u := &domain.User{
		ID:           "user-" + string(rune('0'+f.nextID)),
		TenantID:     tenantID,
		Email:        email,
		DisplayName:  displayName,
		Status:       status,
		PasswordHash: passwordHash,
	}
	f.users[u.ID] = u
	f.emails[key] = true
	return u, nil
}

func (f *fakeStore) UpdateUser(_ context.Context, tenantID, id, displayName, status string) (*domain.User, error) {
	u, ok := f.users[id]
	if !ok || u.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	u.DisplayName = displayName
	u.Status = status
	cp := *u
	return &cp, nil
}

func (f *fakeStore) AssignRole(_ context.Context, _ string, userID, roleID string) error {
	if f.roles[userID] == nil {
		f.roles[userID] = map[string]bool{}
	}
	f.roles[userID][roleID] = true
	return nil
}

func (f *fakeStore) RemoveRole(_ context.Context, _ string, userID, roleID string) error {
	if f.roles[userID] != nil {
		delete(f.roles[userID], roleID)
	}
	return nil
}

func (f *fakeStore) ListRolesForUser(_ context.Context, _ string, userID string) ([]string, error) {
	var names []string
	for r := range f.roles[userID] {
		names = append(names, r)
	}
	return names, nil
}

func (f *fakeStore) GetDirectoryLinkage(_ context.Context, tenantID, userID string) (*domain.DirectoryLinkage, error) {
	if l, ok := f.linkages[userID]; ok && l.TenantID == tenantID {
		cp := *l
		return &cp, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) UpsertDirectoryLinkage(_ context.Context, tenantID, userID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	if l, ok := f.linkages[userID]; ok && l.TenantID == tenantID {
		l.DirectoryType = dirType
		l.DirectoryRef = dirRef
		cp := *l
		return &cp, nil
	}
	f.nextID++
	l := &domain.DirectoryLinkage{
		ID:            "link-" + string(rune('0'+f.nextID)),
		TenantID:      tenantID,
		UserID:        userID,
		DirectoryType: dirType,
		DirectoryRef:  dirRef,
		Status:        "active",
	}
	f.linkages[userID] = l
	cp := *l
	return &cp, nil
}

const testTenant = "tenant-1"

func TestCreateUserSuccess(t *testing.T) {
	fs := newFakeStore()
	svc := New(fs)

	u, err := svc.CreateUser(context.Background(), testTenant, "  Analyst@Demo.io ", "Demo Analyst", "correct-horse", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if u.Email != "analyst@demo.io" {
		t.Fatalf("expected normalized email, got %q", u.Email)
	}
	if u.Status != "active" {
		t.Fatalf("expected default status active, got %q", u.Status)
	}
	// Password must be stored hashed, never as plaintext.
	if u.PasswordHash == "" || u.PasswordHash == "correct-horse" {
		t.Fatalf("password was not hashed: %q", u.PasswordHash)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte("correct-horse")); err != nil {
		t.Fatalf("stored hash does not match password: %v", err)
	}
}

func TestCreateUserShortPassword(t *testing.T) {
	svc := New(newFakeStore())
	_, err := svc.CreateUser(context.Background(), testTenant, "a@demo.io", "A", "short", "")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation, got %v", err)
	}
}

func TestCreateUserBadEmail(t *testing.T) {
	svc := New(newFakeStore())
	for _, bad := range []string{"", "   ", "no-at-sign"} {
		_, err := svc.CreateUser(context.Background(), testTenant, bad, "A", "correct-horse", "")
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("email %q: expected ErrValidation, got %v", bad, err)
		}
	}
}

func TestCreateUserDuplicate(t *testing.T) {
	fs := newFakeStore()
	svc := New(fs)
	if _, err := svc.CreateUser(context.Background(), testTenant, "dup@demo.io", "A", "correct-horse", ""); err != nil {
		t.Fatalf("first create failed: %v", err)
	}
	_, err := svc.CreateUser(context.Background(), testTenant, "dup@demo.io", "A", "correct-horse", "")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestAssignRole(t *testing.T) {
	fs := newFakeStore()
	svc := New(fs)
	u, err := svc.CreateUser(context.Background(), testTenant, "role@demo.io", "A", "correct-horse", "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := svc.AssignRole(context.Background(), testTenant, u.ID, "role-1"); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	names, err := svc.ListRolesForUser(context.Background(), testTenant, u.ID)
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(names) != 1 || names[0] != "role-1" {
		t.Fatalf("expected [role-1], got %v", names)
	}

	// Empty role id is rejected.
	if err := svc.AssignRole(context.Background(), testTenant, u.ID, "  "); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for empty role, got %v", err)
	}
}

func TestSetDirectoryLinkageUpsert(t *testing.T) {
	fs := newFakeStore()
	svc := New(fs)
	u, err := svc.CreateUser(context.Background(), testTenant, "dir@demo.io", "A", "correct-horse", "")
	if err != nil {
		t.Fatalf("create user: %v", err)
	}

	// First call inserts.
	l, err := svc.SetDirectoryLinkage(context.Background(), testTenant, u.ID, "okta", "okta-ref-1")
	if err != nil {
		t.Fatalf("set linkage: %v", err)
	}
	if l.DirectoryType != "okta" || l.DirectoryRef != "okta-ref-1" {
		t.Fatalf("unexpected linkage: %+v", l)
	}
	firstID := l.ID

	// Second call updates in place (same row).
	l2, err := svc.SetDirectoryLinkage(context.Background(), testTenant, u.ID, "azure_ad", "azure-ref-2")
	if err != nil {
		t.Fatalf("update linkage: %v", err)
	}
	if l2.ID != firstID {
		t.Fatalf("expected upsert to reuse row %q, got %q", firstID, l2.ID)
	}
	if l2.DirectoryType != "azure_ad" || l2.DirectoryRef != "azure-ref-2" {
		t.Fatalf("linkage not updated: %+v", l2)
	}

	// Invalid directory type is rejected.
	if _, err := svc.SetDirectoryLinkage(context.Background(), testTenant, u.ID, "bogus", "ref"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for bad type, got %v", err)
	}
}
