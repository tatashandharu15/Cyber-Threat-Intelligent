package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/services/auth-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	tenant   *domain.Tenant
	user     *domain.User
	authz    *domain.Authorization
	sessions map[string]bool // jti -> active
}

func (f *fakeStore) GetTenantBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	if f.tenant != nil && f.tenant.Slug == slug {
		return f.tenant, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeStore) GetUserByEmail(_ context.Context, tenantID, email string) (*domain.User, error) {
	if f.user != nil && f.user.TenantID == tenantID && f.user.Email == email {
		return f.user, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeStore) GetUserByID(_ context.Context, tenantID, userID string) (*domain.User, error) {
	if f.user != nil && f.user.TenantID == tenantID && f.user.ID == userID {
		return f.user, nil
	}
	return nil, errors.New("not found")
}

func (f *fakeStore) GetAuthorization(_ context.Context, _, _ string) (*domain.Authorization, error) {
	return f.authz, nil
}

func (f *fakeStore) CreateSession(_ context.Context, _, _, jti string, _ time.Time, _, _ string) error {
	f.sessions[jti] = true
	return nil
}

func (f *fakeStore) SessionActive(_ context.Context, _, jti string) (bool, error) {
	return f.sessions[jti], nil
}

func (f *fakeStore) RevokeSession(_ context.Context, _, jti string) error {
	f.sessions[jti] = false
	return nil
}

func (f *fakeStore) TouchLastLogin(_ context.Context, _, _ string) error { return nil }

func newTestService(t *testing.T, user *domain.User) (*Service, *fakeStore, *auth.Issuer) {
	t.Helper()
	fs := &fakeStore{
		tenant:   &domain.Tenant{ID: "tenant-1", Slug: "demo", Status: "active"},
		user:     user,
		authz:    &domain.Authorization{Roles: []string{"cti_analyst"}, Permissions: []string{"finding:read"}},
		sessions: map[string]bool{},
	}
	issuer := auth.NewIssuer("test-secret", time.Hour)
	return New(fs, issuer, time.Hour), fs, issuer
}

func testUser(t *testing.T, password string) *domain.User {
	t.Helper()
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return &domain.User{
		ID: "user-1", TenantID: "tenant-1", Email: "analyst@demo.siberindo.io",
		DisplayName: "Demo", Status: "active", PasswordHash: hash,
	}
}

func TestLoginSuccess(t *testing.T) {
	svc, fs, issuer := newTestService(t, testUser(t, "correct-horse"))

	res, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Token == "" {
		t.Fatal("expected a token")
	}
	claims, err := issuer.Verify(res.Token)
	if err != nil {
		t.Fatalf("token did not verify: %v", err)
	}
	if claims.TenantID != "tenant-1" || claims.Subject != "user-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !claims.HasRole("cti_analyst") || !claims.HasPermission("finding:read") {
		t.Fatalf("claims missing roles/permissions: %+v", claims)
	}
	if len(fs.sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(fs.sessions))
	}
}

func TestLoginWrongPassword(t *testing.T) {
	svc, _, _ := newTestService(t, testUser(t, "correct-horse"))
	_, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "wrong",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginUnknownTenant(t *testing.T) {
	svc, _, _ := newTestService(t, testUser(t, "correct-horse"))
	_, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "nope", Email: "analyst@demo.siberindo.io", Password: "correct-horse",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestLoginInactiveUser(t *testing.T) {
	u := testUser(t, "correct-horse")
	u.Status = "suspended"
	svc, _, _ := newTestService(t, u)
	_, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse",
	})
	if !errors.Is(err, ErrUserInactive) {
		t.Fatalf("expected ErrUserInactive, got %v", err)
	}
}

func TestLoginMFA(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SiberIndo", AccountName: "analyst@demo.siberindo.io"})
	if err != nil {
		t.Fatalf("generate totp: %v", err)
	}
	u := testUser(t, "correct-horse")
	u.MFAEnabled = true
	u.MFASecret = key.Secret()
	svc, _, _ := newTestService(t, u)

	// Missing code.
	if _, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse",
	}); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("expected ErrMFARequired, got %v", err)
	}

	// Invalid code.
	if _, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse", MFACode: "000000",
	}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("expected ErrMFAInvalid, got %v", err)
	}

	// Valid code.
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if _, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse", MFACode: code,
	}); err != nil {
		t.Fatalf("expected success with valid mfa, got %v", err)
	}
}

func TestRefreshAndLogout(t *testing.T) {
	svc, _, _ := newTestService(t, testUser(t, "correct-horse"))
	res, err := svc.Login(context.Background(), LoginInput{
		TenantSlug: "demo", Email: "analyst@demo.siberindo.io", Password: "correct-horse",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	// Refresh issues a new, different token.
	refreshed, err := svc.Refresh(context.Background(), res.Token, "", "")
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.Token == res.Token {
		t.Fatal("expected refresh to rotate the token")
	}

	// Logout revokes the refreshed session; a subsequent refresh must fail.
	claims, _ := svc.issuer.Verify(refreshed.Token)
	if err := svc.Logout(context.Background(), claims.TenantID, claims.ID); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if _, err := svc.Refresh(context.Background(), refreshed.Token, "", ""); !errors.Is(err, ErrSessionInactive) {
		t.Fatalf("expected ErrSessionInactive after logout, got %v", err)
	}
}
