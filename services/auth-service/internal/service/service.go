// Package service implements the Auth service's authentication business logic:
// password verification, MFA, JWT issuance, and session lifecycle.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/services/auth-service/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

// Sentinel errors returned by the service and mapped to HTTP responses by the API
// layer. They are intentionally coarse so authentication failures do not reveal
// whether the tenant, user, or password was the cause.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserInactive       = errors.New("user is not active")
	ErrMFARequired        = errors.New("mfa code required")
	ErrMFAInvalid         = errors.New("invalid mfa code")
	ErrSessionInactive    = errors.New("session is no longer active")
)

// Store is the persistence contract the service depends on.
type Store interface {
	GetTenantBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	GetUserByEmail(ctx context.Context, tenantID, email string) (*domain.User, error)
	GetUserByID(ctx context.Context, tenantID, userID string) (*domain.User, error)
	GetAuthorization(ctx context.Context, tenantID, userID string) (*domain.Authorization, error)
	CreateSession(ctx context.Context, tenantID, userID, jti string, expiresAt time.Time, ip, ua string) error
	SessionActive(ctx context.Context, tenantID, jti string) (bool, error)
	RevokeSession(ctx context.Context, tenantID, jti string) error
	TouchLastLogin(ctx context.Context, tenantID, userID string) error
}

// Service holds dependencies for authentication operations.
type Service struct {
	store  Store
	issuer *auth.Issuer
	ttl    time.Duration
}

// New constructs a Service.
func New(store Store, issuer *auth.Issuer, ttl time.Duration) *Service {
	return &Service{store: store, issuer: issuer, ttl: ttl}
}

// LoginInput carries credentials for authentication.
type LoginInput struct {
	TenantSlug string
	Email      string
	Password   string
	MFACode    string
	IP         string
	UserAgent  string
}

// TokenResult is returned on successful authentication.
type TokenResult struct {
	Token     string
	ExpiresAt time.Time
	User      *domain.User
}

// Login authenticates a user and issues a signed JWT plus a session record.
func (s *Service) Login(ctx context.Context, in LoginInput) (*TokenResult, error) {
	tenant, err := s.store.GetTenantBySlug(ctx, in.TenantSlug)
	if err != nil || tenant.Status != "active" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.store.GetUserByEmail(ctx, tenant.ID, in.Email)
	if err != nil {
		// Compare against a dummy hash to keep timing roughly constant whether or
		// not the user exists.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinv"), []byte(in.Password))
		return nil, ErrInvalidCredentials
	}
	if user.Status != "active" {
		return nil, ErrUserInactive
	}
	if user.PasswordHash == "" || bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(in.Password)) != nil {
		return nil, ErrInvalidCredentials
	}

	if user.MFAEnabled {
		if in.MFACode == "" {
			return nil, ErrMFARequired
		}
		if !totp.Validate(in.MFACode, user.MFASecret) {
			return nil, ErrMFAInvalid
		}
	}

	return s.issue(ctx, tenant.ID, user, in.IP, in.UserAgent)
}

// Refresh validates an existing token, rotates it (issuing a new token and
// session), and revokes the previous session.
func (s *Service) Refresh(ctx context.Context, oldToken, ip, ua string) (*TokenResult, error) {
	claims, err := s.issuer.Verify(oldToken)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	active, err := s.store.SessionActive(ctx, claims.TenantID, claims.ID)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrSessionInactive
	}
	user, err := s.store.GetUserByID(ctx, claims.TenantID, claims.Subject)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	if user.Status != "active" {
		return nil, ErrUserInactive
	}
	res, err := s.issue(ctx, claims.TenantID, user, ip, ua)
	if err != nil {
		return nil, err
	}
	// Best-effort revoke of the old session; the new one is already valid.
	_ = s.store.RevokeSession(ctx, claims.TenantID, claims.ID)
	return res, nil
}

// Logout revokes the session identified by jti within the tenant.
func (s *Service) Logout(ctx context.Context, tenantID, jti string) error {
	return s.store.RevokeSession(ctx, tenantID, jti)
}

func (s *Service) issue(ctx context.Context, tenantID string, user *domain.User, ip, ua string) (*TokenResult, error) {
	authz, err := s.store.GetAuthorization(ctx, tenantID, user.ID)
	if err != nil {
		return nil, err
	}
	jti := uuid.NewString()
	token, err := s.issuer.Issue(user.ID, tenantID, jti, authz.Roles, authz.Permissions)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(s.ttl)
	if err := s.store.CreateSession(ctx, tenantID, user.ID, jti, expiresAt, ip, ua); err != nil {
		return nil, err
	}
	_ = s.store.TouchLastLogin(ctx, tenantID, user.ID)
	return &TokenResult{Token: token, ExpiresAt: expiresAt, User: user}, nil
}

// HashPassword returns a bcrypt hash for a plaintext password. Used by seeding and
// by the User service when provisioning accounts.
func HashPassword(plaintext string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
