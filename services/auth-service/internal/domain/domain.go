// Package domain holds the Auth service's core entity types, free of transport
// and storage concerns.
package domain

import "time"

// Tenant is a customer organization.
type Tenant struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
}

// User is an identity within a tenant.
type User struct {
	ID           string  `json:"id"`
	TenantID     string  `json:"tenant_id"`
	Email        string  `json:"email"`
	DisplayName  string  `json:"display_name"`
	Status       string  `json:"status"`
	PasswordHash string  `json:"-"`
	MFAEnabled   bool    `json:"mfa_enabled"`
	MFAMethod    *string `json:"mfa_method,omitempty"`
	MFASecret    string  `json:"-"`
}

// Session is an issued token's server-side record, keyed by its jti.
type Session struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	JTI       string    `json:"jti"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// Authorization is the set of roles and permissions assembled for a user, used to
// populate the JWT claims.
type Authorization struct {
	Roles       []string
	Permissions []string
}
