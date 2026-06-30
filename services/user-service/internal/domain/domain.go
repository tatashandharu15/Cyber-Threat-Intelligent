// Package domain holds the User service's core entity types, free of transport
// and storage concerns.
package domain

// User is an identity within a tenant. The password hash is never exposed over the
// wire; it is held only transiently during provisioning.
type User struct {
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	Email        string `json:"email"`
	DisplayName  string `json:"display_name"`
	Status       string `json:"status"`
	PasswordHash string `json:"-"`
	MFAEnabled   bool   `json:"mfa_enabled"`
}

// DirectoryLinkage maps a platform user to a record in an external identity
// directory (Azure AD, LDAP, Okta) or marks the account as manually managed.
type DirectoryLinkage struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	UserID        string `json:"user_id"`
	DirectoryType string `json:"directory_type"`
	DirectoryRef  string `json:"directory_ref"`
	Status        string `json:"status"`
}
