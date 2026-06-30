// Package domain holds the Role service's core entity types. These mirror the
// core_platform identity tables owned by the Auth service: roles, permissions,
// role_permissions, and user_roles.
package domain

import "time"

// Role is an RBAC role. System roles have a nil TenantID and a role_type of
// "system"; they are visible to every tenant and immutable through this API.
// Tenant roles carry the owning tenant's id and a role_type of "tenant".
type Role struct {
	ID          string    `json:"id"`
	TenantID    *string   `json:"tenant_id"`
	Name        string    `json:"name"`
	RoleType    string    `json:"role_type"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// IsSystem reports whether the role is a system role (nil tenant_id or a
// role_type of "system"). System roles are immutable through this API.
func (r *Role) IsSystem() bool {
	return r.TenantID == nil || r.RoleType == "system"
}

// Permission is a global catalog entry identifying an action on a resource. The
// JWT permission claim is formatted as "resource:action".
type Permission struct {
	ID          string    `json:"id"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description *string   `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// RolePermission is the association of a permission to a role, returned by the
// role-permission listing endpoint as an enriched view of role_permissions.
type RolePermission struct {
	RoleID     string     `json:"role_id"`
	Permission Permission `json:"permission"`
	GrantedAt  time.Time  `json:"granted_at"`
}

// UserRole is the assignment of a role to a user within a tenant.
type UserRole struct {
	UserID     string    `json:"user_id"`
	RoleID     string    `json:"role_id"`
	TenantID   string    `json:"tenant_id"`
	AssignedAt time.Time `json:"assigned_at"`
}
