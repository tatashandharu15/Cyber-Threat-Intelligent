package service

// reservedRoleNames are role names that map to system roles managed by the Auth
// service. The management API forces every role it creates to be a tenant role,
// and the database's partial unique index on system role names already prevents a
// tenant role from colliding with a system role of the same name (the unique
// indexes are scoped separately by tenant_id NULL-ness). This set documents the
// well-known system role names for clarity and future validation hooks.
var reservedRoleNames = map[string]bool{
	"platform_admin": true,
	"tenant_admin":   true,
	"analyst":        true,
	"viewer":         true,
}
