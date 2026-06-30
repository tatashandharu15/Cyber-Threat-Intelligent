-- Identity & Access schema (core_platform). The Auth service owns the DDL for the
-- identity tables; other services consume them. Row-level security is enabled and
-- FORCED so the policies apply even to the schema-owning `cti` role.
--
-- Cross-bounded-context references elsewhere in the platform are plain UUID columns
-- without hard foreign keys; within this single schema, foreign keys are retained.

-- Tenant registry. Not tenant-scoped (it is the registry itself), so no RLS.
CREATE TABLE IF NOT EXISTS core_platform.tenants (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  slug          VARCHAR(63) NOT NULL UNIQUE,
  display_name  VARCHAR(255) NOT NULL,
  status        VARCHAR(32) NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'deprovisioned')),
  plan_tier     VARCHAR(32) NOT NULL DEFAULT 'standard'
                CHECK (plan_tier IN ('standard', 'professional', 'enterprise')),
  settings      JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS core_platform.users (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES core_platform.tenants(id),
  email         VARCHAR(254) NOT NULL,
  display_name  VARCHAR(255) NOT NULL,
  status        VARCHAR(32) NOT NULL DEFAULT 'active'
                CHECK (status IN ('active', 'suspended', 'deprovisioned', 'pending_activation')),
  password_hash VARCHAR(255),
  mfa_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
  mfa_method    VARCHAR(32) CHECK (mfa_method IN ('totp', 'email_otp')),
  mfa_secret    VARCHAR(255),
  last_login_at TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_tenant ON core_platform.users (email, tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON core_platform.users (tenant_id);

ALTER TABLE core_platform.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.users;
CREATE POLICY tenant_isolation ON core_platform.users
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE TABLE IF NOT EXISTS core_platform.sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL REFERENCES core_platform.tenants(id),
  user_id     UUID NOT NULL REFERENCES core_platform.users(id),
  jti         UUID NOT NULL UNIQUE,
  issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  ip_address  INET,
  user_agent  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_jti ON core_platform.sessions (jti);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON core_platform.sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON core_platform.sessions (expires_at) WHERE revoked_at IS NULL;

ALTER TABLE core_platform.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.sessions;
CREATE POLICY tenant_isolation ON core_platform.sessions
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Roles: system roles have NULL tenant_id and are visible to all tenants; tenant
-- roles are scoped. RLS allows a tenant to see system roles plus its own.
CREATE TABLE IF NOT EXISTS core_platform.roles (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID REFERENCES core_platform.tenants(id),
  name        VARCHAR(128) NOT NULL,
  role_type   VARCHAR(32) NOT NULL CHECK (role_type IN ('system', 'tenant')),
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_tenant ON core_platform.roles (name, tenant_id) WHERE tenant_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_name_system ON core_platform.roles (name) WHERE tenant_id IS NULL;

ALTER TABLE core_platform.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.roles;
CREATE POLICY tenant_isolation ON core_platform.roles
  USING (tenant_id IS NULL OR tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Permissions are a global reference catalog; no tenant scoping.
CREATE TABLE IF NOT EXISTS core_platform.permissions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  resource    VARCHAR(128) NOT NULL,
  action      VARCHAR(64) NOT NULL,
  description TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_permissions_resource_action ON core_platform.permissions (resource, action);

CREATE TABLE IF NOT EXISTS core_platform.role_permissions (
  role_id       UUID NOT NULL REFERENCES core_platform.roles(id) ON DELETE CASCADE,
  permission_id UUID NOT NULL REFERENCES core_platform.permissions(id) ON DELETE CASCADE,
  granted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS core_platform.user_roles (
  user_id     UUID NOT NULL REFERENCES core_platform.users(id) ON DELETE CASCADE,
  role_id     UUID NOT NULL REFERENCES core_platform.roles(id) ON DELETE CASCADE,
  tenant_id   UUID NOT NULL REFERENCES core_platform.tenants(id),
  assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON core_platform.user_roles (user_id);

ALTER TABLE core_platform.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.user_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.user_roles;
CREATE POLICY tenant_isolation ON core_platform.user_roles
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- updated_at maintenance triggers.
DROP TRIGGER IF EXISTS set_updated_at ON core_platform.tenants;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.tenants
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

DROP TRIGGER IF EXISTS set_updated_at ON core_platform.users;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.users
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

DROP TRIGGER IF EXISTS set_updated_at ON core_platform.roles;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.roles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
