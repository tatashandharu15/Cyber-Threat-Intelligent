-- User Directory schema (core_platform). The User service shares the core_platform
-- schema with the Auth service. The identity tables (tenants, users, roles,
-- permissions, role_permissions, user_roles) are OWNED by the Auth service and must
-- not be recreated here. The User service owns only the directory-linkage table that
-- maps platform users to their external identity provider records.
--
-- Row-level security is enabled and FORCED so the tenant_isolation policy applies
-- even to the schema-owning `cti` role.

CREATE TABLE IF NOT EXISTS core_platform.user_directory_linkages (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  user_id        UUID NOT NULL,
  directory_type VARCHAR(32) NOT NULL CHECK (directory_type IN ('azure_ad','ldap','okta','manual')),
  directory_ref  VARCHAR(512) NOT NULL,
  status         VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_dir_linkages_user_id ON core_platform.user_directory_linkages (user_id);

ALTER TABLE core_platform.user_directory_linkages ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.user_directory_linkages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.user_directory_linkages;
CREATE POLICY tenant_isolation ON core_platform.user_directory_linkages
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP TRIGGER IF EXISTS set_updated_at ON core_platform.user_directory_linkages;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.user_directory_linkages
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
