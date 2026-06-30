-- Asset Management schema (core_platform). The Asset service owns the DDL for the
-- assets and asset_directory_linkages tables; other services consume them.
-- Row-level security is enabled and FORCED so the policies apply even to the
-- schema-owning `cti` role.
--
-- Cross-bounded-context references elsewhere in the platform are plain UUID columns
-- without hard foreign keys; within this single schema, foreign keys are retained.

CREATE TABLE IF NOT EXISTS core_platform.assets (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           UUID NOT NULL,
  asset_type          VARCHAR(64) NOT NULL CHECK (asset_type IN (
                        'domain','ip_address','ip_range','email_address','email_domain',
                        'brand_keyword','executive_profile','mobile_app','social_handle')),
  value               VARCHAR(1024) NOT NULL,
  display_name        VARCHAR(255),
  criticality         VARCHAR(32) NOT NULL DEFAULT 'medium' CHECK (criticality IN ('critical','high','medium','low')),
  status              VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','decommissioned','pending_approval')),
  approval_status     VARCHAR(32) NOT NULL DEFAULT 'approved' CHECK (approval_status IN ('pending','approved','rejected')),
  approved_by         UUID,
  approved_at         TIMESTAMPTZ,
  visibility          VARCHAR(32) NOT NULL DEFAULT 'tenant' CHECK (visibility IN ('tenant','restricted')),
  metadata            JSONB NOT NULL DEFAULT '{}',
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by          UUID,
  updated_by          UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_value_type_tenant ON core_platform.assets (value, asset_type, tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_tenant_id ON core_platform.assets (tenant_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON core_platform.assets (asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_status ON core_platform.assets (status);
CREATE INDEX IF NOT EXISTS idx_assets_approval_status ON core_platform.assets (approval_status);
ALTER TABLE core_platform.assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.assets;
CREATE POLICY tenant_isolation ON core_platform.assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON core_platform.assets;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.assets
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

CREATE TABLE IF NOT EXISTS core_platform.asset_directory_linkages (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  asset_id       UUID NOT NULL REFERENCES core_platform.assets(id) ON DELETE CASCADE,
  directory_type VARCHAR(32) NOT NULL CHECK (directory_type IN ('azure_ad','ldap','okta','manual')),
  directory_ref  VARCHAR(512) NOT NULL,
  status         VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_asset_dir_linkages_asset_id ON core_platform.asset_directory_linkages (asset_id);
ALTER TABLE core_platform.asset_directory_linkages ENABLE ROW LEVEL SECURITY;
ALTER TABLE core_platform.asset_directory_linkages FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON core_platform.asset_directory_linkages;
CREATE POLICY tenant_isolation ON core_platform.asset_directory_linkages
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON core_platform.asset_directory_linkages;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON core_platform.asset_directory_linkages
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
