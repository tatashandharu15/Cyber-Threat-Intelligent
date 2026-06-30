-- Indicator Management schema (platform_services). The Indicator service owns the
-- DDL for the indicators table. Row-level security is enabled and FORCED so the
-- tenant_isolation policy applies even to the schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, source_finding_id, created_by,
-- updated_by) are plain UUID columns WITHOUT hard foreign keys to other schemas.
--
-- The shared trigger function public.update_updated_at() and the platform_services
-- schema are created by infra/docker/init/01-init.sql.

-- Indicators: deduplicated CTI observables (domains, IPs, hashes, etc.) with a
-- Traffic Light Protocol marking. The (tenant_id, indicator_type, value) unique
-- key is the dedup key used by the upsert path so re-observing an indicator
-- refreshes last_seen_at rather than inserting a duplicate.
CREATE TABLE IF NOT EXISTS platform_services.indicators (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                UUID NOT NULL,
  indicator_type           VARCHAR(64) NOT NULL CHECK (indicator_type IN (
                             'domain','ip_address','url_defanged','hash_md5','hash_sha1',
                             'hash_sha256','email_address','asn','certificate_fingerprint',
                             'mutex','registry_key','file_path')),
  value                    VARCHAR(2048) NOT NULL,
  tlp_marking              VARCHAR(16) NOT NULL DEFAULT 'TLP:AMBER' CHECK (tlp_marking IN (
                             'TLP:WHITE','TLP:GREEN','TLP:AMBER','TLP:RED')),
  confidence               NUMERIC(5,4) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  source_module            VARCHAR(32),
  source_finding_id        UUID,
  tags                     TEXT[],
  first_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at               TIMESTAMPTZ,
  created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by               UUID,
  updated_by               UUID,
  UNIQUE (tenant_id, indicator_type, value)
);
CREATE INDEX IF NOT EXISTS idx_indicators_tenant_type ON platform_services.indicators (tenant_id, indicator_type);
CREATE INDEX IF NOT EXISTS idx_indicators_tenant_tlp ON platform_services.indicators (tenant_id, tlp_marking);
CREATE INDEX IF NOT EXISTS idx_indicators_tenant_value ON platform_services.indicators (tenant_id, value);
ALTER TABLE platform_services.indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.indicators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.indicators;
CREATE POLICY tenant_isolation ON platform_services.indicators
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.indicators;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.indicators
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
