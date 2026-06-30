-- Brand Monitoring schema (monitoring_brm). The BRM service owns the DDL for the
-- collection, finding, evidence, and history tables. Row-level security is enabled
-- and FORCED so the tenant_isolation policies apply even to the schema-owning `cti`
-- role.
--
-- Cross-bounded-context references (tenant_id, asset_id, created_by, suppressed_by,
-- source_id, job_run_id, etc.) are plain UUID columns WITHOUT hard foreign keys to
-- other schemas; within this single schema, foreign keys are retained.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- monitoring_brm schema itself.

-- 1. Collection sources: the configured intelligence sources BRM ingests from
-- (registrar feeds, domain registration feeds, app store APIs, social adapters).
CREATE TABLE IF NOT EXISTS monitoring_brm.collection_sources (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  source_type   VARCHAR(64) NOT NULL CHECK (source_type IN (
                  'registrar_feed','domain_registration_feed',
                  'app_store_api','social_platform_adapter')),
  display_name  VARCHAR(255) NOT NULL,
  status        VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                  'active','paused','retired','error')),
  last_run_at   TIMESTAMPTZ,
  last_error    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID,
  updated_by    UUID
);
CREATE INDEX IF NOT EXISTS idx_brm_sources_tenant_id ON monitoring_brm.collection_sources (tenant_id);
ALTER TABLE monitoring_brm.collection_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_brm.collection_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_brm.collection_sources;
CREATE POLICY tenant_isolation ON monitoring_brm.collection_sources
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_brm.collection_sources;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_brm.collection_sources
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Findings: the brand-impersonation detections produced by collection.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at (e.g. findings_2026_06) to keep the hot
-- set small and enable partition pruning; that is intentionally deferred here.
--
-- similarity_score is nullable (not every finding type has a domain-similarity
-- measure); when present it is constrained to [0,1] and the algorithm version that
-- produced it is recorded for reproducibility (BRM-BR-002 / BRM-NFR-001).
CREATE TABLE IF NOT EXISTS monitoring_brm.findings (
  id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id                   UUID NOT NULL,
  finding_type                VARCHAR(64) NOT NULL CHECK (finding_type IN (
                                'lookalike_domain','typosquatting_domain',
                                'rogue_mobile_application','fake_social_media_profile',
                                'impersonation_website','unauthorized_brand_usage',
                                'brand_mention')),
  title                       VARCHAR(512) NOT NULL,
  severity                    VARCHAR(32) NOT NULL CHECK (severity IN (
                                'critical','high','medium','low','informational')),
  status                      VARCHAR(32) NOT NULL DEFAULT 'new' CHECK (status IN (
                                'new','triaged','confirmed','escalated',
                                'takedown_initiated','takedown_complete',
                                'suppressed','resolved','closed')),
  confidence_score            NUMERIC(5,4) CHECK (confidence_score >= 0 AND confidence_score <= 1),
  similarity_score            NUMERIC(5,4) CHECK (similarity_score IS NULL OR (similarity_score >= 0 AND similarity_score <= 1)),
  similarity_algorithm_version VARCHAR(32),
  candidate_value             VARCHAR(1024) NOT NULL,
  source_id                   UUID,
  job_run_id                  UUID,
  dedup_key                   VARCHAR(512) NOT NULL,
  whois_snapshot              JSONB,
  registration_date           DATE,
  social_platform_id          VARCHAR(128),
  social_account_handle       VARCHAR(512),
  social_profile_url          TEXT,
  app_store_id                VARCHAR(128),
  app_platform                VARCHAR(64),
  app_listing_url             TEXT,
  app_package_id              VARCHAR(512),
  suppression_reason          TEXT,
  suppressed_by               UUID,
  suppressed_at               TIMESTAMPTZ,
  prior_severity              VARCHAR(32),
  severity_overridden_by      UUID,
  severity_override_reason    TEXT,
  created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by                  UUID,
  updated_by                  UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_brm_findings_dedup ON monitoring_brm.findings (tenant_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_brm_findings_tenant_status ON monitoring_brm.findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_brm_findings_tenant_severity ON monitoring_brm.findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_brm_findings_tenant_type ON monitoring_brm.findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_brm_findings_tenant_similarity ON monitoring_brm.findings (tenant_id, similarity_score DESC) WHERE similarity_score IS NOT NULL;
ALTER TABLE monitoring_brm.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_brm.findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_brm.findings;
CREATE POLICY tenant_isolation ON monitoring_brm.findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_brm.findings;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_brm.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 3. Finding-asset linkages: which monitored brand keyword assets a finding
-- implicates. asset_id is a cross-context reference to core_platform.assets (no FK).
CREATE TABLE IF NOT EXISTS monitoring_brm.finding_assets (
  finding_id  UUID NOT NULL REFERENCES monitoring_brm.findings(id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL,
  tenant_id   UUID NOT NULL,
  linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by   UUID,
  PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_brm_finding_assets_asset_id ON monitoring_brm.finding_assets (asset_id);
CREATE INDEX IF NOT EXISTS idx_brm_finding_assets_tenant_id ON monitoring_brm.finding_assets (tenant_id);
ALTER TABLE monitoring_brm.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_brm.finding_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_brm.finding_assets;
CREATE POLICY tenant_isolation ON monitoring_brm.finding_assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 4. Evidence: IMMUTABLE chain-of-custody captures for a finding. UPDATE/DELETE are
-- blocked by the shared public.prevent_mutation() trigger (Database Blueprint 1.4).
CREATE TABLE IF NOT EXISTS monitoring_brm.evidence (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  finding_id        UUID REFERENCES monitoring_brm.findings(id),
  evidence_type     VARCHAR(64) NOT NULL CHECK (evidence_type IN (
                      'screenshot','whois_snapshot','app_listing_metadata',
                      'social_profile_metadata','content_snapshot')),
  capture_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  content_hash      VARCHAR(128) NOT NULL,
  storage_ref       VARCHAR(1024),
  metadata          JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_brm_evidence_finding_id ON monitoring_brm.evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_brm_evidence_tenant_id ON monitoring_brm.evidence (tenant_id);
ALTER TABLE monitoring_brm.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_brm.evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_brm.evidence;
CREATE POLICY tenant_isolation ON monitoring_brm.evidence
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_brm_evidence ON monitoring_brm.evidence;
CREATE TRIGGER immutable_brm_evidence BEFORE UPDATE OR DELETE ON monitoring_brm.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 5. Finding history: IMMUTABLE append-only audit of finding field changes.
CREATE TABLE IF NOT EXISTS monitoring_brm.finding_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  finding_id    UUID NOT NULL,
  changed_field VARCHAR(128) NOT NULL,
  old_value     TEXT,
  new_value     TEXT,
  changed_by    UUID,
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_brm_finding_history_finding_id ON monitoring_brm.finding_history (finding_id);
CREATE INDEX IF NOT EXISTS idx_brm_finding_history_tenant_id ON monitoring_brm.finding_history (tenant_id);
ALTER TABLE monitoring_brm.finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_brm.finding_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_brm.finding_history;
CREATE POLICY tenant_isolation ON monitoring_brm.finding_history
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_brm_finding_history ON monitoring_brm.finding_history;
CREATE TRIGGER immutable_brm_finding_history BEFORE UPDATE OR DELETE ON monitoring_brm.finding_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
