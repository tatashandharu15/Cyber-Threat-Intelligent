-- Data Leak Monitoring schema (monitoring_dlm). The DLM service owns the DDL for
-- the collection, finding, evidence, and history tables. Row-level security is
-- enabled and FORCED so the tenant_isolation policies apply even to the
-- schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, asset_id, created_by, suppressed_by,
-- etc.) are plain UUID columns WITHOUT hard foreign keys to other schemas; within
-- this single schema, foreign keys are retained.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- monitoring_dlm schema itself.

-- 1. Collection sources: the configured intelligence sources DLM ingests from.
CREATE TABLE IF NOT EXISTS monitoring_dlm.collection_sources (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  source_type   VARCHAR(64) NOT NULL CHECK (source_type IN (
                  'paste_site','public_code_repo','leaked_database_index',
                  'document_sharing_site','exposed_storage')),
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
CREATE INDEX IF NOT EXISTS idx_dlm_sources_tenant_id ON monitoring_dlm.collection_sources (tenant_id);
ALTER TABLE monitoring_dlm.collection_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.collection_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.collection_sources;
CREATE POLICY tenant_isolation ON monitoring_dlm.collection_sources
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_dlm.collection_sources;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_dlm.collection_sources
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Collection jobs: a single execution of a collection source.
CREATE TABLE IF NOT EXISTS monitoring_dlm.collection_jobs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  source_id         UUID REFERENCES monitoring_dlm.collection_sources(id),
  status            VARCHAR(32) NOT NULL DEFAULT 'running' CHECK (status IN (
                      'running','completed','failed','cancelled')),
  trigger_type      VARCHAR(32) NOT NULL CHECK (trigger_type IN ('scheduled','on_demand')),
  findings_ingested INT NOT NULL DEFAULT 0,
  errors_count      INT NOT NULL DEFAULT 0,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at      TIMESTAMPTZ,
  error_detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_dlm_jobs_tenant_id ON monitoring_dlm.collection_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dlm_jobs_source_id ON monitoring_dlm.collection_jobs (source_id);
ALTER TABLE monitoring_dlm.collection_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.collection_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.collection_jobs;
CREATE POLICY tenant_isolation ON monitoring_dlm.collection_jobs
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Findings: the leaked-data detections produced by collection.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at (e.g. findings_2026_06) to keep the hot
-- set small and enable partition pruning; that is intentionally deferred here.
--
-- The content_url CHECK enforces that any stored URL is defanged ('hXXp[s]://...')
-- so that operators handling leaked-content references never click a live link.
CREATE TABLE IF NOT EXISTS monitoring_dlm.findings (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               UUID NOT NULL,
  finding_type            VARCHAR(64) NOT NULL CHECK (finding_type IN (
                            'credential_reference','pii_exposure','source_code_leak',
                            'configuration_leak','internal_document_leak',
                            'database_dump_reference','intellectual_property_leak')),
  title                   VARCHAR(512) NOT NULL,
  severity                VARCHAR(32) NOT NULL CHECK (severity IN (
                            'critical','high','medium','low','informational')),
  status                  VARCHAR(32) NOT NULL DEFAULT 'new' CHECK (status IN (
                            'new','triaged','enriched','escalated','suppressed','resolved','closed')),
  confidence_score        NUMERIC(5,4) CHECK (confidence_score >= 0 AND confidence_score <= 1),
  source_id               UUID,
  job_run_id              UUID,
  dedup_key               VARCHAR(512) NOT NULL,
  detection_method        VARCHAR(128),
  content_url             TEXT CHECK (content_url IS NULL OR content_url ~ '^hXXps?://'),
  content_excerpt         TEXT,
  content_hash            VARCHAR(128),
  source_published_at     TIMESTAMPTZ,
  suppression_reason      TEXT,
  suppressed_by           UUID,
  suppressed_at           TIMESTAMPTZ,
  prior_severity          VARCHAR(32),
  severity_overridden_by  UUID,
  severity_override_reason TEXT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by              UUID,
  updated_by              UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dlm_findings_dedup ON monitoring_dlm.findings (tenant_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_dlm_findings_tenant_status ON monitoring_dlm.findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dlm_findings_tenant_severity ON monitoring_dlm.findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_dlm_findings_tenant_type ON monitoring_dlm.findings (tenant_id, finding_type);
ALTER TABLE monitoring_dlm.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.findings;
CREATE POLICY tenant_isolation ON monitoring_dlm.findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_dlm.findings;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_dlm.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 4. Finding-asset linkages: which monitored assets a finding implicates. asset_id
-- is a cross-context reference to core_platform.assets (no FK).
CREATE TABLE IF NOT EXISTS monitoring_dlm.finding_assets (
  finding_id  UUID NOT NULL REFERENCES monitoring_dlm.findings(id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL,
  tenant_id   UUID NOT NULL,
  linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by   UUID,
  PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_dlm_finding_assets_asset_id ON monitoring_dlm.finding_assets (asset_id);
CREATE INDEX IF NOT EXISTS idx_dlm_finding_assets_tenant_id ON monitoring_dlm.finding_assets (tenant_id);
ALTER TABLE monitoring_dlm.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.finding_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.finding_assets;
CREATE POLICY tenant_isolation ON monitoring_dlm.finding_assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 5. Evidence: IMMUTABLE chain-of-custody captures for a finding. UPDATE/DELETE are
-- blocked by the shared public.prevent_mutation() trigger (Database Blueprint 1.4).
CREATE TABLE IF NOT EXISTS monitoring_dlm.evidence (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  finding_id     UUID REFERENCES monitoring_dlm.findings(id),
  evidence_type  VARCHAR(64) NOT NULL CHECK (evidence_type IN (
                   'content_snapshot','screenshot','raw_content_hash','metadata_capture')),
  storage_ref    VARCHAR(1024),
  content_hash   VARCHAR(128) NOT NULL,
  captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  capture_source VARCHAR(128) NOT NULL,
  metadata       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_dlm_evidence_finding_id ON monitoring_dlm.evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_dlm_evidence_tenant_id ON monitoring_dlm.evidence (tenant_id);
ALTER TABLE monitoring_dlm.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.evidence;
CREATE POLICY tenant_isolation ON monitoring_dlm.evidence
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_dlm_evidence ON monitoring_dlm.evidence;
CREATE TRIGGER immutable_dlm_evidence BEFORE UPDATE OR DELETE ON monitoring_dlm.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 6. Finding history: IMMUTABLE append-only audit of finding field changes.
CREATE TABLE IF NOT EXISTS monitoring_dlm.finding_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  finding_id    UUID NOT NULL,
  changed_field VARCHAR(128) NOT NULL,
  old_value     TEXT,
  new_value     TEXT,
  changed_by    UUID,
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dlm_finding_history_finding_id ON monitoring_dlm.finding_history (finding_id);
CREATE INDEX IF NOT EXISTS idx_dlm_finding_history_tenant_id ON monitoring_dlm.finding_history (tenant_id);
ALTER TABLE monitoring_dlm.finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dlm.finding_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dlm.finding_history;
CREATE POLICY tenant_isolation ON monitoring_dlm.finding_history
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_dlm_finding_history ON monitoring_dlm.finding_history;
CREATE TRIGGER immutable_dlm_finding_history BEFORE UPDATE OR DELETE ON monitoring_dlm.finding_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
