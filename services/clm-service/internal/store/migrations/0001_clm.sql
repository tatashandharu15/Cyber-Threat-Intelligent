-- Credential Leak Monitoring schema (monitoring_clm). The CLM service owns the DDL
-- for the breach-source, collection, finding, affected-user, evidence, and history
-- tables. Row-level security is enabled and FORCED so the tenant_isolation policies
-- apply even to the schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, asset_id, created_by, suppressed_by,
-- user_id, etc.) are plain UUID columns WITHOUT hard foreign keys to other schemas;
-- within this single schema, foreign keys are retained.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- monitoring_clm schema itself.
--
-- CLM-BR-001 (CRITICAL): cleartext credential values must NEVER be stored in
-- platform storage in unmasked form. The findings table deliberately has NO column
-- for a raw/cleartext credential value; only a masked_indicator is persisted.

-- 1. Breach sources: the configured breach/credential intelligence sources CLM
-- ingests from.
CREATE TABLE IF NOT EXISTS monitoring_clm.breach_sources (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  source_name   VARCHAR(255) NOT NULL,
  source_tier   VARCHAR(32) NOT NULL CHECK (source_tier IN (
                  'tier_1','tier_2','tier_3')),
  adapter_type  VARCHAR(64) NOT NULL CHECK (adapter_type IN (
                  'breach_feed_api','stealer_log_feed','credential_intelligence_api','manual')),
  status        VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                  'active','paused','retired','error')),
  last_run_at   TIMESTAMPTZ,
  last_error    TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID,
  updated_by    UUID
);
CREATE INDEX IF NOT EXISTS idx_clm_sources_tenant_id ON monitoring_clm.breach_sources (tenant_id);
ALTER TABLE monitoring_clm.breach_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.breach_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.breach_sources;
CREATE POLICY tenant_isolation ON monitoring_clm.breach_sources
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_clm.breach_sources;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_clm.breach_sources
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Collection jobs: a single execution of a breach source ingestion run.
CREATE TABLE IF NOT EXISTS monitoring_clm.collection_jobs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  source_id         UUID REFERENCES monitoring_clm.breach_sources(id),
  status            VARCHAR(32) NOT NULL DEFAULT 'running' CHECK (status IN (
                      'running','completed','failed','cancelled')),
  trigger_type      VARCHAR(32) NOT NULL CHECK (trigger_type IN ('scheduled','on_demand')),
  findings_ingested INT NOT NULL DEFAULT 0,
  errors_count      INT NOT NULL DEFAULT 0,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at      TIMESTAMPTZ,
  error_detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_clm_jobs_tenant_id ON monitoring_clm.collection_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_clm_jobs_source_id ON monitoring_clm.collection_jobs (source_id);
ALTER TABLE monitoring_clm.collection_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.collection_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.collection_jobs;
CREATE POLICY tenant_isolation ON monitoring_clm.collection_jobs
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Findings: the credential-leak detections produced by collection.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at (e.g. findings_2026_06) to keep the hot
-- set small and enable partition pruning; that is intentionally deferred here.
--
-- CLM-BR-001 (CRITICAL): there is intentionally NO column for a raw/cleartext
-- credential value. masked_indicator stores ONLY a masked representation, and
-- masking_policy_version records which deterministic masking policy produced it
-- (CLM-FR-003 / CLM-NFR-002 / CLM-VR-006).
CREATE TABLE IF NOT EXISTS monitoring_clm.findings (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               UUID NOT NULL,
  credential_type         VARCHAR(64) NOT NULL CHECK (credential_type IN (
                            'cleartext_credential','hashed_credential','api_key',
                            'service_account_token','oauth_token','session_token',
                            'certificate_private_key')),
  masked_indicator        VARCHAR(512) NOT NULL,
  masking_policy_version  VARCHAR(32) NOT NULL,
  severity                VARCHAR(32) NOT NULL CHECK (severity IN (
                            'critical','high','medium','low','informational')),
  status                  VARCHAR(32) NOT NULL DEFAULT 'new' CHECK (status IN (
                            'new','triaged','escalated','notified','suppressed','resolved','closed')),
  confidence_score        NUMERIC(5,4) CHECK (confidence_score >= 0 AND confidence_score <= 1),
  breach_source_id        UUID,
  job_run_id              UUID,
  breach_name             VARCHAR(512),
  breach_publication_date DATE,
  dedup_key               VARCHAR(512) NOT NULL,
  affected_user_count     INT,
  user_correlation_state  VARCHAR(32) NOT NULL DEFAULT 'not_applicable' CHECK (user_correlation_state IN (
                            'not_applicable','pending','completed','no_linkage')),
  suppression_reason      TEXT,
  suppressed_by           UUID,
  suppressed_at           TIMESTAMPTZ,
  prior_severity          VARCHAR(32),
  severity_overridden_by  UUID,
  severity_override_reason TEXT,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by              UUID,
  updated_by              UUID,
  UNIQUE (tenant_id, dedup_key)
);
CREATE INDEX IF NOT EXISTS idx_clm_findings_tenant_status ON monitoring_clm.findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_clm_findings_tenant_severity ON monitoring_clm.findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_clm_findings_tenant_type ON monitoring_clm.findings (tenant_id, credential_type);
ALTER TABLE monitoring_clm.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.findings;
CREATE POLICY tenant_isolation ON monitoring_clm.findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_clm.findings;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_clm.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 4. Finding-asset linkages: which monitored assets a finding implicates. asset_id
-- is a cross-context reference to core_platform.assets (no FK).
CREATE TABLE IF NOT EXISTS monitoring_clm.finding_assets (
  finding_id  UUID NOT NULL REFERENCES monitoring_clm.findings(id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL,
  tenant_id   UUID NOT NULL,
  linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by   UUID,
  PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_clm_finding_assets_asset_id ON monitoring_clm.finding_assets (asset_id);
CREATE INDEX IF NOT EXISTS idx_clm_finding_assets_tenant_id ON monitoring_clm.finding_assets (tenant_id);
ALTER TABLE monitoring_clm.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.finding_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.finding_assets;
CREATE POLICY tenant_isolation ON monitoring_clm.finding_assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 5. Affected users: tenant user accounts correlated to a breach finding (CLM-FR-007).
-- email is masked here too (CLM-BR-001 / CLM-NFR-004) — raw PII is never stored in
-- cleartext beyond what the masking policy allows.
CREATE TABLE IF NOT EXISTS monitoring_clm.affected_users (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  finding_id     UUID NOT NULL REFERENCES monitoring_clm.findings(id) ON DELETE CASCADE,
  user_id        UUID,
  email_masked   VARCHAR(512) NOT NULL,
  directory_ref  VARCHAR(512),
  correlated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_clm_affected_users_finding_id ON monitoring_clm.affected_users (finding_id);
CREATE INDEX IF NOT EXISTS idx_clm_affected_users_tenant_id ON monitoring_clm.affected_users (tenant_id);
ALTER TABLE monitoring_clm.affected_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.affected_users FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.affected_users;
CREATE POLICY tenant_isolation ON monitoring_clm.affected_users
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 6. Evidence: IMMUTABLE chain-of-custody captures for a finding. UPDATE/DELETE are
-- blocked by the shared public.prevent_mutation() trigger (Database Blueprint 1.4).
CREATE TABLE IF NOT EXISTS monitoring_clm.evidence (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  finding_id     UUID REFERENCES monitoring_clm.findings(id),
  evidence_type  VARCHAR(64) NOT NULL CHECK (evidence_type IN (
                   'breach_metadata','source_reference','ingestion_record')),
  content_hash   VARCHAR(128) NOT NULL,
  storage_ref    VARCHAR(1024),
  captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_clm_evidence_finding_id ON monitoring_clm.evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_clm_evidence_tenant_id ON monitoring_clm.evidence (tenant_id);
ALTER TABLE monitoring_clm.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.evidence;
CREATE POLICY tenant_isolation ON monitoring_clm.evidence
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_clm_evidence ON monitoring_clm.evidence;
CREATE TRIGGER immutable_clm_evidence BEFORE UPDATE OR DELETE ON monitoring_clm.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 7. Finding history: IMMUTABLE append-only audit of finding field changes.
CREATE TABLE IF NOT EXISTS monitoring_clm.finding_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  finding_id    UUID NOT NULL,
  changed_field VARCHAR(128) NOT NULL,
  old_value     TEXT,
  new_value     TEXT,
  changed_by    UUID,
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_clm_finding_history_finding_id ON monitoring_clm.finding_history (finding_id);
CREATE INDEX IF NOT EXISTS idx_clm_finding_history_tenant_id ON monitoring_clm.finding_history (tenant_id);
ALTER TABLE monitoring_clm.finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_clm.finding_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_clm.finding_history;
CREATE POLICY tenant_isolation ON monitoring_clm.finding_history
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_clm_finding_history ON monitoring_clm.finding_history;
CREATE TRIGGER immutable_clm_finding_history BEFORE UPDATE OR DELETE ON monitoring_clm.finding_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
