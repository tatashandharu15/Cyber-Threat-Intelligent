-- Dark Web Monitoring schema (monitoring_dwm). The DWM service owns the DDL for
-- the source-tier reference data, collection jobs, findings, threat actor
-- profiles, enrichments, evidence, and history tables. Row-level security is
-- enabled and FORCED on every tenant-scoped table so the tenant_isolation
-- policies apply even to the schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, asset_id, created_by, suppressed_by,
-- etc.) are plain UUID columns WITHOUT hard foreign keys to other schemas; within
-- this single schema, foreign keys are retained.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- monitoring_dwm schema itself.
--
-- DWM-specific privacy rules baked into this schema:
--   * DWM-BR-001 / DWM-NFR-004: dark web collection infrastructure identifiers and
--     source access details must NEVER appear in analyst-facing finding records.
--     Findings therefore reference only a source_tier_id (a coarse classification);
--     there is NO adapter URL or source-config column anywhere in this schema.
--   * DWM-BR-002: threat actor profiles must not auto-attribute real identity;
--     identity_confirmed defaults false and requires explicit analyst confirmation.
--   * DWM-FR-009 / DWM-BR-003: network_access_sale findings receive mandatory
--     elevated severity (enforced by the service layer before insert).
--   * Threat URLs are stored DEFANGED so an operator can never click a live link.

-- 1. Source tiers: a GLOBAL platform reference classifying dark web sources by tier.
-- This is reference data shared across tenants: it carries NO tenant_id and is NOT
-- under RLS. It deliberately exposes only a coarse tier classification and never the
-- underlying adapter configuration or routing metadata (DWM-BR-001 / DWM-NFR-004).
CREATE TABLE IF NOT EXISTS monitoring_dwm.source_tiers (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tier_code     VARCHAR(64) NOT NULL UNIQUE CHECK (tier_code IN (
                  'tier_1_dark_forum','tier_2_market','tier_3_telegram','tier_4_i2p')),
  display_name  VARCHAR(255) NOT NULL,
  reliability   NUMERIC(3,2) CHECK (reliability IS NULL OR (reliability >= 0 AND reliability <= 1)),
  status        VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                  'active','paused','retired')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_dwm.source_tiers;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_dwm.source_tiers
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- Seed the four default source tiers. Reliability values are conservative defaults
-- reflecting the relative trustworthiness of each tier; administrators may tune them.
INSERT INTO monitoring_dwm.source_tiers (tier_code, display_name, reliability) VALUES
  ('tier_1_dark_forum', 'Tier 1 - Established Dark Web Forum', 0.85),
  ('tier_2_market',     'Tier 2 - Illicit Marketplace',       0.70),
  ('tier_3_telegram',   'Tier 3 - Approved Telegram Channel',  0.55),
  ('tier_4_i2p',        'Tier 4 - I2P / Eepsite Resource',     0.40)
ON CONFLICT (tier_code) DO NOTHING;

-- 2. Collection jobs: a single execution of a collection run against a source tier.
-- There is intentionally NO adapter config column here (DWM-BR-001): the job records
-- only the coarse source tier it ran against, its lifecycle status, and counts.
CREATE TABLE IF NOT EXISTS monitoring_dwm.collection_jobs (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  source_tier_id    UUID REFERENCES monitoring_dwm.source_tiers(id),
  status            VARCHAR(32) NOT NULL DEFAULT 'running' CHECK (status IN (
                      'running','completed','failed','cancelled')),
  trigger_type      VARCHAR(32) NOT NULL CHECK (trigger_type IN ('scheduled','on_demand')),
  findings_ingested INT NOT NULL DEFAULT 0,
  errors_count      INT NOT NULL DEFAULT 0,
  started_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dwm_jobs_tenant_id ON monitoring_dwm.collection_jobs (tenant_id);
CREATE INDEX IF NOT EXISTS idx_dwm_jobs_source_tier_id ON monitoring_dwm.collection_jobs (source_tier_id);
ALTER TABLE monitoring_dwm.collection_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.collection_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.collection_jobs;
CREATE POLICY tenant_isolation ON monitoring_dwm.collection_jobs
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Findings: the dark web detections produced by collection or manual submission.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at (e.g. findings_2026_06) to keep the hot
-- set small and enable partition pruning; that is intentionally deferred here.
--
-- DWM-BR-001 / DWM-BR-008: findings reference only source_tier_id and job_run_id and
-- never the underlying adapter configuration or source access details.
--
-- The content_url_defanged CHECK enforces that any stored URL is defanged
-- ('hXXp[s]://...') so an operator handling dark web references never clicks a live link.
CREATE TABLE IF NOT EXISTS monitoring_dwm.findings (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               UUID NOT NULL,
  finding_type            VARCHAR(64) NOT NULL CHECK (finding_type IN (
                            'sale_listing','network_access_sale','data_breach_advertisement',
                            'threat_actor_mention','threat_discussion',
                            'malware_distribution_reference','organizational_intelligence_reference')),
  title                   VARCHAR(512) NOT NULL,
  severity                VARCHAR(32) NOT NULL CHECK (severity IN (
                            'critical','high','medium','low','informational')),
  status                  VARCHAR(32) NOT NULL DEFAULT 'new' CHECK (status IN (
                            'new','triaged','enriched','escalated','suppressed','resolved','closed')),
  confidence_score        NUMERIC(5,4) CHECK (confidence_score >= 0 AND confidence_score <= 1),
  source_tier_id          UUID,
  job_run_id              UUID,
  dedup_key               VARCHAR(512) NOT NULL,
  content_excerpt         TEXT,
  content_hash            VARCHAR(128),
  content_url_defanged    TEXT CHECK (content_url_defanged IS NULL OR content_url_defanged ~ '^hXXps?://'),
  observed_at             TIMESTAMPTZ,
  submission_type         VARCHAR(32) NOT NULL DEFAULT 'automated' CHECK (submission_type IN (
                            'automated','manual')),
  manual_source_type      VARCHAR(128),
  manual_collection_method TEXT,
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
CREATE UNIQUE INDEX IF NOT EXISTS idx_dwm_findings_dedup ON monitoring_dwm.findings (tenant_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_dwm_findings_tenant_status ON monitoring_dwm.findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_dwm_findings_tenant_severity ON monitoring_dwm.findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_dwm_findings_tenant_type ON monitoring_dwm.findings (tenant_id, finding_type);
ALTER TABLE monitoring_dwm.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.findings;
CREATE POLICY tenant_isolation ON monitoring_dwm.findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_dwm.findings;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_dwm.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 4. Threat actor profiles: analyst-maintained adversary dossiers. identity_confirmed
-- defaults false and may only be set true with explicit analyst confirmation plus
-- justification (DWM-BR-002): the platform never auto-attributes a real identity.
CREATE TABLE IF NOT EXISTS monitoring_dwm.threat_actor_profiles (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id              UUID NOT NULL,
  codename               VARCHAR(255) NOT NULL,
  description            TEXT,
  identity_confirmed     BOOLEAN NOT NULL DEFAULT FALSE,
  identity_confirmed_by  UUID,
  identity_confirmed_at  TIMESTAMPTZ,
  identity_justification TEXT,
  aliases                TEXT[],
  tactics                TEXT[],
  status                 VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                           'active','archived')),
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by             UUID,
  updated_by             UUID
);
CREATE INDEX IF NOT EXISTS idx_dwm_actors_tenant_id ON monitoring_dwm.threat_actor_profiles (tenant_id);
ALTER TABLE monitoring_dwm.threat_actor_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.threat_actor_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.threat_actor_profiles;
CREATE POLICY tenant_isolation ON monitoring_dwm.threat_actor_profiles
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_dwm.threat_actor_profiles;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_dwm.threat_actor_profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 5. Finding-threat-actor links: an explicit, analyst-confirmed association between a
-- finding and a threat actor profile. confirmed_by and justification are mandatory:
-- every linkage requires explicit analyst confirmation (DWM-FR-013 / DWM-BR-002).
CREATE TABLE IF NOT EXISTS monitoring_dwm.finding_threat_actor_links (
  finding_id       UUID NOT NULL REFERENCES monitoring_dwm.findings(id) ON DELETE CASCADE,
  threat_actor_id  UUID NOT NULL REFERENCES monitoring_dwm.threat_actor_profiles(id),
  tenant_id        UUID NOT NULL,
  confirmed_by     UUID NOT NULL,
  confirmed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  justification    TEXT NOT NULL,
  PRIMARY KEY (finding_id, threat_actor_id)
);
CREATE INDEX IF NOT EXISTS idx_dwm_fta_links_actor_id ON monitoring_dwm.finding_threat_actor_links (threat_actor_id);
CREATE INDEX IF NOT EXISTS idx_dwm_fta_links_tenant_id ON monitoring_dwm.finding_threat_actor_links (tenant_id);
ALTER TABLE monitoring_dwm.finding_threat_actor_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.finding_threat_actor_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.finding_threat_actor_links;
CREATE POLICY tenant_isolation ON monitoring_dwm.finding_threat_actor_links
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 6. Finding enrichments: analyst-added structured threat context (DWM-FR-014).
CREATE TABLE IF NOT EXISTS monitoring_dwm.finding_enrichments (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           UUID NOT NULL,
  finding_id          UUID REFERENCES monitoring_dwm.findings(id),
  tactics_observed    TEXT[],
  affected_asset_scope TEXT,
  response_indicators TEXT,
  enriched_by         UUID,
  enriched_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dwm_enrichments_finding_id ON monitoring_dwm.finding_enrichments (finding_id);
CREATE INDEX IF NOT EXISTS idx_dwm_enrichments_tenant_id ON monitoring_dwm.finding_enrichments (tenant_id);
ALTER TABLE monitoring_dwm.finding_enrichments ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.finding_enrichments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.finding_enrichments;
CREATE POLICY tenant_isolation ON monitoring_dwm.finding_enrichments
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 7. Finding-asset linkages: which monitored asset keywords a finding implicates.
-- asset_id is a cross-context reference to core_platform.assets (no FK).
CREATE TABLE IF NOT EXISTS monitoring_dwm.finding_assets (
  finding_id  UUID NOT NULL REFERENCES monitoring_dwm.findings(id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL,
  tenant_id   UUID NOT NULL,
  linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by   UUID,
  PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_dwm_finding_assets_asset_id ON monitoring_dwm.finding_assets (asset_id);
CREATE INDEX IF NOT EXISTS idx_dwm_finding_assets_tenant_id ON monitoring_dwm.finding_assets (tenant_id);
ALTER TABLE monitoring_dwm.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.finding_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.finding_assets;
CREATE POLICY tenant_isolation ON monitoring_dwm.finding_assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 8. Evidence: IMMUTABLE chain-of-custody captures for a finding. UPDATE/DELETE are
-- blocked by the shared public.prevent_mutation() trigger (Database Blueprint 1.4).
-- evidence_type intentionally references only a coarse source_tier_record and never
-- the underlying adapter/source identity (DWM-BR-001 / DWM-NFR-004).
CREATE TABLE IF NOT EXISTS monitoring_dwm.evidence (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  finding_id     UUID REFERENCES monitoring_dwm.findings(id),
  evidence_type  VARCHAR(64) NOT NULL CHECK (evidence_type IN (
                   'content_snapshot','metadata_capture','source_tier_record')),
  content_hash   VARCHAR(128) NOT NULL,
  storage_ref    VARCHAR(1024),
  captured_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  metadata       JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_dwm_evidence_finding_id ON monitoring_dwm.evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_dwm_evidence_tenant_id ON monitoring_dwm.evidence (tenant_id);
ALTER TABLE monitoring_dwm.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.evidence;
CREATE POLICY tenant_isolation ON monitoring_dwm.evidence
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_dwm_evidence ON monitoring_dwm.evidence;
CREATE TRIGGER immutable_dwm_evidence BEFORE UPDATE OR DELETE ON monitoring_dwm.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 9. Finding history: IMMUTABLE append-only audit of finding field changes.
CREATE TABLE IF NOT EXISTS monitoring_dwm.finding_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  finding_id    UUID NOT NULL,
  changed_field VARCHAR(128) NOT NULL,
  old_value     TEXT,
  new_value     TEXT,
  changed_by    UUID,
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dwm_finding_history_finding_id ON monitoring_dwm.finding_history (finding_id);
CREATE INDEX IF NOT EXISTS idx_dwm_finding_history_tenant_id ON monitoring_dwm.finding_history (tenant_id);
ALTER TABLE monitoring_dwm.finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_dwm.finding_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_dwm.finding_history;
CREATE POLICY tenant_isolation ON monitoring_dwm.finding_history
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_dwm_finding_history ON monitoring_dwm.finding_history;
CREATE TRIGGER immutable_dwm_finding_history BEFORE UPDATE OR DELETE ON monitoring_dwm.finding_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
