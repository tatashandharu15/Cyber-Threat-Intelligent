-- Phishing Monitoring schema (monitoring_phm). The PHM service owns the DDL for
-- the collection, campaign, finding, indicator, certificate, evidence, and history
-- tables. Row-level security is enabled and FORCED so the tenant_isolation
-- policies apply even to the schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, asset_id, created_by, suppressed_by,
-- source_id, job_run_id, etc.) are plain UUID columns WITHOUT hard foreign keys to
-- other schemas; within this single schema, foreign keys are retained.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- monitoring_phm schema itself.

-- 1. Collection sources: the configured intelligence sources PHM ingests from.
CREATE TABLE IF NOT EXISTS monitoring_phm.collection_sources (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  source_type   VARCHAR(64) NOT NULL CHECK (source_type IN (
                  'certificate_transparency_feed','domain_registration_feed',
                  'url_reputation_feed','threat_intelligence_feed','manual_submission')),
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
CREATE INDEX IF NOT EXISTS idx_phm_sources_tenant_id ON monitoring_phm.collection_sources (tenant_id);
ALTER TABLE monitoring_phm.collection_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.collection_sources FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.collection_sources;
CREATE POLICY tenant_isolation ON monitoring_phm.collection_sources
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_phm.collection_sources;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_phm.collection_sources
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Campaigns: groupings of related phishing infrastructure (PHM-FR-006 dedup of
-- repeated observations of the same campaign).
CREATE TABLE IF NOT EXISTS monitoring_phm.campaigns (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  name          VARCHAR(512) NOT NULL,
  description   TEXT,
  status        VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                  'active','resolved','archived')),
  finding_count INT NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID,
  updated_by    UUID
);
CREATE INDEX IF NOT EXISTS idx_phm_campaigns_tenant_id ON monitoring_phm.campaigns (tenant_id);
ALTER TABLE monitoring_phm.campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.campaigns FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.campaigns;
CREATE POLICY tenant_isolation ON monitoring_phm.campaigns
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_phm.campaigns;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_phm.campaigns
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 3. Findings: the phishing detections produced by collection.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at (e.g. findings_2026_06) to keep the hot
-- set small and enable partition pruning; that is intentionally deferred here.
--
-- The phishing_url_defanged CHECK enforces that every stored URL is defanged
-- ('hXXp[s]://...') so that operators handling phishing references never click a
-- live link (PHM-FR-008, PHM-VR-005). PHM stores ONLY defanged URLs, so the column
-- is NOT NULL.
CREATE TABLE IF NOT EXISTS monitoring_phm.findings (
  id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id               UUID NOT NULL,
  finding_type            VARCHAR(64) NOT NULL CHECK (finding_type IN (
                            'active_phishing_page','credential_harvesting_page',
                            'brand_impersonation_page','malware_distribution_page',
                            'phishing_kit_deployment','spear_phishing_infrastructure',
                            'smishing_url')),
  title                   VARCHAR(512) NOT NULL,
  severity                VARCHAR(32) NOT NULL CHECK (severity IN (
                            'critical','high','medium','low','informational')),
  status                  VARCHAR(32) NOT NULL DEFAULT 'new' CHECK (status IN (
                            'new','triaged','confirmed','escalated','takedown_initiated',
                            'takedown_complete','suppressed','resolved','closed')),
  confidence_score        NUMERIC(5,4) CHECK (confidence_score >= 0 AND confidence_score <= 1),
  phishing_url_defanged   TEXT NOT NULL CHECK (phishing_url_defanged ~ '^hXXps?://'),
  hosting_ip              INET,
  hosting_asn             VARCHAR(64),
  hosting_country         CHAR(2),
  registrar               VARCHAR(255),
  registration_date       DATE,
  campaign_id             UUID REFERENCES monitoring_phm.campaigns(id),
  source_id               UUID,
  job_run_id              UUID,
  dedup_key               VARCHAR(512) NOT NULL,
  content_fingerprint     VARCHAR(128),
  source_finding_id       UUID,
  suppression_reason      TEXT,
  suppressed_by           UUID,
  suppressed_at           TIMESTAMPTZ,
  prior_severity          VARCHAR(32),
  severity_overridden_by  UUID,
  severity_override_reason TEXT,
  urgency_promoted        BOOLEAN NOT NULL DEFAULT FALSE,
  urgency_promoted_at     TIMESTAMPTZ,
  created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by              UUID,
  updated_by              UUID
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_phm_findings_dedup ON monitoring_phm.findings (tenant_id, dedup_key);
CREATE INDEX IF NOT EXISTS idx_phm_findings_tenant_status ON monitoring_phm.findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_phm_findings_tenant_severity ON monitoring_phm.findings (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_phm_findings_tenant_type ON monitoring_phm.findings (tenant_id, finding_type);
CREATE INDEX IF NOT EXISTS idx_phm_findings_campaign_id ON monitoring_phm.findings (campaign_id) WHERE campaign_id IS NOT NULL;
ALTER TABLE monitoring_phm.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.findings;
CREATE POLICY tenant_isolation ON monitoring_phm.findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_phm.findings;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_phm.findings
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 4. Indicators: structured IOCs extracted from confirmed findings (PHM-FR-015).
-- TLP markings gate sharing (PHM-FR-016, PHM-NFR-008).
CREATE TABLE IF NOT EXISTS monitoring_phm.indicators (
  id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      UUID NOT NULL,
  finding_id     UUID NOT NULL REFERENCES monitoring_phm.findings(id) ON DELETE CASCADE,
  indicator_type VARCHAR(32) NOT NULL CHECK (indicator_type IN (
                   'domain','ip_address','url_defanged','hash_md5','hash_sha1',
                   'hash_sha256','email_address','asn')),
  value          VARCHAR(1024) NOT NULL,
  tlp_marking    VARCHAR(16) NOT NULL DEFAULT 'TLP:AMBER' CHECK (tlp_marking IN (
                   'TLP:WHITE','TLP:GREEN','TLP:AMBER','TLP:RED')),
  confidence     NUMERIC(5,4) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by     UUID,
  updated_by     UUID
);
CREATE INDEX IF NOT EXISTS idx_phm_indicators_finding_id ON monitoring_phm.indicators (finding_id);
CREATE INDEX IF NOT EXISTS idx_phm_indicators_tenant_type_value ON monitoring_phm.indicators (tenant_id, indicator_type, value);
ALTER TABLE monitoring_phm.indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.indicators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.indicators;
CREATE POLICY tenant_isolation ON monitoring_phm.indicators
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON monitoring_phm.indicators;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON monitoring_phm.indicators
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 5. SSL certificates: IMMUTABLE certificate captures for a finding. Certificate
-- data captured at detection time must be preserved even after revocation,
-- expiry, or DNS change (PHM-BR-006, PHM-NFR-003). UPDATE/DELETE are blocked by the
-- shared public.prevent_mutation() trigger.
CREATE TABLE IF NOT EXISTS monitoring_phm.ssl_certificates (
  id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          UUID NOT NULL,
  finding_id         UUID,
  serial_number      VARCHAR(128) NOT NULL,
  issuer             VARCHAR(512),
  subject            VARCHAR(512),
  san_entries        TEXT[],
  not_before         TIMESTAMPTZ,
  not_after          TIMESTAMPTZ,
  fingerprint_sha256 VARCHAR(128),
  raw_cert_ref       VARCHAR(1024),
  captured_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_phm_certificates_finding_id ON monitoring_phm.ssl_certificates (finding_id);
CREATE INDEX IF NOT EXISTS idx_phm_certificates_tenant_id ON monitoring_phm.ssl_certificates (tenant_id);
ALTER TABLE monitoring_phm.ssl_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.ssl_certificates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.ssl_certificates;
CREATE POLICY tenant_isolation ON monitoring_phm.ssl_certificates
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_phm_certificates ON monitoring_phm.ssl_certificates;
CREATE TRIGGER immutable_phm_certificates BEFORE UPDATE OR DELETE ON monitoring_phm.ssl_certificates
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 6. Finding-asset linkages: which monitored assets a finding implicates. asset_id
-- is a cross-context reference to core_platform.assets (no FK).
CREATE TABLE IF NOT EXISTS monitoring_phm.finding_assets (
  finding_id  UUID NOT NULL REFERENCES monitoring_phm.findings(id) ON DELETE CASCADE,
  asset_id    UUID NOT NULL,
  tenant_id   UUID NOT NULL,
  linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by   UUID,
  PRIMARY KEY (finding_id, asset_id)
);
CREATE INDEX IF NOT EXISTS idx_phm_finding_assets_asset_id ON monitoring_phm.finding_assets (asset_id);
CREATE INDEX IF NOT EXISTS idx_phm_finding_assets_tenant_id ON monitoring_phm.finding_assets (tenant_id);
ALTER TABLE monitoring_phm.finding_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.finding_assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.finding_assets;
CREATE POLICY tenant_isolation ON monitoring_phm.finding_assets
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 7. Evidence: IMMUTABLE chain-of-custody captures for a finding. UPDATE/DELETE are
-- blocked by the shared public.prevent_mutation() trigger (Database Blueprint 1.4,
-- PHM-FR-007, PHM-NFR-003).
CREATE TABLE IF NOT EXISTS monitoring_phm.evidence (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  finding_id        UUID REFERENCES monitoring_phm.findings(id),
  evidence_type     VARCHAR(64) NOT NULL CHECK (evidence_type IN (
                      'screenshot','html_snapshot','dns_record','whois_snapshot',
                      'certificate_capture','content_fingerprint')),
  capture_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  content_hash      VARCHAR(128) NOT NULL,
  storage_ref       VARCHAR(1024),
  metadata          JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_phm_evidence_finding_id ON monitoring_phm.evidence (finding_id);
CREATE INDEX IF NOT EXISTS idx_phm_evidence_tenant_id ON monitoring_phm.evidence (tenant_id);
ALTER TABLE monitoring_phm.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.evidence;
CREATE POLICY tenant_isolation ON monitoring_phm.evidence
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_phm_evidence ON monitoring_phm.evidence;
CREATE TRIGGER immutable_phm_evidence BEFORE UPDATE OR DELETE ON monitoring_phm.evidence
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 8. Finding history: IMMUTABLE append-only audit of finding field changes.
CREATE TABLE IF NOT EXISTS monitoring_phm.finding_history (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  finding_id    UUID NOT NULL,
  changed_field VARCHAR(128) NOT NULL,
  old_value     TEXT,
  new_value     TEXT,
  changed_by    UUID,
  changed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_phm_finding_history_finding_id ON monitoring_phm.finding_history (finding_id);
CREATE INDEX IF NOT EXISTS idx_phm_finding_history_tenant_id ON monitoring_phm.finding_history (tenant_id);
ALTER TABLE monitoring_phm.finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE monitoring_phm.finding_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON monitoring_phm.finding_history;
CREATE POLICY tenant_isolation ON monitoring_phm.finding_history
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_phm_finding_history ON monitoring_phm.finding_history;
CREATE TRIGGER immutable_phm_finding_history BEFORE UPDATE OR DELETE ON monitoring_phm.finding_history
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
