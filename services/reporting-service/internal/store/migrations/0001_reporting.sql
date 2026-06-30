-- Reporting service schema (platform_services). Owns the reports table that tracks
-- requested, in-progress, completed, and failed report generations. RLS is enabled
-- and FORCED so the tenant_isolation policy applies even to the schema-owning `cti`
-- role.
--
-- Cross-bounded-context references (requested_by -> core_platform.users) are plain
-- UUID columns WITHOUT hard foreign keys to other schemas (Database Blueprint 8.9
-- specifies an FK; in this service-owned migration we follow the platform's
-- bounded-context rule and keep cross-schema references as plain UUIDs).
--
-- The platform_services schema and the shared trigger function
-- public.update_updated_at() are created by infra/docker/init/01-init.sql.

CREATE TABLE IF NOT EXISTS platform_services.reports (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  report_type     VARCHAR(64) NOT NULL CHECK (report_type IN (
                    'executive_summary','module_finding_report','takedown_status_report',
                    'credential_exposure_report','threat_actor_report','sla_compliance_report')),
  title           VARCHAR(512) NOT NULL,
  status          VARCHAR(32) NOT NULL DEFAULT 'queued' CHECK (status IN (
                    'queued','generating','complete','failed')),
  parameters      JSONB NOT NULL DEFAULT '{}',
  output_ref      VARCHAR(1024),
  output_format   VARCHAR(16) NOT NULL DEFAULT 'pdf' CHECK (output_format IN (
                    'pdf','csv','json','xlsx')),
  requested_by    UUID,
  generated_at    TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ,
  failure_reason  TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_status ON platform_services.reports (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_reports_tenant_type ON platform_services.reports (tenant_id, report_type);
ALTER TABLE platform_services.reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.reports FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.reports;
CREATE POLICY tenant_isolation ON platform_services.reports
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.reports;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.reports
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
