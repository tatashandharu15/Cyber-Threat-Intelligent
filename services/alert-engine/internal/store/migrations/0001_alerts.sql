-- Alert Engine schema (platform_services). Owns alert_rules and alerts. RLS is
-- enabled and FORCED so the tenant_isolation policies apply to the schema-owning
-- `cti` role. Cross-context references (source_finding_id, acknowledged_by, etc.)
-- are plain UUID columns without hard foreign keys.
--
-- The platform_services schema and shared trigger functions are created by
-- infra/docker/init/01-init.sql.

-- Alert rules: tenant-defined criteria that turn escalated findings into alerts.
CREATE TABLE IF NOT EXISTS platform_services.alert_rules (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL,
  name          VARCHAR(255) NOT NULL,
  description   TEXT,
  source_module VARCHAR(32) CHECK (source_module IS NULL OR source_module IN
                  ('dlm','clm','dwm','brm','phm','any')),
  conditions    JSONB NOT NULL DEFAULT '{}',
  status        VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','archived')),
  webhook_url   TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by    UUID,
  updated_by    UUID
);
CREATE INDEX IF NOT EXISTS idx_alert_rules_tenant ON platform_services.alert_rules (tenant_id, status);
ALTER TABLE platform_services.alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.alert_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.alert_rules;
CREATE POLICY tenant_isolation ON platform_services.alert_rules
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.alert_rules;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.alert_rules
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- Alerts: created when an escalated finding matches an active alert rule.
--
-- For the MVP this is a PLAIN table. In production the Database Blueprint specifies
-- monthly RANGE partitioning on created_at; that is intentionally deferred here.
CREATE TABLE IF NOT EXISTS platform_services.alerts (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  alert_rule_id     UUID,
  source_module     VARCHAR(32) NOT NULL CHECK (source_module IN ('dlm','clm','dwm','brm','phm')),
  source_finding_id UUID NOT NULL,
  correlation_id    UUID,
  title             VARCHAR(512) NOT NULL,
  description       TEXT,
  severity          VARCHAR(32) NOT NULL CHECK (severity IN ('critical','high','medium','low','informational')),
  status            VARCHAR(32) NOT NULL DEFAULT 'open' CHECK (status IN
                      ('open','acknowledged','in_progress','resolved','closed','false_positive')),
  acknowledged_by   UUID,
  acknowledged_at   TIMESTAMPTZ,
  resolved_by       UUID,
  resolved_at       TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON platform_services.alerts (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_severity ON platform_services.alerts (tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_finding ON platform_services.alerts (source_module, source_finding_id);
ALTER TABLE platform_services.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.alerts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.alerts;
CREATE POLICY tenant_isolation ON platform_services.alerts
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.alerts;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.alerts
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
