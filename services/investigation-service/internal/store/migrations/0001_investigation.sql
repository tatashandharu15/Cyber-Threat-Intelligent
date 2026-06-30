-- Investigation service schema (platform_services). The Investigation service owns
-- the DDL for investigations, the findings linked into them, the immutable
-- investigation timeline, and the alert inbox populated by the alert.created
-- consumer. Row-level security is enabled and FORCED so the tenant_isolation
-- policies apply even to the schema-owning `cti` role.
--
-- Cross-bounded-context references (assigned_to, alert_id, source_finding_id,
-- created_by, etc.) are plain UUID columns WITHOUT hard foreign keys to other
-- schemas; within this single schema, foreign keys are retained.
--
-- The platform_services schema and the shared trigger functions
-- public.update_updated_at() and public.prevent_mutation() are created by
-- infra/docker/init/01-init.sql.

-- 1. Investigations: the case records analysts open to consolidate related findings.
CREATE TABLE IF NOT EXISTS platform_services.investigations (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    UUID NOT NULL,
  title        VARCHAR(512) NOT NULL,
  description  TEXT,
  status       VARCHAR(32) NOT NULL DEFAULT 'open' CHECK (status IN (
                 'open','in_progress','pending_review','closed')),
  priority     VARCHAR(32) NOT NULL DEFAULT 'medium' CHECK (priority IN (
                 'critical','high','medium','low')),
  assigned_to  UUID,
  closed_at    TIMESTAMPTZ,
  closed_by    UUID,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by   UUID,
  updated_by   UUID
);
CREATE INDEX IF NOT EXISTS idx_investigations_tenant_status ON platform_services.investigations (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_investigations_tenant_priority ON platform_services.investigations (tenant_id, priority);
ALTER TABLE platform_services.investigations ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.investigations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.investigations;
CREATE POLICY tenant_isolation ON platform_services.investigations
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.investigations;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.investigations
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Investigation findings: the detection-module findings linked into a case.
-- source_finding_id is a cross-context reference to the owning module's schema
-- (no FK).
CREATE TABLE IF NOT EXISTS platform_services.investigation_findings (
  investigation_id  UUID NOT NULL REFERENCES platform_services.investigations(id) ON DELETE CASCADE,
  source_module     VARCHAR(32) NOT NULL,
  source_finding_id UUID NOT NULL,
  tenant_id         UUID NOT NULL,
  notes             TEXT,
  linked_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  linked_by         UUID,
  PRIMARY KEY (investigation_id, source_module, source_finding_id)
);
CREATE INDEX IF NOT EXISTS idx_investigation_findings_tenant_id ON platform_services.investigation_findings (tenant_id);
ALTER TABLE platform_services.investigation_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.investigation_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.investigation_findings;
CREATE POLICY tenant_isolation ON platform_services.investigation_findings
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 3. Investigation timeline: IMMUTABLE append-only audit of case activity.
-- UPDATE/DELETE are blocked by the shared public.prevent_mutation() trigger.
CREATE TABLE IF NOT EXISTS platform_services.investigation_timeline (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id        UUID NOT NULL,
  investigation_id UUID NOT NULL,
  entry_type       VARCHAR(64) NOT NULL,
  detail           TEXT,
  actor_id         UUID,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_investigation_timeline_investigation_id ON platform_services.investigation_timeline (investigation_id);
ALTER TABLE platform_services.investigation_timeline ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.investigation_timeline FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.investigation_timeline;
CREATE POLICY tenant_isolation ON platform_services.investigation_timeline
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_investigation_timeline ON platform_services.investigation_timeline;
CREATE TRIGGER immutable_investigation_timeline BEFORE UPDATE OR DELETE ON platform_services.investigation_timeline
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

-- 4. Investigation alert inbox: the alert.created events fanned out to the
-- Investigation service, awaiting an analyst to link them into a case. Populated
-- by the alert.created Kafka consumer.
CREATE TABLE IF NOT EXISTS platform_services.investigation_alert_inbox (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  alert_id          UUID NOT NULL,
  source_module     VARCHAR(32) NOT NULL,
  source_finding_id UUID NOT NULL,
  severity          VARCHAR(32),
  title             VARCHAR(512),
  linked            BOOLEAN NOT NULL DEFAULT FALSE,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, alert_id)
);
CREATE INDEX IF NOT EXISTS idx_investigation_alert_inbox_tenant_linked ON platform_services.investigation_alert_inbox (tenant_id, linked);
ALTER TABLE platform_services.investigation_alert_inbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.investigation_alert_inbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.investigation_alert_inbox;
CREATE POLICY tenant_isolation ON platform_services.investigation_alert_inbox
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
