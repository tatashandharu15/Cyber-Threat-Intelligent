-- Audit Log schema (platform_services). The Audit Log service owns the DDL for the
-- tamper-evident audit_events table. Every row carries an HMAC signature computed
-- by the emitting service (or this service) over its security-relevant fields, so a
-- mutated or deleted record is detectable.
--
-- Cross-bounded-context references (tenant_id, actor_id, resource_id, request_id)
-- are plain UUID columns WITHOUT hard foreign keys to other schemas.
--
-- The shared trigger function public.prevent_mutation() and the platform_services
-- schema are created by infra/docker/init/01-init.sql.
--
-- NOTE: the Database Blueprint envisions this table with NO row-level security
-- (Security-Auditor-only access enforced at the application/role layer) plus monthly
-- RANGE partitioning on created_at in production. For the MVP we instead apply
-- standard RLS + FORCE ROW LEVEL SECURITY for consistency with the WithTenant
-- pattern used by every other service, and keep the table un-partitioned.

CREATE TABLE IF NOT EXISTS platform_services.audit_events (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       UUID NOT NULL,
  actor_id        UUID NOT NULL,
  actor_type      VARCHAR(32) NOT NULL DEFAULT 'user' CHECK (actor_type IN (
                    'user','service_account','system')),
  event_type      VARCHAR(128) NOT NULL,
  resource_type   VARCHAR(128) NOT NULL,
  resource_id     UUID,
  action          VARCHAR(64) NOT NULL,
  outcome         VARCHAR(32) NOT NULL DEFAULT 'success' CHECK (outcome IN (
                    'success','failure','partial')),
  ip_address      INET,
  user_agent      TEXT,
  request_id      UUID,
  event_payload   JSONB NOT NULL DEFAULT '{}',
  hmac_signature  VARCHAR(128) NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_created ON platform_services.audit_events (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_event_type ON platform_services.audit_events (tenant_id, event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_resource ON platform_services.audit_events (tenant_id, resource_type, resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_tenant_actor ON platform_services.audit_events (tenant_id, actor_id);

-- IMMUTABLE: audit records are append-only. The shared public.prevent_mutation()
-- trigger blocks UPDATE and DELETE so the tamper-evident chain cannot be rewritten.
DROP TRIGGER IF EXISTS immutable_audit_events ON platform_services.audit_events;
CREATE TRIGGER immutable_audit_events BEFORE UPDATE OR DELETE ON platform_services.audit_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();

ALTER TABLE platform_services.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.audit_events;
CREATE POLICY tenant_isolation ON platform_services.audit_events
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
