-- Takedown schema (platform_services). The Takedown service owns the DDL for the
-- takedown request and takedown event tables. Row-level security is enabled and
-- FORCED so the tenant_isolation policies apply even to the schema-owning `cti`
-- role.
--
-- Cross-bounded-context references (tenant_id, source_finding_id, requested_by,
-- closed_by, created_by, etc.) are plain UUID columns WITHOUT hard foreign keys to
-- other schemas; within this single schema there are no cross-schema FKs.
--
-- The shared trigger functions public.update_updated_at() and
-- public.prevent_mutation() are created by infra/docker/init/01-init.sql, as is the
-- platform_services schema itself.

-- 1. Takedown requests: the lifecycle record for a takedown submitted to an
-- external operator (registrar, app store, social platform, hosting provider, or
-- certificate authority) on behalf of a BRM/PHM finding.
CREATE TABLE IF NOT EXISTS platform_services.takedown_requests (
  id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id              UUID NOT NULL,
  source_module          VARCHAR(32) NOT NULL CHECK (source_module IN ('brm','phm')),
  source_finding_id      UUID NOT NULL,
  status                 VARCHAR(32) NOT NULL DEFAULT 'draft' CHECK (status IN (
                           'draft','submitted','acknowledged','actioned','rejected','closed')),
  submission_target      VARCHAR(512) NOT NULL,
  submission_target_type VARCHAR(64) NOT NULL CHECK (submission_target_type IN (
                           'registrar','app_store_operator','social_platform',
                           'hosting_provider','cert_authority')),
  evidence_package_ref   VARCHAR(1024) NOT NULL,
  requested_by           UUID,
  submitted_at           TIMESTAMPTZ,
  acknowledged_at        TIMESTAMPTZ,
  actioned_at            TIMESTAMPTZ,
  rejected_at            TIMESTAMPTZ,
  operator_response      TEXT,
  closed_at              TIMESTAMPTZ,
  closed_by              UUID,
  created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by             UUID,
  updated_by             UUID
);
CREATE INDEX IF NOT EXISTS idx_takedown_requests_tenant_status ON platform_services.takedown_requests (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_takedown_requests_source ON platform_services.takedown_requests (source_module, source_finding_id);
ALTER TABLE platform_services.takedown_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.takedown_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.takedown_requests;
CREATE POLICY tenant_isolation ON platform_services.takedown_requests
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.takedown_requests;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.takedown_requests
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Takedown events: IMMUTABLE append-only accountability chain for each takedown
-- request (created, status_changed, ...). UPDATE/DELETE are blocked by the shared
-- public.prevent_mutation() trigger to preserve the legal accountability chain
-- (BRM-NFR-008).
CREATE TABLE IF NOT EXISTS platform_services.takedown_events (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  takedown_id UUID NOT NULL,
  event_type  VARCHAR(64) NOT NULL,
  detail      TEXT,
  actor_id    UUID,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_takedown_events_takedown_id ON platform_services.takedown_events (takedown_id);
ALTER TABLE platform_services.takedown_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.takedown_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.takedown_events;
CREATE POLICY tenant_isolation ON platform_services.takedown_events
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_takedown_events ON platform_services.takedown_events;
CREATE TRIGGER immutable_takedown_events BEFORE UPDATE OR DELETE ON platform_services.takedown_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
