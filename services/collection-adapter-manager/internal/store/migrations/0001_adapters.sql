-- Collection Adapter Manager schema (platform_services). Owns the central registry
-- of per-module collection adapters and an immutable, append-only history of the
-- collection runs reported by the modules over Kafka.
--
-- RLS is enabled and FORCED so the tenant_isolation policies apply even to the
-- schema-owning `cti` role. Cross-bounded-context references (tenant_id, job_id,
-- created_by, updated_by) are plain UUID columns WITHOUT hard foreign keys to other
-- schemas.
--
-- The platform_services schema and the shared trigger functions
-- public.update_updated_at() and public.prevent_mutation() are created by
-- infra/docker/init/01-init.sql.

-- 1. Collection adapters: the registry of per-module collection adapters and their
-- current health. last_run_at / last_status / last_error / findings_last_run are
-- maintained from the collection.job.completed and collection.job.failed events.
CREATE TABLE IF NOT EXISTS platform_services.collection_adapters (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  module            VARCHAR(32) NOT NULL CHECK (module IN ('dlm','clm','dwm','brm','phm')),
  adapter_type      VARCHAR(64) NOT NULL,
  name              VARCHAR(255) NOT NULL,
  status            VARCHAR(32) NOT NULL DEFAULT 'active' CHECK (status IN (
                      'active','paused','retired','error')),
  schedule_cron     VARCHAR(128),
  config_ref        VARCHAR(512),
  last_run_at       TIMESTAMPTZ,
  last_status       VARCHAR(32),
  last_error        TEXT,
  findings_last_run INTEGER,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by        UUID,
  updated_by        UUID,
  UNIQUE (tenant_id, module, name)
);
CREATE INDEX IF NOT EXISTS idx_adapters_tenant_status ON platform_services.collection_adapters (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_adapters_tenant_module ON platform_services.collection_adapters (tenant_id, module);
ALTER TABLE platform_services.collection_adapters ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.collection_adapters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.collection_adapters;
CREATE POLICY tenant_isolation ON platform_services.collection_adapters
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.collection_adapters;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.collection_adapters
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- 2. Collection run events: IMMUTABLE append-only history of the collection runs
-- reported by the modules. Fed exclusively by the Kafka consumers for
-- collection.job.completed and collection.job.failed. UPDATE/DELETE are blocked by
-- the shared public.prevent_mutation() trigger (Database Blueprint 1.4).
CREATE TABLE IF NOT EXISTS platform_services.collection_run_events (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  adapter_id        UUID,
  job_id            UUID,
  module            VARCHAR(32),
  outcome           VARCHAR(16) NOT NULL CHECK (outcome IN ('completed','failed')),
  findings_ingested INTEGER,
  errors_count      INTEGER,
  detail            TEXT,
  occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_run_events_adapter_id ON platform_services.collection_run_events (adapter_id);
ALTER TABLE platform_services.collection_run_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.collection_run_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.collection_run_events;
CREATE POLICY tenant_isolation ON platform_services.collection_run_events
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS immutable_collection_run_events ON platform_services.collection_run_events;
CREATE TRIGGER immutable_collection_run_events BEFORE UPDATE OR DELETE ON platform_services.collection_run_events
  FOR EACH ROW EXECUTE FUNCTION public.prevent_mutation();
