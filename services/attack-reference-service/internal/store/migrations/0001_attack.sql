-- ATT&CK Reference schema (platform_services). The ATT&CK Reference service owns
-- the DDL for the attack_techniques table, which holds the MITRE ATT&CK technique
-- catalog synced from the MITRE STIX feed (Database Blueprint section 8.10).
--
-- GLOBAL REFERENCE DATA: unlike every other platform_services table, this table is
-- NOT tenant-scoped — the ATT&CK catalog is identical for every tenant. The
-- Database Blueprint therefore defines it with NO row-level security: there is no
-- tenant_id column and no tenant_isolation policy. All queries from the service run
-- via database.WithoutTenant (a plain transaction with no app.current_tenant_id),
-- which is correct precisely because no RLS policy gates this table.
--
-- The platform_services schema is created by infra/docker/init/01-init.sql.

CREATE TABLE IF NOT EXISTS platform_services.attack_techniques (
  id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  technique_id        VARCHAR(32) NOT NULL UNIQUE,
  name                VARCHAR(255) NOT NULL,
  description         TEXT,
  tactic_refs         TEXT[],
  platform_refs       TEXT[],
  is_subtechnique     BOOLEAN NOT NULL DEFAULT FALSE,
  parent_technique_id VARCHAR(32),
  stix_id             VARCHAR(128),
  last_synced_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The UNIQUE constraint on technique_id already provides a lookup index for
-- GetByTechniqueID. This partial index supports listing the sub-techniques of a
-- given parent (the parent/child drill-down used by enrichment lookups).
CREATE INDEX IF NOT EXISTS idx_attack_techniques_parent
  ON platform_services.attack_techniques (parent_technique_id)
  WHERE is_subtechnique = TRUE;

-- INTENTIONALLY NO ROW LEVEL SECURITY: attack_techniques is global reference data
-- shared across all tenants (Database Blueprint 8.10). Do not add ENABLE/FORCE ROW
-- LEVEL SECURITY or a tenant_isolation policy here.
