-- Bootstrap script run once by the postgres superuser on first container start.
-- It creates the non-superuser runtime role, the per-bounded-context schemas, and
-- the shared trigger functions referenced by every service migration.
--
-- Services connect as the `cti` role (NOT a superuser) so that row-level security
-- is enforced. Because `cti` owns the schemas and therefore the tables, each
-- service migration also issues FORCE ROW LEVEL SECURITY so the policies apply to
-- the owning role as well.

-- Runtime application role. Password is for local development only.
CREATE ROLE cti LOGIN PASSWORD 'cti' NOSUPERUSER;

-- One schema per bounded context, matching the Database Blueprint section 1.1.
CREATE SCHEMA IF NOT EXISTS core_platform      AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS monitoring_dlm     AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS monitoring_clm     AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS monitoring_dwm     AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS monitoring_brm     AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS monitoring_phm     AUTHORIZATION cti;
CREATE SCHEMA IF NOT EXISTS platform_services  AUTHORIZATION cti;

GRANT USAGE ON SCHEMA public TO cti;

-- Shared trigger function: maintains updated_at on mutable tables.
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Shared trigger function: blocks UPDATE/DELETE on immutable tables (evidence,
-- finding history, audit events) per the Database Blueprint section 1.4.
CREATE OR REPLACE FUNCTION public.prevent_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Mutation of immutable table % is not permitted', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

ALTER FUNCTION public.update_updated_at() OWNER TO cti;
ALTER FUNCTION public.prevent_mutation() OWNER TO cti;
