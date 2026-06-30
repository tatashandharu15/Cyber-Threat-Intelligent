-- Notification Center schema (platform_services). The Notification service owns
-- the DDL for the notifications and notification_preferences tables. Row-level
-- security is enabled and FORCED so the tenant_isolation policies apply even to
-- the schema-owning `cti` role.
--
-- Cross-bounded-context references (tenant_id, recipient_user_id, user_id,
-- reference_id) are plain UUID columns WITHOUT hard foreign keys to other schemas.
--
-- The platform_services schema and the shared trigger function
-- public.update_updated_at() are created by infra/docker/init/01-init.sql.

-- 1. Notifications: a single notification record fanned out to a recipient on a
-- channel. This is an append/lifecycle table tracked by explicit lifecycle
-- columns (sent_at, read_at, failure_reason), so it has NO updated_at column and
-- NO updated_at trigger.
CREATE TABLE IF NOT EXISTS platform_services.notifications (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id         UUID NOT NULL,
  recipient_user_id UUID,
  channel           VARCHAR(32) NOT NULL DEFAULT 'in_app' CHECK (channel IN (
                      'in_app','email','slack','teams','webhook')),
  event_type        VARCHAR(128) NOT NULL,
  subject           VARCHAR(512),
  body              TEXT,
  reference_type    VARCHAR(64),
  reference_id      UUID,
  severity          VARCHAR(32),
  status            VARCHAR(32) NOT NULL DEFAULT 'pending' CHECK (status IN (
                      'pending','sent','failed','suppressed')),
  sent_at           TIMESTAMPTZ,
  failure_reason    TEXT,
  read_at           TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_status ON platform_services.notifications (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_recipient ON platform_services.notifications (tenant_id, recipient_user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_tenant_created ON platform_services.notifications (tenant_id, created_at);
ALTER TABLE platform_services.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.notifications FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.notifications;
CREATE POLICY tenant_isolation ON platform_services.notifications
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- 2. Notification preferences: per-user, per-channel, per-event opt in/out. A
-- missing row means the channel/event pair defaults to enabled.
CREATE TABLE IF NOT EXISTS platform_services.notification_preferences (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id   UUID NOT NULL,
  user_id     UUID NOT NULL,
  channel     VARCHAR(32) NOT NULL CHECK (channel IN (
                'in_app','email','slack','teams','webhook')),
  event_type  VARCHAR(128) NOT NULL,
  enabled     BOOLEAN NOT NULL DEFAULT TRUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  created_by  UUID,
  updated_by  UUID,
  UNIQUE (tenant_id, user_id, channel, event_type)
);
CREATE INDEX IF NOT EXISTS idx_notification_prefs_tenant_user ON platform_services.notification_preferences (tenant_id, user_id);
ALTER TABLE platform_services.notification_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform_services.notification_preferences FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON platform_services.notification_preferences;
CREATE POLICY tenant_isolation ON platform_services.notification_preferences
  USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);
DROP TRIGGER IF EXISTS set_updated_at ON platform_services.notification_preferences;
CREATE TRIGGER set_updated_at BEFORE UPDATE ON platform_services.notification_preferences
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();
