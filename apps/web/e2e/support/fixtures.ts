/**
 * Static fixture data + the standard success envelope helper.
 *
 * Every backend success response is `{ data, meta }` and the app's `apiFetch`
 * returns `body.data`. These helpers build that envelope so route stubs stay
 * terse. Shapes mirror apps/web/src/lib/types.ts.
 */

export interface Meta {
  request_id: string;
  timestamp: string;
}

export function meta(): Meta {
  return { request_id: "e2e-req", timestamp: "2026-06-21T00:00:00Z" };
}

/** Wrap a payload in the standard `{ data, meta }` success envelope. */
export function envelope<T>(data: T): { data: T; meta: Meta } {
  return { data, meta: meta() };
}

/** JSON string body for a 200 success response. */
export function ok<T>(data: T): string {
  return JSON.stringify(envelope(data));
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

/** Every read/write permission the app's RBAC checks reference. */
export const ALL_PERMISSIONS: string[] = [
  "finding:read",
  "investigation:read",
  "investigation:create",
  "investigation:update",
  "indicator:read",
  "indicator:create",
  "indicator:update",
  "takedown:read",
  "takedown:create",
  "takedown:update",
  "notification:read",
  "notification:update",
  "audit:read",
  "asset:read",
  "asset:approve",
];

// ---------------------------------------------------------------------------
// Auth fixtures
// ---------------------------------------------------------------------------

export const E2E_TOKEN = "e2e.jwt.token";

export const LOGIN_RESPONSE = {
  token: E2E_TOKEN,
  token_type: "Bearer",
  expires_at: "2099-01-01T00:00:00Z",
  user: {
    id: "user-e2e-1",
    email: "analyst@demo.siberindo.io",
    display_name: "E2E Analyst",
    tenant_id: "tenant-demo",
    status: "active",
    mfa_enabled: false,
  },
};

export function meResponse(permissions: string[] = ALL_PERMISSIONS) {
  return {
    user_id: "user-e2e-1",
    tenant_id: "tenant-demo",
    roles: ["cti_analyst"],
    permissions,
    session_id: "session-e2e-0001",
  };
}

// ---------------------------------------------------------------------------
// Data fixtures (small, deterministic)
// ---------------------------------------------------------------------------

export const ALERT_METRICS = {
  open_by_severity: {
    critical: 2,
    high: 5,
    medium: 9,
    low: 3,
    informational: 1,
  },
};

export const RECENT_ALERTS = [
  {
    id: "alert-1",
    source_module: "dlm",
    source_finding_id: "find-1",
    title: "Leaked credential set on paste site",
    severity: "critical",
    status: "open",
    created_at: "2026-06-20T10:00:00Z",
  },
  {
    id: "alert-2",
    source_module: "phm",
    source_finding_id: "find-2",
    title: "Phishing kit targeting brand login",
    severity: "high",
    status: "acknowledged",
    created_at: "2026-06-20T09:30:00Z",
  },
];

export const DLM_FINDINGS = [
  {
    id: "finding-dlm-1",
    title: "Customer DB dump on dark web",
    finding_type: "data_leak",
    severity: "critical",
    status: "open",
    confidence_score: 0.92,
    created_at: "2026-06-19T08:00:00Z",
  },
  {
    id: "finding-dlm-2",
    title: "Source code repository exposed",
    finding_type: "code_leak",
    severity: "high",
    status: "in_progress",
    confidence_score: 0.74,
    created_at: "2026-06-18T12:00:00Z",
  },
];

export const INDICATORS = [
  {
    id: "ioc-1",
    tenant_id: "tenant-demo",
    indicator_type: "domain",
    value: "evil-phish.example.com",
    tlp_marking: "TLP:AMBER",
    confidence: 0.88,
    source_module: "phm",
    source_finding_id: "find-2",
    tags: ["phishing"],
    first_seen_at: "2026-06-10T00:00:00Z",
    last_seen_at: "2026-06-20T00:00:00Z",
    created_at: "2026-06-10T00:00:00Z",
    updated_at: "2026-06-20T00:00:00Z",
  },
  {
    id: "ioc-2",
    tenant_id: "tenant-demo",
    indicator_type: "ip_address",
    value: "203.0.113.66",
    tlp_marking: "TLP:RED",
    confidence: 0.6,
    source_module: "dwm",
    source_finding_id: null,
    tags: [],
    first_seen_at: "2026-06-12T00:00:00Z",
    last_seen_at: "2026-06-21T00:00:00Z",
    created_at: "2026-06-12T00:00:00Z",
    updated_at: "2026-06-21T00:00:00Z",
  },
];

export const TAKEDOWNS = [
  {
    id: "takedown-aaaa1111-2222-3333-4444-555566667777",
    tenant_id: "tenant-demo",
    source_module: "phm",
    source_finding_id: "find-2",
    status: "submitted",
    submission_target: "abuse@registrar.example",
    submission_target_type: "registrar",
    evidence_package_ref: "s3://evidence/case-1.zip",
    created_at: "2026-06-19T00:00:00Z",
    updated_at: "2026-06-19T01:00:00Z",
  },
];

export const NOTIFICATIONS = [
  {
    id: "notif-1",
    tenant_id: "tenant-demo",
    recipient_user_id: "user-e2e-1",
    channel: "email",
    event_type: "alert.created",
    subject: "New critical alert assigned",
    body: "A critical alert needs triage.",
    severity: "critical",
    status: "sent",
    sent_at: "2026-06-20T10:01:00Z",
    read_at: null,
    created_at: "2026-06-20T10:00:30Z",
  },
];

export const AUDIT_EVENTS = [
  {
    id: "audit-1",
    tenant_id: "tenant-demo",
    actor_id: "user-e2e-1",
    actor_type: "user",
    event_type: "auth.login",
    resource_type: "session",
    resource_id: "session-e2e-0001",
    action: "create",
    outcome: "success",
    ip_address: "198.51.100.10",
    user_agent: "e2e",
    request_id: "e2e-req",
    hmac_signature: "deadbeef",
    created_at: "2026-06-20T07:00:00Z",
  },
];

export const ASSETS = [
  {
    id: "asset-1",
    tenant_id: "tenant-demo",
    asset_type: "domain",
    value: "siberindo.io",
    display_name: "Primary corporate domain",
    criticality: "critical",
    status: "active",
    approval_status: "approved",
    visibility: "tenant",
    created_at: "2026-05-01T00:00:00Z",
    updated_at: "2026-05-01T00:00:00Z",
  },
  {
    id: "asset-2",
    tenant_id: "tenant-demo",
    asset_type: "brand_keyword",
    value: "SiberIndo",
    display_name: null,
    criticality: "high",
    status: "pending_approval",
    approval_status: "pending",
    visibility: "tenant",
    created_at: "2026-06-15T00:00:00Z",
    updated_at: "2026-06-15T00:00:00Z",
  },
];
