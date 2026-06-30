// Strongly-typed entities consumed from the SiberIndo CTI backend.
// Every success response is { data, meta }; every error is { error, meta }.

export interface Meta {
  request_id: string;
  timestamp: string;
}

export interface ApiSuccess<T> {
  data: T;
  meta: Meta;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  details?: unknown;
}

export interface ApiErrorEnvelope {
  error: ApiErrorBody;
  meta: Meta;
}

export type Severity = "critical" | "high" | "medium" | "low" | "informational";

export type AlertStatus =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "resolved"
  | "closed"
  | "suppressed"
  | "false_positive";

export type FindingStatus =
  | "open"
  | "in_progress"
  | "resolved"
  | "closed"
  | "false_positive"
  | "accepted_risk";

export interface AuthUser {
  id: string;
  email: string;
  display_name: string;
  tenant_id: string;
  status: string;
  mfa_enabled: boolean;
}

export interface LoginResponse {
  token: string;
  token_type: string;
  expires_at: string;
  user: AuthUser;
}

export interface MeResponse {
  user_id: string;
  tenant_id: string;
  roles: string[];
  permissions: string[];
  session_id: string;
}

export interface Alert {
  id: string;
  source_module: string;
  source_finding_id: string;
  title: string;
  severity: Severity;
  status: AlertStatus;
  created_at: string;
  updated_at?: string;
  assignee_id?: string | null;
  tenant_id?: string;
  [key: string]: unknown;
}

export type SeverityCounts = Partial<Record<Severity, number>>;

export interface AlertMetrics {
  open_by_severity: SeverityCounts;
  [key: string]: unknown;
}

// Findings are emitted by five monitoring modules; the shared fields below are
// guaranteed across modules. CLM findings have no `title` (they expose
// masked_indicator + credential_type instead) — both are optional here.
export interface Finding {
  id: string;
  title?: string;
  finding_type?: string;
  severity: Severity;
  status: FindingStatus;
  confidence_score?: number;
  created_at: string;
  updated_at?: string;
  // CLM-specific
  masked_indicator?: string;
  credential_type?: string;
  [key: string]: unknown;
}

export type FindingModule = "dlm" | "clm" | "dwm" | "brm" | "phm";

// ---------------------------------------------------------------------------
// Investigation service (port 8090 — /api/investigations)
// ---------------------------------------------------------------------------

export type InvestigationStatus =
  | "open"
  | "in_progress"
  | "pending_review"
  | "closed";

export type InvestigationPriority = "critical" | "high" | "medium" | "low";

export interface Investigation {
  id: string;
  tenant_id: string;
  title: string;
  description?: string | null;
  status: InvestigationStatus;
  priority: InvestigationPriority;
  assigned_to?: string | null;
  closed_at?: string | null;
  closed_by?: string | null;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
  updated_by?: string | null;
}

export interface LinkedFinding {
  investigation_id: string;
  source_module: string;
  source_finding_id: string;
  tenant_id: string;
  notes?: string | null;
  linked_at: string;
  linked_by?: string | null;
}

export interface TimelineEntry {
  id: string;
  tenant_id: string;
  investigation_id: string;
  entry_type: string;
  detail?: string | null;
  actor_id?: string | null;
  created_at: string;
}

// GET /api/investigations/{id} embeds the investigation fields inline plus
// linked_findings and timeline arrays.
export interface InvestigationDetail extends Investigation {
  linked_findings: LinkedFinding[];
  timeline: TimelineEntry[];
}

// GET /api/investigations/inbox — unlinked alerts available to link.
export interface InboxAlert {
  id: string;
  tenant_id: string;
  alert_id: string;
  source_module: string;
  source_finding_id: string;
  severity?: string | null;
  title?: string | null;
  linked: boolean;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Indicator service (port 8093 — /api/indicators)
// ---------------------------------------------------------------------------

export type IndicatorType =
  | "domain"
  | "ip_address"
  | "url_defanged"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email_address"
  | "asn"
  | "certificate_fingerprint"
  | "mutex"
  | "registry_key"
  | "file_path";

export type TlpMarking = "TLP:WHITE" | "TLP:GREEN" | "TLP:AMBER" | "TLP:RED";

export interface Indicator {
  id: string;
  tenant_id: string;
  indicator_type: IndicatorType | string;
  value: string;
  tlp_marking: TlpMarking | string;
  confidence?: number | null;
  source_module?: string | null;
  source_finding_id?: string | null;
  tags?: string[];
  first_seen_at: string;
  last_seen_at: string;
  expires_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Takedown service (port 8094 — /api/takedowns)
// ---------------------------------------------------------------------------

export type TakedownStatus =
  | "draft"
  | "submitted"
  | "acknowledged"
  | "actioned"
  | "rejected"
  | "closed";

export type TakedownSourceModule = "brm" | "phm";

export type SubmissionTargetType =
  | "registrar"
  | "app_store_operator"
  | "social_platform"
  | "hosting_provider"
  | "cert_authority";

export interface Takedown {
  id: string;
  tenant_id: string;
  source_module: TakedownSourceModule | string;
  source_finding_id: string;
  status: TakedownStatus;
  submission_target: string;
  submission_target_type: SubmissionTargetType | string;
  evidence_package_ref: string;
  requested_by?: string | null;
  submitted_at?: string | null;
  acknowledged_at?: string | null;
  actioned_at?: string | null;
  rejected_at?: string | null;
  operator_response?: string | null;
  closed_at?: string | null;
  closed_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface TakedownEvent {
  id: string;
  tenant_id: string;
  takedown_id: string;
  event_type: string;
  detail?: string | null;
  actor_id?: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Notification service (port 8091 — /api/notifications)
// ---------------------------------------------------------------------------

export type NotificationStatus = "pending" | "sent" | "suppressed";

export type NotificationChannel =
  | "in_app"
  | "email"
  | "slack"
  | "teams"
  | "webhook";

export interface Notification {
  id: string;
  tenant_id: string;
  recipient_user_id?: string | null;
  channel: NotificationChannel | string;
  event_type: string;
  subject?: string | null;
  body?: string | null;
  reference_type?: string | null;
  reference_id?: string | null;
  severity?: string | null;
  status: NotificationStatus | string;
  sent_at?: string | null;
  failure_reason?: string | null;
  read_at?: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Audit service (port 8092 — /api/audit-logs)
// ---------------------------------------------------------------------------

export type AuditOutcome = "success" | "failure" | "partial";

export interface AuditEvent {
  id: string;
  tenant_id: string;
  actor_id: string;
  actor_type: string;
  event_type: string;
  resource_type: string;
  resource_id?: string | null;
  action: string;
  outcome: AuditOutcome | string;
  ip_address?: string | null;
  user_agent?: string | null;
  request_id?: string | null;
  event_payload?: unknown;
  hmac_signature: string;
  created_at: string;
}

// GET /api/audit-logs/{id}/verify
export interface AuditVerifyResult {
  id: string;
  valid: boolean;
}

// ---------------------------------------------------------------------------
// Asset service (port 8083 — /api/assets)
// ---------------------------------------------------------------------------

export type AssetType =
  | "domain"
  | "ip_address"
  | "ip_range"
  | "email_address"
  | "email_domain"
  | "brand_keyword"
  | "executive_profile"
  | "mobile_app"
  | "social_handle";

export type Criticality = "critical" | "high" | "medium" | "low";

export type AssetStatus =
  | "active"
  | "paused"
  | "decommissioned"
  | "pending_approval";

export type ApprovalStatus = "pending" | "approved";

export interface Asset {
  id: string;
  tenant_id: string;
  asset_type: AssetType | string;
  value: string;
  display_name?: string | null;
  criticality: Criticality | string;
  status: AssetStatus | string;
  approval_status: ApprovalStatus | string;
  approved_by?: string | null;
  approved_at?: string | null;
  visibility: string;
  created_at: string;
  updated_at: string;
  created_by?: string | null;
  updated_by?: string | null;
}
