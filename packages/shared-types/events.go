package types

import "time"

// Kafka topic names. These mirror the Integration Architecture section of the
// Architecture Blueprint (section 5.1 Kafka Topic Catalog).
const (
	TopicFindingCreatedDLM    = "finding.created.dlm"
	TopicFindingCreatedCLM    = "finding.created.clm"
	TopicFindingCreatedDWM    = "finding.created.dwm"
	TopicFindingCreatedBRM    = "finding.created.brm"
	TopicFindingCreatedPHM    = "finding.created.phm"
	TopicFindingEscalatedDLM  = "finding.escalated.dlm"
	TopicFindingEscalatedCLM  = "finding.escalated.clm"
	TopicFindingEscalatedDWM  = "finding.escalated.dwm"
	TopicFindingEscalatedBRM  = "finding.escalated.brm"
	TopicFindingEscalatedPHM  = "finding.escalated.phm"
	TopicAlertCreated         = "alert.created"
	TopicAlertUpdated         = "alert.updated"
	TopicCollectionCompleted  = "collection.job.completed"
	TopicCollectionFailed     = "collection.job.failed"
	TopicAuditEventWritten    = "audit.event.written"
	TopicIndicatorCreated     = "indicator.created"
	TopicTakedownRequested    = "takedown.requested"
	TopicTakedownStatusUpdate = "takedown.status.updated"
	TopicReportRequested      = "report.requested"
	TopicReportCompleted      = "report.completed"
)

// FindingCreatedTopic returns the finding.created topic for a given module.
func FindingCreatedTopic(m Module) string {
	return "finding.created." + string(m)
}

// FindingEscalatedTopic returns the finding.escalated topic for a given module.
func FindingEscalatedTopic(m Module) string {
	return "finding.escalated." + string(m)
}

// FindingCreated is published when any detection module persists a new finding.
// Consumed by the Alert Engine and the OpenSearch sync worker.
type FindingCreated struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	SourceModule    Module    `json:"source_module"`
	TenantID        string    `json:"tenant_id"`
	FindingID       string    `json:"finding_id"`
	FindingType     string    `json:"finding_type"`
	Severity        Severity  `json:"severity"`
	ConfidenceScore float64   `json:"confidence_score"`
	AssetIDs        []string  `json:"asset_ids"`
	CreatedAt       time.Time `json:"created_at"`
}

// FindingEscalated is published when a detection module escalates a finding that
// meets configured thresholds. Consumed by the Alert Engine for rule evaluation.
type FindingEscalated struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	SourceModule    Module    `json:"source_module"`
	TenantID        string    `json:"tenant_id"`
	FindingID       string    `json:"finding_id"`
	FindingType     string    `json:"finding_type"`
	Severity        Severity  `json:"severity"`
	ConfidenceScore float64   `json:"confidence_score"`
	AssetIDs        []string  `json:"asset_ids"`
	Title           string    `json:"title"`
	EscalatedBy     string    `json:"escalated_by"`
	EscalatedAt     time.Time `json:"escalated_at"`
}

// AlertCreated is published by the Alert Engine when a new alert is written.
// Consumed by the Notification Center and the Investigation service.
type AlertCreated struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	TenantID        string    `json:"tenant_id"`
	AlertID         string    `json:"alert_id"`
	SourceModule    Module    `json:"source_module"`
	SourceFindingID string    `json:"source_finding_id"`
	Severity        Severity  `json:"severity"`
	Title           string    `json:"title"`
	CreatedAt       time.Time `json:"created_at"`
}

// CollectionJobResult is published by collection workers on job completion.
type CollectionJobResult struct {
	EventID          string    `json:"event_id"`
	EventType        string    `json:"event_type"`
	TenantID         string    `json:"tenant_id"`
	JobID            string    `json:"job_id"`
	Module           Module    `json:"module"`
	SourceAdapterID  string    `json:"source_adapter_id"`
	FindingsIngested int       `json:"findings_ingested"`
	ErrorsCount      int       `json:"errors_count"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at"`
}

// AuditEventWritten mirrors an audit record for asynchronous fan-out to the
// Audit Log service. The HMAC signature is computed by the emitting service.
type AuditEventWritten struct {
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`
	TenantID     string    `json:"tenant_id"`
	ActorID      string    `json:"actor_id"`
	ActorType    string    `json:"actor_type"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	Outcome      string    `json:"outcome"`
	RequestID    string    `json:"request_id"`
	HMAC         string    `json:"hmac_signature"`
	CreatedAt    time.Time `json:"created_at"`
}

// IndicatorCreated is published by Indicator Management when an indicator is
// registered, for downstream enrichment/export consumers.
type IndicatorCreated struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	TenantID        string    `json:"tenant_id"`
	IndicatorID     string    `json:"indicator_id"`
	IndicatorType   string    `json:"indicator_type"`
	Value           string    `json:"value"`
	TLP             TLP       `json:"tlp_marking"`
	SourceModule    string    `json:"source_module"`
	SourceFindingID string    `json:"source_finding_id"`
	CreatedAt       time.Time `json:"created_at"`
}

// TakedownRequested is published by the Takedown service when a takedown request is
// submitted. Consumed by the Notification Center.
type TakedownRequested struct {
	EventID              string    `json:"event_id"`
	EventType            string    `json:"event_type"`
	TenantID             string    `json:"tenant_id"`
	TakedownID           string    `json:"takedown_id"`
	SourceModule         string    `json:"source_module"`
	SourceFindingID      string    `json:"source_finding_id"`
	SubmissionTarget     string    `json:"submission_target"`
	SubmissionTargetType string    `json:"submission_target_type"`
	RequestedBy          string    `json:"requested_by"`
	CreatedAt            time.Time `json:"created_at"`
}

// TakedownStatusUpdate is published by the Takedown service on a status change.
// Consumed by the originating module (BRM/PHM) and the Notification Center.
type TakedownStatusUpdate struct {
	EventID          string    `json:"event_id"`
	EventType        string    `json:"event_type"`
	TenantID         string    `json:"tenant_id"`
	TakedownID       string    `json:"takedown_id"`
	SourceModule     string    `json:"source_module"`
	SourceFindingID  string    `json:"source_finding_id"`
	Status           string    `json:"status"`
	OperatorResponse string    `json:"operator_response"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// ReportRequested is published by the Reporting service when a report is queued.
// Consumed by the Reporting worker to perform generation.
type ReportRequested struct {
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	TenantID    string    `json:"tenant_id"`
	ReportID    string    `json:"report_id"`
	ReportType  string    `json:"report_type"`
	Format      string    `json:"format"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// ReportCompleted is published when a report finishes generating. Consumed by the
// Notification Center to inform the requester.
type ReportCompleted struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	TenantID  string    `json:"tenant_id"`
	ReportID  string    `json:"report_id"`
	Status    string    `json:"status"` // complete | failed
	OutputRef string    `json:"output_ref"`
	CreatedAt time.Time `json:"created_at"`
}

// CollectionJobFailed is published by collection workers when a job fails.
// Consumed by the Collection Adapter Manager to track adapter health.
type CollectionJobFailed struct {
	EventID         string    `json:"event_id"`
	EventType       string    `json:"event_type"`
	TenantID        string    `json:"tenant_id"`
	JobID           string    `json:"job_id"`
	Module          Module    `json:"module"`
	SourceAdapterID string    `json:"source_adapter_id"`
	Error           string    `json:"error"`
	FailedAt        time.Time `json:"failed_at"`
}
