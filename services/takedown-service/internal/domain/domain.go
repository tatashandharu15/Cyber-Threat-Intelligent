// Package domain holds the Takedown service's core entity types.
package domain

import "time"

// Takedown is a takedown request and its lifecycle record.
type Takedown struct {
	ID                   string     `json:"id"`
	TenantID             string     `json:"tenant_id"`
	SourceModule         string     `json:"source_module"`
	SourceFindingID      string     `json:"source_finding_id"`
	Status               string     `json:"status"`
	SubmissionTarget     string     `json:"submission_target"`
	SubmissionTargetType string     `json:"submission_target_type"`
	EvidencePackageRef   string     `json:"evidence_package_ref"`
	RequestedBy          *string    `json:"requested_by,omitempty"`
	SubmittedAt          *time.Time `json:"submitted_at,omitempty"`
	AcknowledgedAt       *time.Time `json:"acknowledged_at,omitempty"`
	ActionedAt           *time.Time `json:"actioned_at,omitempty"`
	RejectedAt           *time.Time `json:"rejected_at,omitempty"`
	OperatorResponse     *string    `json:"operator_response,omitempty"`
	ClosedAt             *time.Time `json:"closed_at,omitempty"`
	ClosedBy             *string    `json:"closed_by,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// TakedownEvent is an immutable accountability-chain entry for a takedown request.
type TakedownEvent struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	TakedownID string    `json:"takedown_id"`
	EventType  string    `json:"event_type"`
	Detail     *string   `json:"detail,omitempty"`
	ActorID    *string   `json:"actor_id,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// TakedownFilter constrains a takedown list query.
type TakedownFilter struct {
	Status       string
	SourceModule string
	Limit        int
	Offset       int
}
