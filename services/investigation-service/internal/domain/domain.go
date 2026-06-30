// Package domain holds the Investigation service's core entity types.
package domain

import "time"

// Investigation is an analyst case consolidating related findings and alerts.
type Investigation struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Title       string     `json:"title"`
	Description *string    `json:"description,omitempty"`
	Status      string     `json:"status"`
	Priority    string     `json:"priority"`
	AssignedTo  *string    `json:"assigned_to,omitempty"`
	ClosedAt    *time.Time `json:"closed_at,omitempty"`
	ClosedBy    *string    `json:"closed_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	CreatedBy   *string    `json:"created_by,omitempty"`
	UpdatedBy   *string    `json:"updated_by,omitempty"`
}

// LinkedFinding is a detection-module finding linked into an investigation.
type LinkedFinding struct {
	InvestigationID string    `json:"investigation_id"`
	SourceModule    string    `json:"source_module"`
	SourceFindingID string    `json:"source_finding_id"`
	TenantID        string    `json:"tenant_id"`
	Notes           *string   `json:"notes,omitempty"`
	LinkedAt        time.Time `json:"linked_at"`
	LinkedBy        *string   `json:"linked_by,omitempty"`
}

// TimelineEntry is an immutable record of activity on an investigation.
type TimelineEntry struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	InvestigationID string    `json:"investigation_id"`
	EntryType       string    `json:"entry_type"`
	Detail          *string   `json:"detail,omitempty"`
	ActorID         *string   `json:"actor_id,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// InboxAlert is an alert.created event awaiting linkage into an investigation.
type InboxAlert struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	AlertID         string    `json:"alert_id"`
	SourceModule    string    `json:"source_module"`
	SourceFindingID string    `json:"source_finding_id"`
	Severity        *string   `json:"severity,omitempty"`
	Title           *string   `json:"title,omitempty"`
	Linked          bool      `json:"linked"`
	CreatedAt       time.Time `json:"created_at"`
}

// InvestigationFilter constrains an investigation list query.
type InvestigationFilter struct {
	Status     string `json:"status"`
	Priority   string `json:"priority"`
	AssignedTo string `json:"assigned_to"`
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
}
