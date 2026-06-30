// Package domain holds the Collection Adapter Manager's core entity types.
package domain

import "time"

// Adapter is a registered per-module collection adapter and its current health.
// Nullable database columns are modeled as pointers so a missing value is
// distinguishable from a zero value.
type Adapter struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	Module          string     `json:"module"`
	AdapterType     string     `json:"adapter_type"`
	Name            string     `json:"name"`
	Status          string     `json:"status"`
	ScheduleCron    *string    `json:"schedule_cron,omitempty"`
	ConfigRef       *string    `json:"config_ref,omitempty"`
	LastRunAt       *time.Time `json:"last_run_at,omitempty"`
	LastStatus      *string    `json:"last_status,omitempty"`
	LastError       *string    `json:"last_error,omitempty"`
	FindingsLastRun *int       `json:"findings_last_run,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	CreatedBy       *string    `json:"created_by,omitempty"`
	UpdatedBy       *string    `json:"updated_by,omitempty"`
}

// RunEvent is one immutable, append-only collection-run history entry produced
// from a collection.job.completed or collection.job.failed Kafka event.
type RunEvent struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	AdapterID        *string   `json:"adapter_id,omitempty"`
	JobID            *string   `json:"job_id,omitempty"`
	Module           *string   `json:"module,omitempty"`
	Outcome          string    `json:"outcome"`
	FindingsIngested *int      `json:"findings_ingested,omitempty"`
	ErrorsCount      *int      `json:"errors_count,omitempty"`
	Detail           *string   `json:"detail,omitempty"`
	OccurredAt       time.Time `json:"occurred_at"`
}

// AdapterFilter constrains an adapter list query.
type AdapterFilter struct {
	Module string
	Status string
	Limit  int
	Offset int
}
