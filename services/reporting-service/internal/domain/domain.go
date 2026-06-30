// Package domain holds the Reporting service's core entity types.
package domain

import "time"

// Report is a requested report and its generation lifecycle state. It maps to the
// platform_services.reports table.
type Report struct {
	ID            string     `json:"id"`
	TenantID      string     `json:"tenant_id"`
	ReportType    string     `json:"report_type"`
	Title         string     `json:"title"`
	Status        string     `json:"status"`
	Parameters    []byte     `json:"parameters,omitempty"`
	OutputRef     *string    `json:"output_ref,omitempty"`
	OutputFormat  string     `json:"output_format"`
	RequestedBy   *string    `json:"requested_by,omitempty"`
	GeneratedAt   *time.Time `json:"generated_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	FailureReason *string    `json:"failure_reason,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// ReportFilter constrains a report list query.
type ReportFilter struct {
	ReportType string
	Status     string
	Limit      int
	Offset     int
}
