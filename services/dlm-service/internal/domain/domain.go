// Package domain holds the DLM service's core entity types.
package domain

import "time"

// Finding is a data-leak detection.
type Finding struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	FindingType            string     `json:"finding_type"`
	Title                  string     `json:"title"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	ConfidenceScore        float64    `json:"confidence_score"`
	SourceID               *string    `json:"source_id,omitempty"`
	JobRunID               *string    `json:"job_run_id,omitempty"`
	DedupKey               string     `json:"dedup_key"`
	DetectionMethod        *string    `json:"detection_method,omitempty"`
	ContentURL             *string    `json:"content_url,omitempty"`
	ContentExcerpt         *string    `json:"content_excerpt,omitempty"`
	ContentHash            *string    `json:"content_hash,omitempty"`
	PriorSeverity          *string    `json:"prior_severity,omitempty"`
	SeverityOverrideReason *string    `json:"severity_override_reason,omitempty"`
	SuppressionReason      *string    `json:"suppression_reason,omitempty"`
	SuppressedAt           *time.Time `json:"suppressed_at,omitempty"`
	AssetIDs               []string   `json:"asset_ids,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// Evidence is an immutable chain-of-custody capture for a finding.
type Evidence struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	FindingID     string    `json:"finding_id"`
	EvidenceType  string    `json:"evidence_type"`
	StorageRef    *string   `json:"storage_ref,omitempty"`
	ContentHash   string    `json:"content_hash"`
	CaptureSource string    `json:"capture_source"`
	CapturedAt    time.Time `json:"captured_at"`
	Metadata      []byte    `json:"metadata,omitempty"`
}

// CollectionSource is a configured DLM intelligence source.
type CollectionSource struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	SourceType  string     `json:"source_type"`
	DisplayName string     `json:"display_name"`
	Status      string     `json:"status"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// FindingFilter constrains a finding list query.
type FindingFilter struct {
	Status      string
	FindingType string
	Severity    string
	Limit       int
	Offset      int
}
