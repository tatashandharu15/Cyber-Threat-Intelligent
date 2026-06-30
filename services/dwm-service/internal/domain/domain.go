// Package domain holds the DWM (Dark Web Monitoring) service's core entity types.
package domain

import "time"

// Finding is a dark web detection.
//
// To honor DWM-BR-001 / DWM-NFR-004, a finding carries only the coarse
// SourceTierID classification and never any adapter URL or source access detail.
type Finding struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	FindingType            string     `json:"finding_type"`
	Title                  string     `json:"title"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	ConfidenceScore        float64    `json:"confidence_score"`
	SourceTierID           *string    `json:"source_tier_id,omitempty"`
	JobRunID               *string    `json:"job_run_id,omitempty"`
	DedupKey               string     `json:"dedup_key"`
	ContentExcerpt         *string    `json:"content_excerpt,omitempty"`
	ContentHash            *string    `json:"content_hash,omitempty"`
	ContentURLDefanged     *string    `json:"content_url_defanged,omitempty"`
	ObservedAt             *time.Time `json:"observed_at,omitempty"`
	SubmissionType         string     `json:"submission_type"`
	PriorSeverity          *string    `json:"prior_severity,omitempty"`
	SeverityOverrideReason *string    `json:"severity_override_reason,omitempty"`
	SuppressionReason      *string    `json:"suppression_reason,omitempty"`
	SuppressedAt           *time.Time `json:"suppressed_at,omitempty"`
	AssetIDs               []string   `json:"asset_ids,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// ThreatActorProfile is an analyst-maintained adversary dossier. IdentityConfirmed
// is never set automatically; it requires explicit analyst confirmation
// (DWM-BR-002).
type ThreatActorProfile struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Codename          string    `json:"codename"`
	Description       *string   `json:"description,omitempty"`
	IdentityConfirmed bool      `json:"identity_confirmed"`
	Aliases           []string  `json:"aliases,omitempty"`
	Tactics           []string  `json:"tactics,omitempty"`
	Status            string    `json:"status"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Enrichment is analyst-added structured threat context for a finding (DWM-FR-014).
type Enrichment struct {
	ID                 string    `json:"id"`
	TenantID           string    `json:"tenant_id"`
	FindingID          string    `json:"finding_id"`
	TacticsObserved    []string  `json:"tactics_observed,omitempty"`
	AffectedAssetScope *string   `json:"affected_asset_scope,omitempty"`
	ResponseIndicators *string   `json:"response_indicators,omitempty"`
	EnrichedAt         time.Time `json:"enriched_at"`
}

// Evidence is an immutable chain-of-custody capture for a finding.
type Evidence struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	FindingID    string    `json:"finding_id"`
	EvidenceType string    `json:"evidence_type"`
	ContentHash  string    `json:"content_hash"`
	StorageRef   *string   `json:"storage_ref,omitempty"`
	CapturedAt   time.Time `json:"captured_at"`
	Metadata     []byte    `json:"metadata,omitempty"`
}

// FindingFilter constrains a finding list query.
type FindingFilter struct {
	Status      string
	FindingType string
	Severity    string
	Limit       int
	Offset      int
}
