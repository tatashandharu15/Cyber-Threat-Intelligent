// Package domain holds the CLM service's core entity types.
package domain

import "time"

// Finding is a credential-leak detection.
//
// CLM-BR-001: no cleartext credential value is ever stored. MaskedIndicator holds
// only a masked representation, and MaskingPolicyVersion records which deterministic
// masking policy produced it.
type Finding struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	CredentialType         string     `json:"credential_type"`
	MaskedIndicator        string     `json:"masked_indicator"`
	MaskingPolicyVersion   string     `json:"masking_policy_version"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	ConfidenceScore        float64    `json:"confidence_score"`
	BreachSourceID         *string    `json:"breach_source_id,omitempty"`
	JobRunID               *string    `json:"job_run_id,omitempty"`
	BreachName             *string    `json:"breach_name,omitempty"`
	DedupKey               string     `json:"dedup_key"`
	AffectedUserCount      *int       `json:"affected_user_count,omitempty"`
	UserCorrelationState   string     `json:"user_correlation_state"`
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
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	FindingID    string    `json:"finding_id"`
	EvidenceType string    `json:"evidence_type"`
	ContentHash  string    `json:"content_hash"`
	StorageRef   *string   `json:"storage_ref,omitempty"`
	CapturedAt   time.Time `json:"captured_at"`
	Metadata     []byte    `json:"metadata,omitempty"`
}

// BreachSource is a configured CLM breach/credential intelligence source.
type BreachSource struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	SourceName  string     `json:"source_name"`
	SourceTier  string     `json:"source_tier"`
	AdapterType string     `json:"adapter_type"`
	Status      string     `json:"status"`
	LastRunAt   *time.Time `json:"last_run_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// FindingFilter constrains a finding list query.
type FindingFilter struct {
	Status         string
	CredentialType string
	Severity       string
	Limit          int
	Offset         int
}
