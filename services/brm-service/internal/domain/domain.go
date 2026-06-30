// Package domain holds the BRM service's core entity types.
package domain

import "time"

// Finding is a brand-impersonation detection (lookalike domain, rogue app, fake
// social profile, etc.).
type Finding struct {
	ID                         string     `json:"id"`
	TenantID                   string     `json:"tenant_id"`
	FindingType                string     `json:"finding_type"`
	Title                      string     `json:"title"`
	Severity                   string     `json:"severity"`
	Status                     string     `json:"status"`
	ConfidenceScore            float64    `json:"confidence_score"`
	SimilarityScore            *float64   `json:"similarity_score,omitempty"`
	SimilarityAlgorithmVersion *string    `json:"similarity_algorithm_version,omitempty"`
	CandidateValue             string     `json:"candidate_value"`
	SourceID                   *string    `json:"source_id,omitempty"`
	JobRunID                   *string    `json:"job_run_id,omitempty"`
	DedupKey                   string     `json:"dedup_key"`
	WhoisSnapshot              []byte     `json:"whois_snapshot,omitempty"`
	RegistrationDate           *time.Time `json:"registration_date,omitempty"`
	SocialPlatformID           *string    `json:"social_platform_id,omitempty"`
	SocialAccountHandle        *string    `json:"social_account_handle,omitempty"`
	SocialProfileURL           *string    `json:"social_profile_url,omitempty"`
	AppStoreID                 *string    `json:"app_store_id,omitempty"`
	AppPlatform                *string    `json:"app_platform,omitempty"`
	AppListingURL              *string    `json:"app_listing_url,omitempty"`
	AppPackageID               *string    `json:"app_package_id,omitempty"`
	PriorSeverity              *string    `json:"prior_severity,omitempty"`
	SeverityOverrideReason     *string    `json:"severity_override_reason,omitempty"`
	SuppressionReason          *string    `json:"suppression_reason,omitempty"`
	SuppressedAt               *time.Time `json:"suppressed_at,omitempty"`
	AssetIDs                   []string   `json:"asset_ids,omitempty"`
	CreatedAt                  time.Time  `json:"created_at"`
	UpdatedAt                  time.Time  `json:"updated_at"`
}

// Evidence is an immutable chain-of-custody capture for a finding.
type Evidence struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	FindingID        string    `json:"finding_id"`
	EvidenceType     string    `json:"evidence_type"`
	StorageRef       *string   `json:"storage_ref,omitempty"`
	ContentHash      string    `json:"content_hash"`
	CaptureTimestamp time.Time `json:"capture_timestamp"`
	Metadata         []byte    `json:"metadata,omitempty"`
}

// CollectionSource is a configured BRM intelligence source.
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
