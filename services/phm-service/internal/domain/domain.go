// Package domain holds the PHM service's core entity types.
package domain

import "time"

// Finding is a phishing detection.
type Finding struct {
	ID                     string     `json:"id"`
	TenantID               string     `json:"tenant_id"`
	FindingType            string     `json:"finding_type"`
	Title                  string     `json:"title"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	ConfidenceScore        float64    `json:"confidence_score"`
	PhishingURLDefanged    string     `json:"phishing_url_defanged"`
	HostingIP              *string    `json:"hosting_ip,omitempty"`
	Registrar              *string    `json:"registrar,omitempty"`
	CampaignID             *string    `json:"campaign_id,omitempty"`
	SourceID               *string    `json:"source_id,omitempty"`
	JobRunID               *string    `json:"job_run_id,omitempty"`
	DedupKey               string     `json:"dedup_key"`
	ContentFingerprint     *string    `json:"content_fingerprint,omitempty"`
	UrgencyPromoted        bool       `json:"urgency_promoted"`
	UrgencyPromotedAt      *time.Time `json:"urgency_promoted_at,omitempty"`
	PriorSeverity          *string    `json:"prior_severity,omitempty"`
	SeverityOverrideReason *string    `json:"severity_override_reason,omitempty"`
	SuppressionReason      *string    `json:"suppression_reason,omitempty"`
	SuppressedAt           *time.Time `json:"suppressed_at,omitempty"`
	AssetIDs               []string   `json:"asset_ids,omitempty"`
	CreatedAt              time.Time  `json:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"`
}

// Campaign groups related phishing infrastructure.
type Campaign struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	Description  *string   `json:"description,omitempty"`
	Status       string    `json:"status"`
	FindingCount int       `json:"finding_count"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// Indicator is a structured IOC extracted from a finding.
type Indicator struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	FindingID     string    `json:"finding_id"`
	IndicatorType string    `json:"indicator_type"`
	Value         string    `json:"value"`
	TLPMarking    string    `json:"tlp_marking"`
	Confidence    *float64  `json:"confidence,omitempty"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// SSLCertificate is an immutable certificate capture preserved for a finding.
type SSLCertificate struct {
	ID                string     `json:"id"`
	TenantID          string     `json:"tenant_id"`
	FindingID         *string    `json:"finding_id,omitempty"`
	SerialNumber      string     `json:"serial_number"`
	Issuer            *string    `json:"issuer,omitempty"`
	Subject           *string    `json:"subject,omitempty"`
	SANEntries        []string   `json:"san_entries,omitempty"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	FingerprintSHA256 *string    `json:"fingerprint_sha256,omitempty"`
	RawCertRef        *string    `json:"raw_cert_ref,omitempty"`
	CapturedAt        time.Time  `json:"captured_at"`
}

// Evidence is an immutable chain-of-custody capture for a finding.
type Evidence struct {
	ID               string    `json:"id"`
	TenantID         string    `json:"tenant_id"`
	FindingID        string    `json:"finding_id"`
	EvidenceType     string    `json:"evidence_type"`
	CaptureTimestamp time.Time `json:"capture_timestamp"`
	ContentHash      string    `json:"content_hash"`
	StorageRef       *string   `json:"storage_ref,omitempty"`
	Metadata         []byte    `json:"metadata,omitempty"`
}

// CollectionSource is a configured PHM intelligence source.
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
	CampaignID  string
	Limit       int
	Offset      int
}
