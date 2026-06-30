// Package domain holds the Indicator service's core entity types.
package domain

import "time"

// Indicator is a deduplicated CTI observable with a Traffic Light Protocol marking.
type Indicator struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	IndicatorType   string     `json:"indicator_type"`
	Value           string     `json:"value"`
	TLPMarking      string     `json:"tlp_marking"`
	Confidence      *float64   `json:"confidence,omitempty"`
	SourceModule    *string    `json:"source_module,omitempty"`
	SourceFindingID *string    `json:"source_finding_id,omitempty"`
	Tags            []string   `json:"tags,omitempty"`
	FirstSeenAt     time.Time  `json:"first_seen_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// IndicatorFilter constrains an indicator list query.
type IndicatorFilter struct {
	IndicatorType string
	TLPMarking    string
	SourceModule  string
	Value         string
	Limit         int
	Offset        int
}
