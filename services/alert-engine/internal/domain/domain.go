// Package domain holds the Alert Engine's core entity types.
package domain

import (
	"time"

	"github.com/siberindo/cti/services/alert-engine/internal/rules"
)

// Alert is a created alert record.
type Alert struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	AlertRuleID     *string    `json:"alert_rule_id,omitempty"`
	SourceModule    string     `json:"source_module"`
	SourceFindingID string     `json:"source_finding_id"`
	CorrelationID   *string    `json:"correlation_id,omitempty"`
	Title           string     `json:"title"`
	Description     *string    `json:"description,omitempty"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	AcknowledgedBy  *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedBy      *string    `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AlertRule is the persisted form of a rule, including presentation fields.
type AlertRule struct {
	ID           string           `json:"id"`
	TenantID     string           `json:"tenant_id"`
	Name         string           `json:"name"`
	Description  *string          `json:"description,omitempty"`
	SourceModule *string          `json:"source_module,omitempty"`
	Conditions   rules.Conditions `json:"conditions"`
	Status       string           `json:"status"`
	WebhookURL   *string          `json:"webhook_url,omitempty"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
}

// AlertFilter constrains an alert list query.
type AlertFilter struct {
	Status       string
	Severity     string
	SourceModule string
	Limit        int
	Offset       int
}
