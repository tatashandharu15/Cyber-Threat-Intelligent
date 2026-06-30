// Package domain holds the Notification service's core entity types.
package domain

import "time"

// Notification is a single notification record fanned out to a recipient on a
// channel.
type Notification struct {
	ID              string     `json:"id"`
	TenantID        string     `json:"tenant_id"`
	RecipientUserID *string    `json:"recipient_user_id,omitempty"`
	Channel         string     `json:"channel"`
	EventType       string     `json:"event_type"`
	Subject         *string    `json:"subject,omitempty"`
	Body            *string    `json:"body,omitempty"`
	ReferenceType   *string    `json:"reference_type,omitempty"`
	ReferenceID     *string    `json:"reference_id,omitempty"`
	Severity        *string    `json:"severity,omitempty"`
	Status          string     `json:"status"`
	SentAt          *time.Time `json:"sent_at,omitempty"`
	FailureReason   *string    `json:"failure_reason,omitempty"`
	ReadAt          *time.Time `json:"read_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// Preference is a per-user, per-channel, per-event opt in/out. A missing row
// means the channel/event pair defaults to enabled.
type Preference struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	UserID    string    `json:"user_id"`
	Channel   string    `json:"channel"`
	EventType string    `json:"event_type"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NotificationFilter constrains a notification list query.
type NotificationFilter struct {
	Status          string
	Channel         string
	RecipientUserID string
	Limit           int
	Offset          int
}
