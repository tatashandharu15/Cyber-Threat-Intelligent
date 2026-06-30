// Package service implements the Notification Center's business logic:
// validation of notification fields, the in_app fast path, preference-aware
// fan-out, and the mandatory security-notification rule for high/critical alerts.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/notification-service/internal/domain"
	"github.com/siberindo/cti/services/notification-service/internal/store"
)

// ValidationError carries a human-readable validation message.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func newValidation(format string, a ...any) *ValidationError {
	return &ValidationError{msg: fmt.Sprintf(format, a...)}
}

// IsValidation reports whether err is a ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}

var (
	// ErrNotFound and ErrConflict are re-exported from the store for the API layer.
	ErrNotFound = store.ErrNotFound
	ErrConflict = store.ErrConflict
)

// allowedChannels is the set of delivery channels supported by the MVP.
var allowedChannels = map[string]bool{
	"in_app": true, "email": true, "slack": true, "teams": true, "webhook": true,
}

// alertCreatedEvent is the event_type recorded for notifications generated from
// alert.created events and used as the preference key.
const alertCreatedEvent = "alert.created"

// Store is the persistence contract.
type Store interface {
	CreateNotification(ctx context.Context, n *domain.Notification) (*domain.Notification, error)
	ListNotifications(ctx context.Context, tenantID string, fil domain.NotificationFilter) ([]domain.Notification, error)
	GetNotification(ctx context.Context, tenantID, id string) (*domain.Notification, error)
	MarkRead(ctx context.Context, tenantID, id string) error
	GetPreference(ctx context.Context, tenantID, userID, channel, eventType string) (*domain.Preference, error)
	UpsertPreference(ctx context.Context, p *domain.Preference) (*domain.Preference, error)
	ListPreferences(ctx context.Context, tenantID, userID string) ([]domain.Preference, error)
}

// Service holds the Notification Center business logic dependencies.
type Service struct {
	store Store
	log   *slog.Logger
}

// New constructs a Service.
func New(s Store, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: s, log: log}
}

// CreateNotificationInput carries the fields for a directly-sent notification.
type CreateNotificationInput struct {
	Channel         string
	EventType       string
	Subject         *string
	Body            *string
	RecipientUserID *string
	ReferenceType   *string
	ReferenceID     *string
	Severity        *string
}

// CreateNotification validates and persists a notification. The in_app channel is
// delivered synchronously (status 'sent', sent_at now); all other channels are
// queued as 'pending' since the MVP has no real dispatcher.
func (s *Service) CreateNotification(ctx context.Context, tenantID string, in CreateNotificationInput) (*domain.Notification, error) {
	channel := in.Channel
	if channel == "" {
		channel = "in_app"
	}
	if !allowedChannels[channel] {
		return nil, newValidation("invalid channel %q", channel)
	}
	if in.EventType == "" {
		return nil, newValidation("event_type is required")
	}

	n := &domain.Notification{
		TenantID: tenantID, RecipientUserID: in.RecipientUserID, Channel: channel,
		EventType: in.EventType, Subject: in.Subject, Body: in.Body,
		ReferenceType: in.ReferenceType, ReferenceID: in.ReferenceID, Severity: in.Severity,
	}
	applyDeliveryStatus(n)
	return s.store.CreateNotification(ctx, n)
}

// applyDeliveryStatus sets status/sent_at for a notification that is about to be
// stored, based on its channel. in_app is delivered immediately; other channels
// are queued pending a (future) dispatcher.
func applyDeliveryStatus(n *domain.Notification) {
	if n.Status == "suppressed" {
		return
	}
	if n.Channel == "in_app" {
		now := time.Now()
		n.Status = "sent"
		n.SentAt = &now
		return
	}
	n.Status = "pending"
}

// NotifyForAlert reacts to an alert.created event by creating an in_app
// notification. High and critical alerts are mandatory security notifications:
// they are always sent and cannot be suppressed by a user preference. For lower
// severities, a disabling preference for (in_app, alert.created) causes the
// notification to be recorded with status 'suppressed' (kept queryable) rather
// than dropped; absent any preference the channel defaults to enabled.
func (s *Service) NotifyForAlert(ctx context.Context, alert types.AlertCreated) (*domain.Notification, error) {
	if alert.TenantID == "" {
		return nil, newValidation("tenant_id is required")
	}

	severity := string(alert.Severity)
	mandatory := alert.Severity == types.SeverityCritical || alert.Severity == types.SeverityHigh

	subject := fmt.Sprintf("Alert: %s", alert.Title)
	body := fmt.Sprintf("A %s severity alert was raised by the %s module: %s",
		severity, alert.SourceModule, alert.Title)
	refType := "alert"
	refID := alert.AlertID

	n := &domain.Notification{
		TenantID: alert.TenantID, Channel: "in_app", EventType: alertCreatedEvent,
		Subject: &subject, Body: &body, ReferenceType: &refType, ReferenceID: &refID,
		Severity: &severity,
	}

	if !mandatory && !s.preferenceEnabled(ctx, alert.TenantID) {
		n.Status = "suppressed"
	}
	applyDeliveryStatus(n)
	return s.store.CreateNotification(ctx, n)
}

// preferenceEnabled reports whether in_app/alert.created notifications are enabled
// for the tenant. A missing preference (or a lookup error) defaults to enabled so
// that notifications are never silently dropped on infrastructure issues.
func (s *Service) preferenceEnabled(ctx context.Context, tenantID string) bool {
	// Preferences are keyed per user; an alert.created notification is a
	// tenant-wide in_app notification with no specific recipient, so the
	// preference is looked up against the empty user id (tenant default).
	pref, err := s.store.GetPreference(ctx, tenantID, "", "in_app", alertCreatedEvent)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			s.log.WarnContext(ctx, "preference lookup failed; defaulting to enabled",
				slog.String("tenant_id", tenantID), slog.String("error", err.Error()))
		}
		return true
	}
	return pref.Enabled
}

// ListNotifications returns notifications for a tenant.
func (s *Service) ListNotifications(ctx context.Context, tenantID string, fil domain.NotificationFilter) ([]domain.Notification, error) {
	return s.store.ListNotifications(ctx, tenantID, fil)
}

// GetNotification returns one notification.
func (s *Service) GetNotification(ctx context.Context, tenantID, id string) (*domain.Notification, error) {
	return s.store.GetNotification(ctx, tenantID, id)
}

// MarkRead marks a notification read.
func (s *Service) MarkRead(ctx context.Context, tenantID, id string) error {
	return s.store.MarkRead(ctx, tenantID, id)
}

// ListPreferences returns the stored preferences for a user.
func (s *Service) ListPreferences(ctx context.Context, tenantID, userID string) ([]domain.Preference, error) {
	return s.store.ListPreferences(ctx, tenantID, userID)
}

// SetPreference validates and upserts a notification preference for a user.
func (s *Service) SetPreference(ctx context.Context, tenantID, userID, channel, eventType string, enabled bool) (*domain.Preference, error) {
	if userID == "" {
		return nil, newValidation("user_id is required")
	}
	if !allowedChannels[channel] {
		return nil, newValidation("invalid channel %q", channel)
	}
	if eventType == "" {
		return nil, newValidation("event_type is required")
	}
	return s.store.UpsertPreference(ctx, &domain.Preference{
		TenantID: tenantID, UserID: userID, Channel: channel, EventType: eventType, Enabled: enabled,
	})
}
