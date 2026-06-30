// Package consumer is the Kafka side of the Notification Center: it consumes
// alert.created events and turns each into an in_app notification (subject to the
// service's preference and mandatory-security-notification rules).
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/notification-service/internal/domain"
)

// Notifier is the service contract the consumer needs. Using an interface keeps
// the handler unit-testable with a fake.
type Notifier interface {
	NotifyForAlert(ctx context.Context, alert types.AlertCreated) (*domain.Notification, error)
}

// Handler processes alert.created events.
type Handler struct {
	svc Notifier
	log *slog.Logger
}

// New constructs a Handler.
func New(svc Notifier, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{svc: svc, log: log}
}

// Handle is the kafka.Handler entry point. Returning an error triggers a retry,
// so only infrastructure failures (e.g. the DB) return errors; a malformed
// payload will never succeed on retry and is logged and dropped (nil).
func (h *Handler) Handle(ctx context.Context, _, value []byte) error {
	var ev types.AlertCreated
	if err := json.Unmarshal(value, &ev); err != nil {
		h.log.ErrorContext(ctx, "drop unparseable alert.created event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" {
		h.log.WarnContext(ctx, "drop alert.created event missing tenant id")
		return nil
	}

	n, err := h.svc.NotifyForAlert(ctx, ev)
	if err != nil {
		return fmt.Errorf("notify for alert %s: %w", ev.AlertID, err)
	}
	h.log.InfoContext(ctx, "notification created for alert",
		slog.String("tenant_id", ev.TenantID), slog.String("alert_id", ev.AlertID),
		slog.String("notification_id", n.ID), slog.String("status", n.Status))
	return nil
}
