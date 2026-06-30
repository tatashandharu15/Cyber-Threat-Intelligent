// Package consumer is the Kafka side of the Investigation service. It consumes
// alert.created events and records each one in the investigation alert inbox so an
// analyst can later link it into a case.
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/investigation-service/internal/domain"
)

// Store is the persistence contract the consumer needs.
type Store interface {
	InsertInboxAlert(ctx context.Context, a *domain.InboxAlert) error
}

// Handler processes alert.created events.
type Handler struct {
	store Store
	log   *slog.Logger
}

// New constructs a Handler.
func New(store Store, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{store: store, log: log}
}

// Handle is the kafka.Handler entry point. Returning an error triggers a retry, so
// only infrastructure failures (DB) return errors; a malformed or incomplete event
// is logged and dropped.
func (h *Handler) Handle(ctx context.Context, _, value []byte) error {
	var ev types.AlertCreated
	if err := json.Unmarshal(value, &ev); err != nil {
		// A malformed message will never succeed on retry; log and drop it.
		h.log.ErrorContext(ctx, "drop unparseable alert.created event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.AlertID == "" {
		h.log.WarnContext(ctx, "drop alert.created event missing tenant or alert id")
		return nil
	}

	severity := string(ev.Severity)
	title := ev.Title
	a := &domain.InboxAlert{
		TenantID: ev.TenantID, AlertID: ev.AlertID, SourceModule: string(ev.SourceModule),
		SourceFindingID: ev.SourceFindingID,
	}
	if severity != "" {
		a.Severity = &severity
	}
	if title != "" {
		a.Title = &title
	}
	if err := h.store.InsertInboxAlert(ctx, a); err != nil {
		return err
	}
	return nil
}
