// Package consumer is the Kafka side of the Audit Log service: it ingests
// audit.event.written events emitted by every other service and persists them as
// tamper-evident audit records.
package consumer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/audit-service/internal/domain"
)

// Recorder is the contract the consumer needs (an interface so it is unit-testable).
type Recorder interface {
	RecordFromEvent(ctx context.Context, ev types.AuditEventWritten) (*domain.AuditEvent, error)
}

// Handler processes audit.event.written events.
type Handler struct {
	recorder Recorder
	log      *slog.Logger
}

// New constructs a Handler.
func New(recorder Recorder, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{recorder: recorder, log: log}
}

// Handle is the kafka.Handler entry point. Returning an error triggers a retry, so
// only infrastructure failures (e.g. the DB insert) return errors; a malformed or
// incomplete message is logged and dropped (a retry would never succeed).
func (h *Handler) Handle(ctx context.Context, _, value []byte) error {
	var ev types.AuditEventWritten
	if err := json.Unmarshal(value, &ev); err != nil {
		h.log.ErrorContext(ctx, "drop unparseable audit.event.written event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.ActorID == "" {
		h.log.WarnContext(ctx, "drop audit.event.written event missing tenant or actor id")
		return nil
	}
	if _, err := h.recorder.RecordFromEvent(ctx, ev); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}
