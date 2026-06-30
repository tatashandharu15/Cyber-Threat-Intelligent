// Package consumer is the Kafka side of the Reporting service. For each
// report.requested event it drives report generation via the Generator (the
// service layer's deterministic MVP generator).
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
)

// Generator performs report generation for a requested report. The service layer's
// *Service.Generate satisfies this; tests use a fake.
type Generator interface {
	Generate(ctx context.Context, ev types.ReportRequested) error
}

// Handler processes report.requested events.
type Handler struct {
	generator Generator
	log       *slog.Logger
}

// New constructs a Handler.
func New(generator Generator, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{generator: generator, log: log}
}

// Handle is the kafka.Handler entry point. Returning an error triggers a retry, so
// only genuine infrastructure failures (returned by the generator) cause a retry; a
// malformed or empty-tenant message can never succeed on retry, so it is logged and
// dropped (nil).
func (h *Handler) Handle(ctx context.Context, _, value []byte) error {
	var ev types.ReportRequested
	if err := json.Unmarshal(value, &ev); err != nil {
		h.log.ErrorContext(ctx, "drop unparseable report.requested event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.ReportID == "" {
		h.log.WarnContext(ctx, "drop report.requested event missing tenant or report id")
		return nil
	}
	return h.generator.Generate(ctx, ev)
}
