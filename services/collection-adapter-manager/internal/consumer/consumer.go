// Package consumer turns the collection-job outcome events produced by the
// detection modules into adapter-health updates. It is the Kafka side of the
// Collection Adapter Manager: it consumes the existing collection.job.completed and
// collection.job.failed topics and records each run against the reporting adapter.
package consumer

import (
	"context"
	"encoding/json"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/service"
)

// Ingester records a normalized collection run. It is an interface so the handler
// can be unit-tested without a database.
type Ingester interface {
	IngestRun(ctx context.Context, run service.Run) error
}

// Handler dispatches collection-job events to the ingester. It exposes one handler
// per topic because the two topics carry different payload shapes.
type Handler struct {
	ingester Ingester
	log      *slog.Logger
}

// New constructs a Handler.
func New(ingester Ingester, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{ingester: ingester, log: log}
}

// HandleCompleted is the kafka.Handler for collection.job.completed. A malformed or
// empty-tenant payload is logged and dropped (it would never succeed on retry).
func (h *Handler) HandleCompleted(ctx context.Context, _, value []byte) error {
	var ev types.CollectionJobResult
	if err := json.Unmarshal(value, &ev); err != nil {
		h.log.ErrorContext(ctx, "drop unparseable collection.job.completed event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.SourceAdapterID == "" {
		h.log.WarnContext(ctx, "drop collection.job.completed event missing tenant or adapter id")
		return nil
	}
	findings := ev.FindingsIngested
	errs := ev.ErrorsCount
	return h.ingester.IngestRun(ctx, service.Run{
		TenantID: ev.TenantID, AdapterID: ev.SourceAdapterID, Module: string(ev.Module),
		Outcome: "completed", FindingsIngested: &findings, ErrorsCount: &errs,
	})
}

// HandleFailed is the kafka.Handler for collection.job.failed. A malformed or
// empty-tenant payload is logged and dropped.
func (h *Handler) HandleFailed(ctx context.Context, _, value []byte) error {
	var ev types.CollectionJobFailed
	if err := json.Unmarshal(value, &ev); err != nil {
		h.log.ErrorContext(ctx, "drop unparseable collection.job.failed event", slog.String("error", err.Error()))
		return nil
	}
	if ev.TenantID == "" || ev.SourceAdapterID == "" {
		h.log.WarnContext(ctx, "drop collection.job.failed event missing tenant or adapter id")
		return nil
	}
	return h.ingester.IngestRun(ctx, service.Run{
		TenantID: ev.TenantID, AdapterID: ev.SourceAdapterID, Module: string(ev.Module),
		Outcome: "failed", Detail: ev.Error,
	})
}
