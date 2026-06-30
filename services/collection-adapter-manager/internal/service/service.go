// Package service implements the Collection Adapter Manager's business logic:
// adapter registration, lifecycle transitions (pause/resume/retire), on-demand
// trigger intent, and ingestion of the collection-run outcomes reported by the
// detection modules over Kafka.
//
// This service is a pure Kafka CONSUMER for adapter-health tracking. It consumes
// the existing collection.job.completed and collection.job.failed topics and does
// NOT publish any events of its own (the Kafka Topic Catalog defines no
// collection-request topic), so there is no producer here.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/domain"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/store"
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

// Store is the persistence contract the service needs.
type Store interface {
	CreateAdapter(ctx context.Context, a *domain.Adapter) (*domain.Adapter, error)
	GetAdapter(ctx context.Context, tenantID, id string) (*domain.Adapter, error)
	ListAdapters(ctx context.Context, tenantID string, fil domain.AdapterFilter) ([]domain.Adapter, error)
	UpdateAdapter(ctx context.Context, tenantID, id string, scheduleCron, configRef *string) error
	SetStatus(ctx context.Context, tenantID, id, status string) error
	ListRuns(ctx context.Context, tenantID, adapterID string) ([]domain.RunEvent, error)
	RecordRunByAdapterID(ctx context.Context, tenantID, adapterID, module, outcome string, findingsIngested, errorsCount *int, detail string) error
}

// Service holds the Collection Adapter Manager business logic dependencies.
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

// CreateAdapterInput carries the fields for a new adapter.
type CreateAdapterInput struct {
	Module       string
	AdapterType  string
	Name         string
	ScheduleCron *string
	ConfigRef    *string
}

// CreateAdapter validates and registers a new collection adapter.
func (s *Service) CreateAdapter(ctx context.Context, tenantID string, in CreateAdapterInput) (*domain.Adapter, error) {
	if !types.Module(in.Module).Valid() {
		return nil, newValidation("invalid module %q", in.Module)
	}
	if in.AdapterType == "" {
		return nil, newValidation("adapter_type is required")
	}
	if in.Name == "" {
		return nil, newValidation("name is required")
	}
	return s.store.CreateAdapter(ctx, &domain.Adapter{
		TenantID: tenantID, Module: in.Module, AdapterType: in.AdapterType, Name: in.Name,
		ScheduleCron: in.ScheduleCron, ConfigRef: in.ConfigRef,
	})
}

// ListAdapters returns adapters for a tenant.
func (s *Service) ListAdapters(ctx context.Context, tenantID string, fil domain.AdapterFilter) ([]domain.Adapter, error) {
	return s.store.ListAdapters(ctx, tenantID, fil)
}

// GetAdapter returns one adapter.
func (s *Service) GetAdapter(ctx context.Context, tenantID, id string) (*domain.Adapter, error) {
	return s.store.GetAdapter(ctx, tenantID, id)
}

// UpdateAdapter applies a partial update of schedule_cron and config_ref.
func (s *Service) UpdateAdapter(ctx context.Context, tenantID, id string, scheduleCron, configRef *string) error {
	return s.store.UpdateAdapter(ctx, tenantID, id, scheduleCron, configRef)
}

// Pause moves an adapter to the paused state. Retired adapters are terminal and
// cannot be paused.
func (s *Service) Pause(ctx context.Context, tenantID, id string) error {
	cur, err := s.store.GetAdapter(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "retired" {
		return newValidation("cannot pause a retired adapter")
	}
	return s.store.SetStatus(ctx, tenantID, id, "paused")
}

// Resume moves an adapter back to the active state. Retired adapters are terminal
// and cannot be resumed.
func (s *Service) Resume(ctx context.Context, tenantID, id string) error {
	cur, err := s.store.GetAdapter(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "retired" {
		return newValidation("cannot resume a retired adapter")
	}
	return s.store.SetStatus(ctx, tenantID, id, "active")
}

// Retire permanently retires an adapter. Retirement is terminal.
func (s *Service) Retire(ctx context.Context, tenantID, id string) error {
	cur, err := s.store.GetAdapter(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "retired" {
		return nil
	}
	return s.store.SetStatus(ctx, tenantID, id, "retired")
}

// Trigger records the intent to run an adapter on demand. For the MVP it validates
// that the adapter exists and is active and returns success; the actual job
// dispatch is the collection worker's responsibility. The Kafka Topic Catalog
// defines no collection-request topic, so nothing is published here.
func (s *Service) Trigger(ctx context.Context, tenantID, id string) error {
	cur, err := s.store.GetAdapter(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status != "active" {
		return newValidation("cannot trigger adapter in status %q; adapter must be active", cur.Status)
	}
	s.log.InfoContext(ctx, "collection adapter trigger requested",
		slog.String("tenant_id", tenantID), slog.String("adapter_id", id), slog.String("module", cur.Module))
	return nil
}

// ListRuns returns the run history for an adapter.
func (s *Service) ListRuns(ctx context.Context, tenantID, adapterID string) ([]domain.RunEvent, error) {
	return s.store.ListRuns(ctx, tenantID, adapterID)
}

// Run is a normalized collection-run outcome, derived by the consumer from either a
// collection.job.completed or a collection.job.failed event.
type Run struct {
	TenantID         string
	AdapterID        string
	Module           string
	Outcome          string // "completed" | "failed"
	FindingsIngested *int
	ErrorsCount      *int
	Detail           string
}

// IngestRun is called by the Kafka consumer for both completed and failed runs. It
// maps the normalized run onto the store, which updates adapter health and appends
// an immutable run-event row. An event whose adapter id does not resolve is
// logged and skipped by the store rather than failing the consumer.
func (s *Service) IngestRun(ctx context.Context, run Run) error {
	if run.TenantID == "" || run.AdapterID == "" {
		s.log.WarnContext(ctx, "drop collection run event missing tenant or adapter id")
		return nil
	}
	return s.store.RecordRunByAdapterID(ctx, run.TenantID, run.AdapterID, run.Module, run.Outcome,
		run.FindingsIngested, run.ErrorsCount, run.Detail)
}
