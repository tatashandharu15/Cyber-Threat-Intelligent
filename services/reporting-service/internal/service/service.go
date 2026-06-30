// Package service implements the Reporting service's business logic: validating a
// report request, queuing it, publishing report.requested for asynchronous
// generation, and the deterministic MVP generator that the Kafka consumer drives.
//
// The MVP generator does NOT render a real document. A production deployment will
// run a dedicated worker that materializes a PDF/CSV/XLSX/JSON artifact and uploads
// it to object storage; here we synthesize a stable output reference so the full
// request -> queued -> generating -> complete lifecycle (and its events) can be
// exercised end to end.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/reporting-service/internal/domain"
	"github.com/siberindo/cti/services/reporting-service/internal/events"
	"github.com/siberindo/cti/services/reporting-service/internal/store"
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

var allowedReportTypes = map[string]bool{
	"executive_summary": true, "module_finding_report": true, "takedown_status_report": true,
	"credential_exposure_report": true, "threat_actor_report": true, "sla_compliance_report": true,
}

var allowedFormats = map[string]bool{
	"pdf": true, "csv": true, "json": true, "xlsx": true,
}

// Store is the persistence contract.
type Store interface {
	CreateReport(ctx context.Context, r *domain.Report) (*domain.Report, error)
	GetReport(ctx context.Context, tenantID, id string) (*domain.Report, error)
	ListReports(ctx context.Context, tenantID string, fil domain.ReportFilter) ([]domain.Report, error)
	MarkGenerating(ctx context.Context, tenantID, id string) error
	MarkComplete(ctx context.Context, tenantID, id, outputRef string, generatedAt time.Time) error
	MarkFailed(ctx context.Context, tenantID, id, reason string) error
}

// Service holds the Reporting business logic dependencies.
type Service struct {
	store Store
	pub   events.Publisher
	log   *slog.Logger
}

// New constructs a Service.
func New(s Store, pub events.Publisher, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: s, pub: pub, log: log}
}

// RequestReportInput carries the fields for a new report request.
type RequestReportInput struct {
	ReportType  string
	Title       string
	Format      string
	Parameters  []byte
	RequestedBy *string
}

// RequestReport validates and queues a report, then publishes report.requested so
// the generation worker (here, this service's own consumer) picks it up. The
// publish is best-effort: a Kafka failure is logged but does not fail the request,
// since the report is already durably stored in the 'queued' state.
func (s *Service) RequestReport(ctx context.Context, tenantID string, in RequestReportInput) (*domain.Report, error) {
	if !allowedReportTypes[in.ReportType] {
		return nil, newValidation("invalid report_type %q", in.ReportType)
	}
	if in.Title == "" {
		return nil, newValidation("title is required")
	}
	format := in.Format
	if format == "" {
		format = "pdf"
	}
	if !allowedFormats[format] {
		return nil, newValidation("invalid output_format %q", format)
	}

	created, err := s.store.CreateReport(ctx, &domain.Report{
		TenantID: tenantID, ReportType: in.ReportType, Title: in.Title,
		Status: "queued", OutputFormat: format, Parameters: in.Parameters,
		RequestedBy: in.RequestedBy,
	})
	if err != nil {
		return nil, err
	}

	requestedBy := ""
	if created.RequestedBy != nil {
		requestedBy = *created.RequestedBy
	}
	s.publish(ctx, types.TopicReportRequested, tenantID, types.ReportRequested{
		EventID: newEventID(), EventType: "report.requested", TenantID: tenantID,
		ReportID: created.ID, ReportType: created.ReportType, Format: created.OutputFormat,
		RequestedBy: requestedBy, CreatedAt: created.CreatedAt,
	})
	return created, nil
}

// Generate performs the (MVP, deterministic) generation of a requested report. It
// is invoked by the Kafka consumer for each report.requested event: it marks the
// report 'generating', synthesizes a stable output reference, marks it 'complete',
// and publishes report.completed. On any failure it marks the report 'failed' and
// publishes report.completed with status 'failed'.
func (s *Service) Generate(ctx context.Context, ev types.ReportRequested) error {
	if err := s.store.MarkGenerating(ctx, ev.TenantID, ev.ReportID); err != nil {
		return s.fail(ctx, ev, fmt.Errorf("mark generating: %w", err))
	}

	format := ev.Format
	if format == "" {
		format = "pdf"
	}
	// MVP: no real document is rendered. A production worker replaces this with
	// actual PDF/CSV/XLSX/JSON generation and an object-storage upload.
	outputRef := fmt.Sprintf("s3://siberindo-reports/%s/%s.%s", ev.TenantID, ev.ReportID, format)

	if err := s.store.MarkComplete(ctx, ev.TenantID, ev.ReportID, outputRef, time.Now()); err != nil {
		return s.fail(ctx, ev, fmt.Errorf("mark complete: %w", err))
	}

	s.publish(ctx, types.TopicReportCompleted, ev.TenantID, types.ReportCompleted{
		EventID: newEventID(), EventType: "report.completed", TenantID: ev.TenantID,
		ReportID: ev.ReportID, Status: "complete", OutputRef: outputRef, CreatedAt: time.Now(),
	})
	return nil
}

// fail records a failed generation and publishes report.completed with status
// 'failed'. It returns nil so the consumer treats generation failure as handled
// (not an infra retry): the failure is durably recorded on the report row.
func (s *Service) fail(ctx context.Context, ev types.ReportRequested, cause error) error {
	s.log.ErrorContext(ctx, "report generation failed",
		slog.String("tenant_id", ev.TenantID), slog.String("report_id", ev.ReportID),
		slog.String("error", cause.Error()))
	if err := s.store.MarkFailed(ctx, ev.TenantID, ev.ReportID, cause.Error()); err != nil {
		// The report could not be marked failed; return the original cause so the
		// consumer retries the whole event.
		return fmt.Errorf("mark failed after %v: %w", cause, err)
	}
	s.publish(ctx, types.TopicReportCompleted, ev.TenantID, types.ReportCompleted{
		EventID: newEventID(), EventType: "report.completed", TenantID: ev.TenantID,
		ReportID: ev.ReportID, Status: "failed", CreatedAt: time.Now(),
	})
	return nil
}

// ListReports returns reports for a tenant.
func (s *Service) ListReports(ctx context.Context, tenantID string, fil domain.ReportFilter) ([]domain.Report, error) {
	return s.store.ListReports(ctx, tenantID, fil)
}

// GetReport returns one report.
func (s *Service) GetReport(ctx context.Context, tenantID, id string) (*domain.Report, error) {
	return s.store.GetReport(ctx, tenantID, id)
}

// publish emits an event best-effort: a Kafka failure is logged but does not fail
// the originating operation, since the report is already durably stored.
func (s *Service) publish(ctx context.Context, topic, key string, value any) {
	if s.pub == nil {
		return
	}
	if err := s.pub.Publish(ctx, topic, key, value); err != nil {
		s.log.WarnContext(ctx, "event publish failed", slog.String("topic", topic), slog.String("error", err.Error()))
	}
}
