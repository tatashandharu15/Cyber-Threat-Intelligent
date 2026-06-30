// Package service implements the Takedown service's business logic: takedown
// request creation, the status state machine, and publication of
// takedown.requested / takedown.status.updated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/takedown-service/internal/domain"
	"github.com/siberindo/cti/services/takedown-service/internal/events"
	"github.com/siberindo/cti/services/takedown-service/internal/store"
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

var allowedSourceModules = map[string]bool{
	"brm": true, "phm": true,
}

var allowedTargetTypes = map[string]bool{
	"registrar": true, "app_store_operator": true, "social_platform": true,
	"hosting_provider": true, "cert_authority": true,
}

// validTransitions encodes the takedown status state machine: each key is a
// current status mapped to the set of statuses it may transition to.
var validTransitions = map[string]map[string]bool{
	"draft":        {"submitted": true},
	"submitted":    {"acknowledged": true, "rejected": true},
	"acknowledged": {"actioned": true, "rejected": true},
	"actioned":     {"closed": true},
	"rejected":     {"closed": true},
}

// validTransition reports whether moving from->to is an allowed status change.
func validTransition(from, to string) bool {
	return validTransitions[from][to]
}

// Store is the persistence contract.
type Store interface {
	CreateTakedown(ctx context.Context, t *domain.Takedown) (*domain.Takedown, error)
	GetTakedown(ctx context.Context, tenantID, id string) (*domain.Takedown, error)
	ListTakedowns(ctx context.Context, tenantID string, fil domain.TakedownFilter) ([]domain.Takedown, error)
	Transition(ctx context.Context, tenantID, id, newStatus, operatorResponse, actorID string) error
	ListEvents(ctx context.Context, tenantID, takedownID string) ([]domain.TakedownEvent, error)
}

// Service holds the Takedown business logic dependencies.
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

// CreateTakedownInput carries the fields for a new takedown request.
type CreateTakedownInput struct {
	SourceModule         string
	SourceFindingID      string
	SubmissionTarget     string
	SubmissionTargetType string
	EvidencePackageRef   string
}

// CreateTakedown validates and persists a takedown request in 'draft' status. No
// event is published yet because the request has not been submitted.
func (s *Service) CreateTakedown(ctx context.Context, tenantID string, in CreateTakedownInput) (*domain.Takedown, error) {
	if !allowedSourceModules[in.SourceModule] {
		return nil, newValidation("invalid source_module %q", in.SourceModule)
	}
	if in.SourceFindingID == "" {
		return nil, newValidation("source_finding_id is required")
	}
	if in.SubmissionTarget == "" {
		return nil, newValidation("submission_target is required")
	}
	if !allowedTargetTypes[in.SubmissionTargetType] {
		return nil, newValidation("invalid submission_target_type %q", in.SubmissionTargetType)
	}
	if in.EvidencePackageRef == "" {
		return nil, newValidation("evidence_package_ref is required")
	}

	t := &domain.Takedown{
		TenantID: tenantID, SourceModule: in.SourceModule, SourceFindingID: in.SourceFindingID,
		Status: "draft", SubmissionTarget: in.SubmissionTarget,
		SubmissionTargetType: in.SubmissionTargetType, EvidencePackageRef: in.EvidencePackageRef,
	}
	return s.store.CreateTakedown(ctx, t)
}

// ListTakedowns returns takedown requests for a tenant.
func (s *Service) ListTakedowns(ctx context.Context, tenantID string, fil domain.TakedownFilter) ([]domain.Takedown, error) {
	return s.store.ListTakedowns(ctx, tenantID, fil)
}

// GetTakedown returns one takedown request.
func (s *Service) GetTakedown(ctx context.Context, tenantID, id string) (*domain.Takedown, error) {
	return s.store.GetTakedown(ctx, tenantID, id)
}

// ListEvents returns the accountability-chain events for a takedown request.
func (s *Service) ListEvents(ctx context.Context, tenantID, takedownID string) ([]domain.TakedownEvent, error) {
	return s.store.ListEvents(ctx, tenantID, takedownID)
}

// Submit moves a draft takedown to 'submitted' and publishes both
// takedown.requested and takedown.status.updated.
func (s *Service) Submit(ctx context.Context, tenantID, id, actorID string) (*domain.Takedown, error) {
	cur, err := s.store.GetTakedown(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if !validTransition(cur.Status, "submitted") {
		return nil, newValidation("cannot submit a takedown in status %q", cur.Status)
	}
	if err := s.store.Transition(ctx, tenantID, id, "submitted", "", actorID); err != nil {
		return nil, err
	}
	updated, err := s.store.GetTakedown(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicTakedownRequested, tenantID, types.TakedownRequested{
		EventID: newEventID(), EventType: "takedown.requested", TenantID: tenantID,
		TakedownID: updated.ID, SourceModule: updated.SourceModule,
		SourceFindingID: updated.SourceFindingID, SubmissionTarget: updated.SubmissionTarget,
		SubmissionTargetType: updated.SubmissionTargetType, RequestedBy: actorID,
		CreatedAt: updated.CreatedAt,
	})
	s.publish(ctx, types.TopicTakedownStatusUpdate, tenantID, types.TakedownStatusUpdate{
		EventID: newEventID(), EventType: "takedown.status.updated", TenantID: tenantID,
		TakedownID: updated.ID, SourceModule: updated.SourceModule,
		SourceFindingID: updated.SourceFindingID, Status: updated.Status,
		UpdatedAt: time.Now(),
	})
	return updated, nil
}

// UpdateStatus validates and applies a status transition (operator acknowledgement,
// action, rejection, or close), then publishes takedown.status.updated.
func (s *Service) UpdateStatus(ctx context.Context, tenantID, id, newStatus, operatorResponse, actorID string) (*domain.Takedown, error) {
	cur, err := s.store.GetTakedown(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if !validTransition(cur.Status, newStatus) {
		return nil, newValidation("invalid transition %q -> %q", cur.Status, newStatus)
	}
	if err := s.store.Transition(ctx, tenantID, id, newStatus, operatorResponse, actorID); err != nil {
		return nil, err
	}
	updated, err := s.store.GetTakedown(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicTakedownStatusUpdate, tenantID, types.TakedownStatusUpdate{
		EventID: newEventID(), EventType: "takedown.status.updated", TenantID: tenantID,
		TakedownID: updated.ID, SourceModule: updated.SourceModule,
		SourceFindingID: updated.SourceFindingID, Status: updated.Status,
		OperatorResponse: operatorResponse, UpdatedAt: time.Now(),
	})
	return updated, nil
}

// publish emits an event best-effort: a Kafka failure is logged but does not fail
// the originating request, since the takedown is already durably stored.
func (s *Service) publish(ctx context.Context, topic, key string, value any) {
	if s.pub == nil {
		return
	}
	if err := s.pub.Publish(ctx, topic, key, value); err != nil {
		s.log.WarnContext(ctx, "event publish failed", slog.String("topic", topic), slog.String("error", err.Error()))
	}
}
