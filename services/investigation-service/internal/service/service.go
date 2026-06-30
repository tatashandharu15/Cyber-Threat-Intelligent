// Package service implements the Investigation service's business logic: the
// investigation lifecycle (open, assign, note, link findings, close), validation
// of status transitions and link sources, and the immutable timeline.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/siberindo/cti/services/investigation-service/internal/domain"
	"github.com/siberindo/cti/services/investigation-service/internal/store"
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

var allowedStatuses = map[string]bool{
	"open": true, "in_progress": true, "pending_review": true, "closed": true,
}

var allowedPriorities = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true,
}

var allowedLinkModules = map[string]bool{
	"dlm": true, "clm": true, "dwm": true, "brm": true, "phm": true,
}

// Store is the persistence contract.
type Store interface {
	CreateInvestigation(ctx context.Context, inv *domain.Investigation) (*domain.Investigation, error)
	GetInvestigation(ctx context.Context, tenantID, id string) (*domain.Investigation, error)
	ListInvestigations(ctx context.Context, tenantID string, fil domain.InvestigationFilter) ([]domain.Investigation, error)
	UpdateStatus(ctx context.Context, tenantID, id, status string) error
	Assign(ctx context.Context, tenantID, id, assignedTo string) error
	AddNote(ctx context.Context, tenantID, id, note string) error
	Close(ctx context.Context, tenantID, id string) error
	LinkFinding(ctx context.Context, lf *domain.LinkedFinding) error
	ListLinkedFindings(ctx context.Context, tenantID, investigationID string) ([]domain.LinkedFinding, error)
	ListTimeline(ctx context.Context, tenantID, investigationID string) ([]domain.TimelineEntry, error)
	ListInbox(ctx context.Context, tenantID string) ([]domain.InboxAlert, error)
}

// Service holds the Investigation business logic dependencies.
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

// CreateInvestigationInput carries the fields for a new investigation.
type CreateInvestigationInput struct {
	Title       string
	Description *string
	Priority    string
}

// CreateInvestigation validates and persists a new investigation.
func (s *Service) CreateInvestigation(ctx context.Context, tenantID string, in CreateInvestigationInput) (*domain.Investigation, error) {
	if in.Title == "" {
		return nil, newValidation("title is required")
	}
	priority := in.Priority
	if priority == "" {
		priority = "medium"
	}
	if !allowedPriorities[priority] {
		return nil, newValidation("invalid priority %q", priority)
	}
	return s.store.CreateInvestigation(ctx, &domain.Investigation{
		TenantID: tenantID, Title: in.Title, Description: in.Description,
		Status: "open", Priority: priority,
	})
}

// ListInvestigations returns investigations for a tenant.
func (s *Service) ListInvestigations(ctx context.Context, tenantID string, fil domain.InvestigationFilter) ([]domain.Investigation, error) {
	return s.store.ListInvestigations(ctx, tenantID, fil)
}

// GetInvestigation returns one investigation.
func (s *Service) GetInvestigation(ctx context.Context, tenantID, id string) (*domain.Investigation, error) {
	return s.store.GetInvestigation(ctx, tenantID, id)
}

// ListLinkedFindings returns the findings linked into an investigation.
func (s *Service) ListLinkedFindings(ctx context.Context, tenantID, id string) ([]domain.LinkedFinding, error) {
	return s.store.ListLinkedFindings(ctx, tenantID, id)
}

// ListTimeline returns the timeline for an investigation.
func (s *Service) ListTimeline(ctx context.Context, tenantID, id string) ([]domain.TimelineEntry, error) {
	return s.store.ListTimeline(ctx, tenantID, id)
}

// ListInbox returns the unlinked alert inbox for a tenant.
func (s *Service) ListInbox(ctx context.Context, tenantID string) ([]domain.InboxAlert, error) {
	return s.store.ListInbox(ctx, tenantID)
}

// UpdateStatus validates and applies a status transition.
func (s *Service) UpdateStatus(ctx context.Context, tenantID, id, status string) error {
	if !allowedStatuses[status] {
		return newValidation("invalid status %q", status)
	}
	cur, err := s.store.GetInvestigation(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "closed" {
		return newValidation("cannot change status of a closed investigation")
	}
	return s.store.UpdateStatus(ctx, tenantID, id, status)
}

// Assign sets the assignee on an investigation.
func (s *Service) Assign(ctx context.Context, tenantID, id, assignedTo string) error {
	if assignedTo == "" {
		return newValidation("assigned_to is required")
	}
	return s.store.Assign(ctx, tenantID, id, assignedTo)
}

// AddNote appends a free-text note to an investigation's timeline.
func (s *Service) AddNote(ctx context.Context, tenantID, id, note string) error {
	if note == "" {
		return newValidation("note is required")
	}
	return s.store.AddNote(ctx, tenantID, id, note)
}

// Close marks an investigation closed.
func (s *Service) Close(ctx context.Context, tenantID, id string) error {
	cur, err := s.store.GetInvestigation(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "closed" {
		return newValidation("investigation is already closed")
	}
	return s.store.Close(ctx, tenantID, id)
}

// LinkFindingInput carries the fields for linking a finding into an investigation.
type LinkFindingInput struct {
	SourceModule    string
	SourceFindingID string
	Notes           *string
}

// LinkFinding validates and links a detection-module finding into an investigation.
func (s *Service) LinkFinding(ctx context.Context, tenantID, id string, in LinkFindingInput) error {
	if !allowedLinkModules[in.SourceModule] {
		return newValidation("invalid source_module %q", in.SourceModule)
	}
	if in.SourceFindingID == "" {
		return newValidation("source_finding_id is required")
	}
	return s.store.LinkFinding(ctx, &domain.LinkedFinding{
		InvestigationID: id, SourceModule: in.SourceModule, SourceFindingID: in.SourceFindingID,
		TenantID: tenantID, Notes: in.Notes,
	})
}
