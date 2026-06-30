// Package service implements the DLM service's business logic: finding lifecycle,
// validation of CTI-specific rules (defanged URLs, severity overrides), and the
// publication of finding.created / finding.escalated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/dlm-service/internal/domain"
	"github.com/siberindo/cti/services/dlm-service/internal/events"
	"github.com/siberindo/cti/services/dlm-service/internal/store"
)

// defangedURL matches a defanged http(s) URL ("hXXp://" / "hXXps://"). Storing
// only defanged URLs prevents an operator from accidentally opening a live
// leaked-content link.
var defangedURL = regexp.MustCompile(`^hXXps?://`)

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

var allowedFindingTypes = map[string]bool{
	"credential_reference": true, "pii_exposure": true, "source_code_leak": true,
	"configuration_leak": true, "internal_document_leak": true,
	"database_dump_reference": true, "intellectual_property_leak": true,
}

var allowedStatuses = map[string]bool{
	"new": true, "triaged": true, "enriched": true, "escalated": true,
	"suppressed": true, "resolved": true, "closed": true,
}

// Store is the persistence contract.
type Store interface {
	CreateFinding(ctx context.Context, f *domain.Finding) (*domain.Finding, error)
	GetFinding(ctx context.Context, tenantID, id string) (*domain.Finding, error)
	ListFindings(ctx context.Context, tenantID string, fil domain.FindingFilter) ([]domain.Finding, error)
	UpdateStatus(ctx context.Context, tenantID, id, status string) error
	Escalate(ctx context.Context, tenantID, id string) error
	Suppress(ctx context.Context, tenantID, id, reason string) error
	OverrideSeverity(ctx context.Context, tenantID, id, severity, reason string) error
	AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error)
	ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error)
	ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error)
	CreateSource(ctx context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error)
}

// Service holds the DLM business logic dependencies.
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

// CreateFindingInput carries the fields for a new finding.
type CreateFindingInput struct {
	FindingType     string
	Title           string
	Severity        string
	ConfidenceScore float64
	SourceID        *string
	DedupKey        string
	DetectionMethod *string
	ContentURL      *string
	ContentExcerpt  *string
	ContentHash     *string
	AssetIDs        []string
}

// CreateFinding validates and persists a finding, then publishes finding.created.dlm.
func (s *Service) CreateFinding(ctx context.Context, tenantID string, in CreateFindingInput) (*domain.Finding, error) {
	if !allowedFindingTypes[in.FindingType] {
		return nil, newValidation("invalid finding_type %q", in.FindingType)
	}
	if in.Title == "" {
		return nil, newValidation("title is required")
	}
	if !types.Severity(in.Severity).Valid() {
		return nil, newValidation("invalid severity %q", in.Severity)
	}
	if in.ConfidenceScore < 0 || in.ConfidenceScore > 1 {
		return nil, newValidation("confidence_score must be between 0 and 1")
	}
	if in.DedupKey == "" {
		return nil, newValidation("dedup_key is required")
	}
	if in.ContentURL != nil && *in.ContentURL != "" && !defangedURL.MatchString(*in.ContentURL) {
		return nil, newValidation("content_url must be defanged (e.g. hXXps://...)")
	}

	f := &domain.Finding{
		TenantID: tenantID, FindingType: in.FindingType, Title: in.Title,
		Severity: in.Severity, Status: "new", ConfidenceScore: in.ConfidenceScore,
		SourceID: in.SourceID, DedupKey: in.DedupKey, DetectionMethod: in.DetectionMethod,
		ContentURL: in.ContentURL, ContentExcerpt: in.ContentExcerpt, ContentHash: in.ContentHash,
		AssetIDs: in.AssetIDs,
	}
	created, err := s.store.CreateFinding(ctx, f)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicFindingCreatedDLM, tenantID, types.FindingCreated{
		EventID: newEventID(), EventType: "finding.created", SourceModule: types.ModuleDLM,
		TenantID: tenantID, FindingID: created.ID, FindingType: created.FindingType,
		Severity: types.Severity(created.Severity), ConfidenceScore: created.ConfidenceScore,
		AssetIDs: created.AssetIDs, CreatedAt: created.CreatedAt,
	})
	return created, nil
}

// ListFindings returns findings for a tenant.
func (s *Service) ListFindings(ctx context.Context, tenantID string, fil domain.FindingFilter) ([]domain.Finding, error) {
	return s.store.ListFindings(ctx, tenantID, fil)
}

// GetFinding returns one finding.
func (s *Service) GetFinding(ctx context.Context, tenantID, id string) (*domain.Finding, error) {
	return s.store.GetFinding(ctx, tenantID, id)
}

// UpdateStatus validates and applies a status transition.
func (s *Service) UpdateStatus(ctx context.Context, tenantID, id, status string) error {
	if !allowedStatuses[status] {
		return newValidation("invalid status %q", status)
	}
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if cur.Status == "closed" {
		return newValidation("cannot change status of a closed finding")
	}
	return s.store.UpdateStatus(ctx, tenantID, id, status)
}

// Escalate marks a finding escalated and publishes finding.escalated.dlm so the
// Alert Engine can evaluate it.
func (s *Service) Escalate(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.Escalate(ctx, tenantID, id); err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedDLM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModuleDLM,
		TenantID: tenantID, FindingID: cur.ID, FindingType: cur.FindingType,
		Severity: types.Severity(cur.Severity), ConfidenceScore: cur.ConfidenceScore,
		AssetIDs: cur.AssetIDs, Title: cur.Title, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return s.store.GetFinding(ctx, tenantID, id)
}

// OverrideSeverity changes a finding's severity, preserving the prior value.
func (s *Service) OverrideSeverity(ctx context.Context, tenantID, id, severity, justification string) error {
	if !types.Severity(severity).Valid() {
		return newValidation("invalid severity %q", severity)
	}
	if justification == "" {
		return newValidation("justification is required for a severity override")
	}
	return s.store.OverrideSeverity(ctx, tenantID, id, severity, justification)
}

// Suppress marks a finding as a false positive; a justification is required.
func (s *Service) Suppress(ctx context.Context, tenantID, id, justification string) error {
	if justification == "" {
		return newValidation("justification is required to suppress a finding")
	}
	return s.store.Suppress(ctx, tenantID, id, justification)
}

// AddEvidenceInput carries fields for a new evidence record.
type AddEvidenceInput struct {
	EvidenceType  string
	StorageRef    *string
	ContentHash   string
	CaptureSource string
	Metadata      []byte
}

// AddEvidence appends immutable evidence to a finding.
func (s *Service) AddEvidence(ctx context.Context, tenantID, findingID string, in AddEvidenceInput) (*domain.Evidence, error) {
	if in.ContentHash == "" {
		return nil, newValidation("content_hash is required")
	}
	if in.CaptureSource == "" {
		return nil, newValidation("capture_source is required")
	}
	return s.store.AddEvidence(ctx, &domain.Evidence{
		TenantID: tenantID, FindingID: findingID, EvidenceType: in.EvidenceType,
		StorageRef: in.StorageRef, ContentHash: in.ContentHash, CaptureSource: in.CaptureSource,
		Metadata: in.Metadata,
	})
}

// ListEvidence returns evidence for a finding.
func (s *Service) ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error) {
	return s.store.ListEvidence(ctx, tenantID, findingID)
}

// ListSources returns DLM collection sources.
func (s *Service) ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error) {
	return s.store.ListSources(ctx, tenantID)
}

// CreateSource registers a DLM collection source.
func (s *Service) CreateSource(ctx context.Context, tenantID, sourceType, displayName string) (*domain.CollectionSource, error) {
	if displayName == "" {
		return nil, newValidation("display_name is required")
	}
	return s.store.CreateSource(ctx, &domain.CollectionSource{
		TenantID: tenantID, SourceType: sourceType, DisplayName: displayName,
	})
}

// publish emits an event best-effort: a Kafka failure is logged but does not fail
// the originating request, since the finding is already durably stored.
func (s *Service) publish(ctx context.Context, topic, key string, value any) {
	if s.pub == nil {
		return
	}
	if err := s.pub.Publish(ctx, topic, key, value); err != nil {
		s.log.WarnContext(ctx, "event publish failed", slog.String("topic", topic), slog.String("error", err.Error()))
	}
}
