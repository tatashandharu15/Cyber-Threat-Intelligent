// Package service implements the BRM service's business logic: brand-finding
// lifecycle, validation of CTI-specific rules (similarity-score reproducibility,
// finding-type-specific required fields, takedown eligibility), and the publication
// of finding.created / finding.escalated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/brm-service/internal/domain"
	"github.com/siberindo/cti/services/brm-service/internal/events"
	"github.com/siberindo/cti/services/brm-service/internal/store"
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

var allowedFindingTypes = map[string]bool{
	"lookalike_domain": true, "typosquatting_domain": true,
	"rogue_mobile_application": true, "fake_social_media_profile": true,
	"impersonation_website": true, "unauthorized_brand_usage": true,
	"brand_mention": true,
}

var allowedStatuses = map[string]bool{
	"new": true, "triaged": true, "confirmed": true, "escalated": true,
	"takedown_initiated": true, "takedown_complete": true,
	"suppressed": true, "resolved": true, "closed": true,
}

// Store is the persistence contract.
type Store interface {
	CreateFinding(ctx context.Context, f *domain.Finding) (*domain.Finding, error)
	GetFinding(ctx context.Context, tenantID, id string) (*domain.Finding, error)
	ListFindings(ctx context.Context, tenantID string, fil domain.FindingFilter) ([]domain.Finding, error)
	UpdateStatus(ctx context.Context, tenantID, id, status string) error
	Escalate(ctx context.Context, tenantID, id string) error
	InitiateTakedown(ctx context.Context, tenantID, id string) error
	Suppress(ctx context.Context, tenantID, id, reason string) error
	OverrideSeverity(ctx context.Context, tenantID, id, severity, reason string) error
	AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error)
	ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error)
	ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error)
	CreateSource(ctx context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error)
}

// Service holds the BRM business logic dependencies.
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
	FindingType                string
	Title                      string
	Severity                   string
	ConfidenceScore            float64
	SimilarityScore            *float64
	SimilarityAlgorithmVersion *string
	CandidateValue             string
	SourceID                   *string
	DedupKey                   string
	SocialPlatformID           *string
	SocialAccountHandle        *string
	SocialProfileURL           *string
	AppStoreID                 *string
	AppPlatform                *string
	AppListingURL              *string
	AppPackageID               *string
	AssetIDs                   []string
}

// CreateFinding validates and persists a finding, then publishes finding.created.brm.
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
	if in.CandidateValue == "" {
		return nil, newValidation("candidate_value is required")
	}
	if in.DedupKey == "" {
		return nil, newValidation("dedup_key is required")
	}
	// BRM-VR-008 / BRM-BR-002: a similarity score must be in range and must record
	// the scoring algorithm version that produced it for reproducibility.
	if in.SimilarityScore != nil {
		if *in.SimilarityScore < 0 || *in.SimilarityScore > 1 {
			return nil, newValidation("similarity_score must be between 0 and 1")
		}
		if in.SimilarityAlgorithmVersion == nil || *in.SimilarityAlgorithmVersion == "" {
			return nil, newValidation("similarity_algorithm_version is required when similarity_score is provided")
		}
	}
	// BRM-VR-009: fake social media profile findings must identify the platform plus
	// an account handle or a profile URL.
	if in.FindingType == "fake_social_media_profile" {
		if isBlank(in.SocialPlatformID) {
			return nil, newValidation("social_platform_id is required for fake_social_media_profile findings")
		}
		if isBlank(in.SocialAccountHandle) && isBlank(in.SocialProfileURL) {
			return nil, newValidation("social_account_handle or social_profile_url is required for fake_social_media_profile findings")
		}
	}
	// BRM-VR-010: rogue mobile application findings must identify the store, platform,
	// and a listing URL or package id.
	if in.FindingType == "rogue_mobile_application" {
		if isBlank(in.AppStoreID) {
			return nil, newValidation("app_store_id is required for rogue_mobile_application findings")
		}
		if isBlank(in.AppPlatform) {
			return nil, newValidation("app_platform is required for rogue_mobile_application findings")
		}
		if isBlank(in.AppListingURL) && isBlank(in.AppPackageID) {
			return nil, newValidation("app_listing_url or app_package_id is required for rogue_mobile_application findings")
		}
	}

	f := &domain.Finding{
		TenantID: tenantID, FindingType: in.FindingType, Title: in.Title,
		Severity: in.Severity, Status: "new", ConfidenceScore: in.ConfidenceScore,
		SimilarityScore: in.SimilarityScore, SimilarityAlgorithmVersion: in.SimilarityAlgorithmVersion,
		CandidateValue: in.CandidateValue, SourceID: in.SourceID, DedupKey: in.DedupKey,
		SocialPlatformID: in.SocialPlatformID, SocialAccountHandle: in.SocialAccountHandle,
		SocialProfileURL: in.SocialProfileURL, AppStoreID: in.AppStoreID, AppPlatform: in.AppPlatform,
		AppListingURL: in.AppListingURL, AppPackageID: in.AppPackageID, AssetIDs: in.AssetIDs,
	}
	created, err := s.store.CreateFinding(ctx, f)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicFindingCreatedBRM, tenantID, types.FindingCreated{
		EventID: newEventID(), EventType: "finding.created", SourceModule: types.ModuleBRM,
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

// Escalate marks a finding escalated and publishes finding.escalated.brm so the
// Alert Engine can evaluate it.
func (s *Service) Escalate(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.Escalate(ctx, tenantID, id); err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedBRM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModuleBRM,
		TenantID: tenantID, FindingID: cur.ID, FindingType: cur.FindingType,
		Severity: types.Severity(cur.Severity), ConfidenceScore: cur.ConfidenceScore,
		AssetIDs: cur.AssetIDs, Title: cur.Title, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return s.store.GetFinding(ctx, tenantID, id)
}

// InitiateTakedown moves a confirmed or escalated finding to takedown_initiated.
// Per BRM-BR-005 / BRM-VR-005 only findings in an eligible status are admissible.
func (s *Service) InitiateTakedown(ctx context.Context, tenantID, id string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if cur.Status != "confirmed" && cur.Status != "escalated" {
		return nil, newValidation("takedown can only be initiated for findings in 'confirmed' or 'escalated' status, not %q", cur.Status)
	}
	if err := s.store.InitiateTakedown(ctx, tenantID, id); err != nil {
		return nil, err
	}
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
	EvidenceType string
	StorageRef   *string
	ContentHash  string
	Metadata     []byte
}

// AddEvidence appends immutable evidence to a finding.
func (s *Service) AddEvidence(ctx context.Context, tenantID, findingID string, in AddEvidenceInput) (*domain.Evidence, error) {
	if in.ContentHash == "" {
		return nil, newValidation("content_hash is required")
	}
	return s.store.AddEvidence(ctx, &domain.Evidence{
		TenantID: tenantID, FindingID: findingID, EvidenceType: in.EvidenceType,
		StorageRef: in.StorageRef, ContentHash: in.ContentHash, Metadata: in.Metadata,
	})
}

// ListEvidence returns evidence for a finding.
func (s *Service) ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error) {
	return s.store.ListEvidence(ctx, tenantID, findingID)
}

// ListSources returns BRM collection sources.
func (s *Service) ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error) {
	return s.store.ListSources(ctx, tenantID)
}

// CreateSource registers a BRM collection source.
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

func isBlank(p *string) bool {
	return p == nil || *p == ""
}
