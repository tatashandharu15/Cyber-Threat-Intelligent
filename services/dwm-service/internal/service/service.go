// Package service implements the DWM (Dark Web Monitoring) service's business
// logic: finding lifecycle, threat actor profile management, validation of
// DWM-specific rules (defanged URLs, mandatory network-access-sale severity
// elevation, explicit threat-actor link confirmation), and the publication of
// finding.created / finding.escalated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/dwm-service/internal/domain"
	"github.com/siberindo/cti/services/dwm-service/internal/events"
	"github.com/siberindo/cti/services/dwm-service/internal/store"
)

// defangedURL matches a defanged http(s) URL ("hXXp://" / "hXXps://"). Storing
// only defanged URLs prevents an operator from accidentally opening a live dark
// web link.
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
	"sale_listing": true, "network_access_sale": true, "data_breach_advertisement": true,
	"threat_actor_mention": true, "threat_discussion": true,
	"malware_distribution_reference": true, "organizational_intelligence_reference": true,
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
	CreateThreatActor(ctx context.Context, a *domain.ThreatActorProfile) (*domain.ThreatActorProfile, error)
	ListThreatActors(ctx context.Context, tenantID string) ([]domain.ThreatActorProfile, error)
	LinkThreatActor(ctx context.Context, tenantID, findingID, actorID, confirmedBy, justification string) error
	AddEnrichment(ctx context.Context, e *domain.Enrichment) (*domain.Enrichment, error)
}

// Service holds the DWM business logic dependencies.
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
	FindingType        string
	Title              string
	Severity           string
	ConfidenceScore    float64
	SourceTierID       *string
	DedupKey           string
	ContentExcerpt     *string
	ContentURLDefanged *string
	ObservedAt         *time.Time
	AssetIDs           []string
}

// CreateFinding validates and persists a finding, then publishes finding.created.dwm.
//
// DWM-FR-009 / DWM-BR-003: network_access_sale findings receive mandatory elevated
// severity. Any reported severity below 'high' is forced up to 'high' regardless of
// the source-reported confidence level.
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
	if in.ContentURLDefanged != nil && *in.ContentURLDefanged != "" && !defangedURL.MatchString(*in.ContentURLDefanged) {
		return nil, newValidation("content_url_defanged must be defanged (e.g. hXXps://...)")
	}

	severity := in.Severity
	// DWM-FR-009 / DWM-BR-003: mandatory elevated severity for network access sales.
	if in.FindingType == "network_access_sale" && types.Severity(severity).Rank() < types.SeverityHigh.Rank() {
		severity = string(types.SeverityHigh)
	}

	f := &domain.Finding{
		TenantID: tenantID, FindingType: in.FindingType, Title: in.Title,
		Severity: severity, Status: "new", ConfidenceScore: in.ConfidenceScore,
		SourceTierID: in.SourceTierID, DedupKey: in.DedupKey,
		ContentExcerpt: in.ContentExcerpt, ContentURLDefanged: in.ContentURLDefanged,
		ObservedAt: in.ObservedAt, SubmissionType: "automated",
		AssetIDs: in.AssetIDs,
	}
	created, err := s.store.CreateFinding(ctx, f)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicFindingCreatedDWM, tenantID, types.FindingCreated{
		EventID: newEventID(), EventType: "finding.created", SourceModule: types.ModuleDWM,
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

// Escalate marks a finding escalated and publishes finding.escalated.dwm so the
// Alert Engine can evaluate it.
func (s *Service) Escalate(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.Escalate(ctx, tenantID, id); err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedDWM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModuleDWM,
		TenantID: tenantID, FindingID: cur.ID, FindingType: cur.FindingType,
		Severity: types.Severity(cur.Severity), ConfidenceScore: cur.ConfidenceScore,
		AssetIDs: cur.AssetIDs, Title: cur.Title, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return s.store.GetFinding(ctx, tenantID, id)
}

// OverrideSeverity changes a finding's severity, preserving the prior value
// (DWM-FR-010): actor attribution and a justification are required.
func (s *Service) OverrideSeverity(ctx context.Context, tenantID, id, severity, justification string) error {
	if !types.Severity(severity).Valid() {
		return newValidation("invalid severity %q", severity)
	}
	if justification == "" {
		return newValidation("justification is required for a severity override")
	}
	return s.store.OverrideSeverity(ctx, tenantID, id, severity, justification)
}

// Suppress marks a finding as a false positive; a justification is required
// (DWM-FR-011). Suppressed findings remain queryable for audit (DWM-BR-004).
func (s *Service) Suppress(ctx context.Context, tenantID, id, justification string) error {
	if justification == "" {
		return newValidation("justification is required to suppress a finding")
	}
	return s.store.Suppress(ctx, tenantID, id, justification)
}

// AddEvidenceInput carries fields for a new evidence record.
type AddEvidenceInput struct {
	EvidenceType string
	ContentHash  string
	StorageRef   *string
	Metadata     []byte
}

// AddEvidence appends immutable evidence to a finding.
func (s *Service) AddEvidence(ctx context.Context, tenantID, findingID string, in AddEvidenceInput) (*domain.Evidence, error) {
	if in.ContentHash == "" {
		return nil, newValidation("content_hash is required")
	}
	return s.store.AddEvidence(ctx, &domain.Evidence{
		TenantID: tenantID, FindingID: findingID, EvidenceType: in.EvidenceType,
		ContentHash: in.ContentHash, StorageRef: in.StorageRef, Metadata: in.Metadata,
	})
}

// ListEvidence returns evidence for a finding.
func (s *Service) ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error) {
	return s.store.ListEvidence(ctx, tenantID, findingID)
}

// ListThreatActors returns threat actor profiles for a tenant.
func (s *Service) ListThreatActors(ctx context.Context, tenantID string) ([]domain.ThreatActorProfile, error) {
	return s.store.ListThreatActors(ctx, tenantID)
}

// CreateThreatActor registers a threat actor profile. identity is never confirmed at
// creation (DWM-BR-002).
func (s *Service) CreateThreatActor(ctx context.Context, tenantID, codename string, description *string, aliases []string) (*domain.ThreatActorProfile, error) {
	if codename == "" {
		return nil, newValidation("codename is required")
	}
	return s.store.CreateThreatActor(ctx, &domain.ThreatActorProfile{
		TenantID: tenantID, Codename: codename, Description: description, Aliases: aliases,
	})
}

// LinkThreatActor links a finding to a threat actor profile. The link requires
// explicit analyst confirmation and a non-empty justification (DWM-FR-013 /
// DWM-BR-002): the platform never auto-attributes an actor.
func (s *Service) LinkThreatActor(ctx context.Context, tenantID, findingID, actorID, confirmedBy, justification string) error {
	if actorID == "" {
		return newValidation("threat_actor_id is required")
	}
	if justification == "" {
		return newValidation("justification is required to confirm a threat actor linkage")
	}
	return s.store.LinkThreatActor(ctx, tenantID, findingID, actorID, confirmedBy, justification)
}

// AddEnrichmentInput carries fields for a new finding enrichment.
type AddEnrichmentInput struct {
	TacticsObserved    []string
	AffectedAssetScope *string
	ResponseIndicators *string
}

// AddEnrichment records analyst-added structured threat context for a finding
// (DWM-FR-014).
func (s *Service) AddEnrichment(ctx context.Context, tenantID, findingID string, in AddEnrichmentInput) (*domain.Enrichment, error) {
	return s.store.AddEnrichment(ctx, &domain.Enrichment{
		TenantID: tenantID, FindingID: findingID, TacticsObserved: in.TacticsObserved,
		AffectedAssetScope: in.AffectedAssetScope, ResponseIndicators: in.ResponseIndicators,
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
