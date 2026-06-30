// Package service implements the CLM service's business logic: credential-leak
// finding lifecycle, validation of CTI-specific rules (credential masking,
// mandatory severity for cleartext credentials, severity overrides), and the
// publication of finding.created / finding.escalated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/clm-service/internal/domain"
	"github.com/siberindo/cti/services/clm-service/internal/events"
	"github.com/siberindo/cti/services/clm-service/internal/store"
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

// allowedCredentialTypes is the approved credential classification set (CLM-FR-002,
// CLM-VR-001).
var allowedCredentialTypes = map[string]bool{
	"cleartext_credential": true, "hashed_credential": true, "api_key": true,
	"service_account_token": true, "oauth_token": true, "session_token": true,
	"certificate_private_key": true,
}

// allowedStatuses is the approved finding status set (CLM-FR-010).
var allowedStatuses = map[string]bool{
	"new": true, "triaged": true, "escalated": true, "notified": true,
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
	AddAffectedUsers(ctx context.Context, tenantID, findingID string, emailsMasked []string) error
	AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error)
	ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error)
	ListSources(ctx context.Context, tenantID string) ([]domain.BreachSource, error)
	CreateSource(ctx context.Context, c *domain.BreachSource) (*domain.BreachSource, error)
}

// Service holds the CLM business logic dependencies.
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
	CredentialType       string
	MaskedIndicator      string
	MaskingPolicyVersion string
	Severity             string
	ConfidenceScore      float64
	BreachSourceID       *string
	BreachName           *string
	DedupKey             string
	AssetIDs             []string
}

// CreateFinding validates and persists a finding, then publishes finding.created.clm.
//
// CLM-FR-011: cleartext credentials carry a mandatory minimum severity of high; if a
// caller passes a lower severity it is bumped to high (critical/high are kept as-is).
// CLM-BR-001 / CLM-VR-006: only a masked indicator is accepted and persisted.
func (s *Service) CreateFinding(ctx context.Context, tenantID string, in CreateFindingInput) (*domain.Finding, error) {
	if !allowedCredentialTypes[in.CredentialType] {
		return nil, newValidation("invalid credential_type %q", in.CredentialType)
	}
	if in.MaskedIndicator == "" {
		return nil, newValidation("masked_indicator is required")
	}
	if in.MaskingPolicyVersion == "" {
		return nil, newValidation("masking_policy_version is required")
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

	severity := enforceCleartextSeverity(in.CredentialType, in.Severity)

	f := &domain.Finding{
		TenantID: tenantID, CredentialType: in.CredentialType,
		MaskedIndicator: in.MaskedIndicator, MaskingPolicyVersion: in.MaskingPolicyVersion,
		Severity: severity, Status: "new", ConfidenceScore: in.ConfidenceScore,
		BreachSourceID: in.BreachSourceID, BreachName: in.BreachName, DedupKey: in.DedupKey,
		UserCorrelationState: "not_applicable", AssetIDs: in.AssetIDs,
	}
	created, err := s.store.CreateFinding(ctx, f)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicFindingCreatedCLM, tenantID, types.FindingCreated{
		EventID: newEventID(), EventType: "finding.created", SourceModule: types.ModuleCLM,
		TenantID: tenantID, FindingID: created.ID, FindingType: created.CredentialType,
		Severity: types.Severity(created.Severity), ConfidenceScore: created.ConfidenceScore,
		AssetIDs: created.AssetIDs, CreatedAt: created.CreatedAt,
	})
	return created, nil
}

// enforceCleartextSeverity implements CLM-FR-011: a confirmed cleartext credential
// gets at least high severity. critical and high are preserved; medium/low/
// informational are bumped to high.
func enforceCleartextSeverity(credentialType, severity string) string {
	if credentialType != "cleartext_credential" {
		return severity
	}
	if types.Severity(severity).Rank() < types.SeverityHigh.Rank() {
		return string(types.SeverityHigh)
	}
	return severity
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

// Escalate marks a finding escalated and publishes finding.escalated.clm so the
// Alert Engine can evaluate it.
func (s *Service) Escalate(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.Escalate(ctx, tenantID, id); err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedCLM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModuleCLM,
		TenantID: tenantID, FindingID: cur.ID, FindingType: cur.CredentialType,
		Severity: types.Severity(cur.Severity), ConfidenceScore: cur.ConfidenceScore,
		AssetIDs: cur.AssetIDs, Title: cur.MaskedIndicator, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return s.store.GetFinding(ctx, tenantID, id)
}

// OverrideSeverity changes a finding's severity, preserving the prior value
// (CLM-FR-012). A justification is required.
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
// (CLM-FR-013 / CLM-VR-007).
func (s *Service) Suppress(ctx context.Context, tenantID, id, justification string) error {
	if justification == "" {
		return newValidation("justification is required to suppress a finding")
	}
	return s.store.Suppress(ctx, tenantID, id, justification)
}

// CorrelateAffectedUsers records correlated affected users for a finding and marks
// the correlation state completed (CLM-FR-007). emailsMasked must already be masked
// (CLM-BR-001).
func (s *Service) CorrelateAffectedUsers(ctx context.Context, tenantID, findingID string, emailsMasked []string) error {
	if len(emailsMasked) == 0 {
		return newValidation("at least one masked email is required")
	}
	for _, email := range emailsMasked {
		if email == "" {
			return newValidation("masked email values must not be empty")
		}
	}
	return s.store.AddAffectedUsers(ctx, tenantID, findingID, emailsMasked)
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

// ListSources returns CLM breach sources.
func (s *Service) ListSources(ctx context.Context, tenantID string) ([]domain.BreachSource, error) {
	return s.store.ListSources(ctx, tenantID)
}

// CreateSource registers a CLM breach source (CLM-FR-019).
func (s *Service) CreateSource(ctx context.Context, tenantID, sourceName, sourceTier, adapterType string) (*domain.BreachSource, error) {
	if sourceName == "" {
		return nil, newValidation("source_name is required")
	}
	if !allowedSourceTiers[sourceTier] {
		return nil, newValidation("invalid source_tier %q", sourceTier)
	}
	if !allowedAdapterTypes[adapterType] {
		return nil, newValidation("invalid adapter_type %q", adapterType)
	}
	return s.store.CreateSource(ctx, &domain.BreachSource{
		TenantID: tenantID, SourceName: sourceName, SourceTier: sourceTier, AdapterType: adapterType,
	})
}

var allowedSourceTiers = map[string]bool{"tier_1": true, "tier_2": true, "tier_3": true}

var allowedAdapterTypes = map[string]bool{
	"breach_feed_api": true, "stealer_log_feed": true,
	"credential_intelligence_api": true, "manual": true,
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
