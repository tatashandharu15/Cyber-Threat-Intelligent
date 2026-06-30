// Package service implements the PHM service's business logic: finding lifecycle,
// validation of CTI-specific rules (defanged phishing URLs, severity overrides, TLP
// markings), urgency promotion for confirmed active phishing infrastructure, and
// the publication of finding.created / finding.escalated events.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/phm-service/internal/domain"
	"github.com/siberindo/cti/services/phm-service/internal/events"
	"github.com/siberindo/cti/services/phm-service/internal/store"
)

// defangedURL matches a defanged http(s) URL ("hXXp://" / "hXXps://"). PHM stores
// ONLY defanged URLs so that an operator can never accidentally open a live
// phishing link from an analyst-facing interface (PHM-FR-008, PHM-VR-005).
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
	"active_phishing_page": true, "credential_harvesting_page": true,
	"brand_impersonation_page": true, "malware_distribution_page": true,
	"phishing_kit_deployment": true, "spear_phishing_infrastructure": true,
	"smishing_url": true,
}

var allowedStatuses = map[string]bool{
	"new": true, "triaged": true, "confirmed": true, "escalated": true,
	"takedown_initiated": true, "takedown_complete": true, "suppressed": true,
	"resolved": true, "closed": true,
}

var allowedIndicatorTypes = map[string]bool{
	"domain": true, "ip_address": true, "url_defanged": true, "hash_md5": true,
	"hash_sha1": true, "hash_sha256": true, "email_address": true, "asn": true,
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
	PromoteUrgency(ctx context.Context, tenantID, id, newSeverity string) error
	CreateCampaign(ctx context.Context, c *domain.Campaign) (*domain.Campaign, error)
	ListCampaigns(ctx context.Context, tenantID string) ([]domain.Campaign, error)
	AddIndicator(ctx context.Context, i *domain.Indicator) (*domain.Indicator, error)
	ListIndicators(ctx context.Context, tenantID, findingID string) ([]domain.Indicator, error)
	AddCertificate(ctx context.Context, c *domain.SSLCertificate) (*domain.SSLCertificate, error)
	ListCertificates(ctx context.Context, tenantID, findingID string) ([]domain.SSLCertificate, error)
	AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error)
	ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error)
	ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error)
	CreateSource(ctx context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error)
}

// Service holds the PHM business logic dependencies.
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
	FindingType         string
	Title               string
	Severity            string
	ConfidenceScore     float64
	PhishingURLDefanged string
	HostingIP           *string
	Registrar           *string
	CampaignID          *string
	SourceID            *string
	DedupKey            string
	ContentFingerprint  *string
	AssetIDs            []string
}

// CreateFinding validates and persists a finding, then publishes finding.created.phm.
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
	if in.PhishingURLDefanged == "" {
		return nil, newValidation("phishing_url_defanged is required")
	}
	if !defangedURL.MatchString(in.PhishingURLDefanged) {
		return nil, newValidation("phishing_url_defanged must be defanged (e.g. hXXps://...)")
	}

	f := &domain.Finding{
		TenantID: tenantID, FindingType: in.FindingType, Title: in.Title,
		Severity: in.Severity, Status: "new", ConfidenceScore: in.ConfidenceScore,
		PhishingURLDefanged: in.PhishingURLDefanged, HostingIP: in.HostingIP,
		Registrar: in.Registrar, CampaignID: in.CampaignID, SourceID: in.SourceID,
		DedupKey: in.DedupKey, ContentFingerprint: in.ContentFingerprint,
		AssetIDs: in.AssetIDs,
	}
	created, err := s.store.CreateFinding(ctx, f)
	if err != nil {
		return nil, err
	}

	s.publish(ctx, types.TopicFindingCreatedPHM, tenantID, types.FindingCreated{
		EventID: newEventID(), EventType: "finding.created", SourceModule: types.ModulePHM,
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

// Escalate marks a finding escalated and publishes finding.escalated.phm so the
// Alert Engine can evaluate it.
func (s *Service) Escalate(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.store.Escalate(ctx, tenantID, id); err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedPHM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModulePHM,
		TenantID: tenantID, FindingID: cur.ID, FindingType: cur.FindingType,
		Severity: types.Severity(cur.Severity), ConfidenceScore: cur.ConfidenceScore,
		AssetIDs: cur.AssetIDs, Title: cur.Title, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return s.store.GetFinding(ctx, tenantID, id)
}

// PromoteUrgency flags a finding's phishing infrastructure as confirmed active and
// urgency-promoted (PHM-BR-001, PHM-FR-014). It raises the severity to at least
// "high" and publishes finding.escalated.phm so the Alert Engine processes it
// immediately rather than via the standard finding queue.
func (s *Service) PromoteUrgency(ctx context.Context, tenantID, id, actorID string) (*domain.Finding, error) {
	cur, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	// Bump severity to at least high; never downgrade a more severe finding.
	newSeverity := cur.Severity
	if types.Severity(cur.Severity).Rank() < types.SeverityHigh.Rank() {
		newSeverity = string(types.SeverityHigh)
	}
	if err := s.store.PromoteUrgency(ctx, tenantID, id, newSeverity); err != nil {
		return nil, err
	}
	updated, err := s.store.GetFinding(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	s.publish(ctx, types.TopicFindingEscalatedPHM, tenantID, types.FindingEscalated{
		EventID: newEventID(), EventType: "finding.escalated", SourceModule: types.ModulePHM,
		TenantID: tenantID, FindingID: updated.ID, FindingType: updated.FindingType,
		Severity: types.Severity(updated.Severity), ConfidenceScore: updated.ConfidenceScore,
		AssetIDs: updated.AssetIDs, Title: updated.Title, EscalatedBy: actorID, EscalatedAt: time.Now(),
	})
	return updated, nil
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

// CreateCampaign registers a phishing campaign.
func (s *Service) CreateCampaign(ctx context.Context, tenantID, name string, description *string) (*domain.Campaign, error) {
	if name == "" {
		return nil, newValidation("name is required")
	}
	return s.store.CreateCampaign(ctx, &domain.Campaign{
		TenantID: tenantID, Name: name, Description: description,
	})
}

// ListCampaigns returns PHM campaigns.
func (s *Service) ListCampaigns(ctx context.Context, tenantID string) ([]domain.Campaign, error) {
	return s.store.ListCampaigns(ctx, tenantID)
}

// AddIndicatorInput carries fields for a new indicator.
type AddIndicatorInput struct {
	IndicatorType string
	Value         string
	TLPMarking    string
	Confidence    *float64
}

// AddIndicator validates and persists an indicator extracted from a finding.
func (s *Service) AddIndicator(ctx context.Context, tenantID, findingID string, in AddIndicatorInput) (*domain.Indicator, error) {
	if !allowedIndicatorTypes[in.IndicatorType] {
		return nil, newValidation("invalid indicator_type %q", in.IndicatorType)
	}
	if in.Value == "" {
		return nil, newValidation("value is required")
	}
	tlp := in.TLPMarking
	if tlp == "" {
		tlp = string(types.TLPAmber)
	}
	if !types.TLP(tlp).Valid() {
		return nil, newValidation("invalid tlp_marking %q", in.TLPMarking)
	}
	if in.Confidence != nil && (*in.Confidence < 0 || *in.Confidence > 1) {
		return nil, newValidation("confidence must be between 0 and 1")
	}
	return s.store.AddIndicator(ctx, &domain.Indicator{
		TenantID: tenantID, FindingID: findingID, IndicatorType: in.IndicatorType,
		Value: in.Value, TLPMarking: tlp, Confidence: in.Confidence,
	})
}

// ListIndicators returns indicators for a finding.
func (s *Service) ListIndicators(ctx context.Context, tenantID, findingID string) ([]domain.Indicator, error) {
	return s.store.ListIndicators(ctx, tenantID, findingID)
}

// AddCertificateInput carries fields for a new certificate capture.
type AddCertificateInput struct {
	SerialNumber      string
	Issuer            *string
	Subject           *string
	SANEntries        []string
	NotBefore         *time.Time
	NotAfter          *time.Time
	FingerprintSHA256 *string
	RawCertRef        *string
}

// AddCertificate appends an immutable certificate capture to a finding (PHM-BR-006).
func (s *Service) AddCertificate(ctx context.Context, tenantID, findingID string, in AddCertificateInput) (*domain.SSLCertificate, error) {
	if in.SerialNumber == "" {
		return nil, newValidation("serial_number is required")
	}
	fid := findingID
	return s.store.AddCertificate(ctx, &domain.SSLCertificate{
		TenantID: tenantID, FindingID: &fid, SerialNumber: in.SerialNumber,
		Issuer: in.Issuer, Subject: in.Subject, SANEntries: in.SANEntries,
		NotBefore: in.NotBefore, NotAfter: in.NotAfter,
		FingerprintSHA256: in.FingerprintSHA256, RawCertRef: in.RawCertRef,
	})
}

// ListCertificates returns certificate captures for a finding.
func (s *Service) ListCertificates(ctx context.Context, tenantID, findingID string) ([]domain.SSLCertificate, error) {
	return s.store.ListCertificates(ctx, tenantID, findingID)
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

// ListSources returns PHM collection sources.
func (s *Service) ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error) {
	return s.store.ListSources(ctx, tenantID)
}

// CreateSource registers a PHM collection source.
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
