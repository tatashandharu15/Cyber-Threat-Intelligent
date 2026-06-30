// Package service implements the Indicator service's business logic: indicator
// registration with deduplicating upsert, validation of CTI-specific rules
// (indicator type, TLP marking, confidence), and the publication of
// indicator.created events on first creation.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/indicator-service/internal/domain"
	"github.com/siberindo/cti/services/indicator-service/internal/events"
	"github.com/siberindo/cti/services/indicator-service/internal/store"
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

var allowedIndicatorTypes = map[string]bool{
	"domain": true, "ip_address": true, "url_defanged": true, "hash_md5": true,
	"hash_sha1": true, "hash_sha256": true, "email_address": true, "asn": true,
	"certificate_fingerprint": true, "mutex": true, "registry_key": true, "file_path": true,
}

// Store is the persistence contract.
type Store interface {
	UpsertIndicator(ctx context.Context, ind *domain.Indicator) (*domain.Indicator, bool, error)
	GetIndicator(ctx context.Context, tenantID, id string) (*domain.Indicator, error)
	ListIndicators(ctx context.Context, tenantID string, fil domain.IndicatorFilter) ([]domain.Indicator, error)
	UpdateIndicator(ctx context.Context, tenantID, id string, upd store.IndicatorUpdate) (*domain.Indicator, error)
	DeleteIndicator(ctx context.Context, tenantID, id string) error
}

// Service holds the Indicator business logic dependencies.
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

// RegisterIndicatorInput carries the fields for registering an indicator.
type RegisterIndicatorInput struct {
	IndicatorType   string
	Value           string
	TLPMarking      string
	Confidence      *float64
	SourceModule    *string
	SourceFindingID *string
	Tags            []string
	ExpiresAt       *time.Time
}

// RegisterIndicator validates and upserts an indicator. When a NEW row is
// inserted (i.e. not a re-observation of an existing indicator), it publishes
// indicator.created. The stored indicator is always returned.
func (s *Service) RegisterIndicator(ctx context.Context, tenantID string, in RegisterIndicatorInput) (*domain.Indicator, error) {
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

	ind := &domain.Indicator{
		TenantID: tenantID, IndicatorType: in.IndicatorType, Value: in.Value,
		TLPMarking: tlp, Confidence: in.Confidence, SourceModule: in.SourceModule,
		SourceFindingID: in.SourceFindingID, Tags: in.Tags, ExpiresAt: in.ExpiresAt,
	}
	stored, inserted, err := s.store.UpsertIndicator(ctx, ind)
	if err != nil {
		return nil, err
	}

	if inserted {
		ev := types.IndicatorCreated{
			EventID: newEventID(), EventType: "indicator.created",
			TenantID: tenantID, IndicatorID: stored.ID, IndicatorType: stored.IndicatorType,
			Value: stored.Value, TLP: types.TLP(stored.TLPMarking), CreatedAt: stored.CreatedAt,
		}
		if stored.SourceModule != nil {
			ev.SourceModule = *stored.SourceModule
		}
		if stored.SourceFindingID != nil {
			ev.SourceFindingID = *stored.SourceFindingID
		}
		s.publish(ctx, types.TopicIndicatorCreated, tenantID, ev)
	}
	return stored, nil
}

// ListIndicators returns indicators for a tenant.
func (s *Service) ListIndicators(ctx context.Context, tenantID string, fil domain.IndicatorFilter) ([]domain.Indicator, error) {
	return s.store.ListIndicators(ctx, tenantID, fil)
}

// GetIndicator returns one indicator.
func (s *Service) GetIndicator(ctx context.Context, tenantID, id string) (*domain.Indicator, error) {
	return s.store.GetIndicator(ctx, tenantID, id)
}

// UpdateIndicatorInput carries the partially-updatable fields of an indicator.
type UpdateIndicatorInput struct {
	TLPMarking *string
	Confidence *float64
	Tags       *[]string
	ExpiresAt  *time.Time
}

// UpdateIndicator validates and applies a partial update to an indicator.
func (s *Service) UpdateIndicator(ctx context.Context, tenantID, id string, in UpdateIndicatorInput) (*domain.Indicator, error) {
	if in.TLPMarking != nil && !types.TLP(*in.TLPMarking).Valid() {
		return nil, newValidation("invalid tlp_marking %q", *in.TLPMarking)
	}
	if in.Confidence != nil && (*in.Confidence < 0 || *in.Confidence > 1) {
		return nil, newValidation("confidence must be between 0 and 1")
	}
	return s.store.UpdateIndicator(ctx, tenantID, id, store.IndicatorUpdate{
		TLPMarking: in.TLPMarking, Confidence: in.Confidence,
		Tags: in.Tags, ExpiresAt: in.ExpiresAt,
	})
}

// DeleteIndicator removes an indicator.
func (s *Service) DeleteIndicator(ctx context.Context, tenantID, id string) error {
	return s.store.DeleteIndicator(ctx, tenantID, id)
}

// publish emits an event best-effort: a Kafka failure is logged but does not fail
// the originating request, since the indicator is already durably stored.
func (s *Service) publish(ctx context.Context, topic, key string, value any) {
	if s.pub == nil {
		return
	}
	if err := s.pub.Publish(ctx, topic, key, value); err != nil {
		s.log.WarnContext(ctx, "event publish failed", slog.String("topic", topic), slog.String("error", err.Error()))
	}
}
