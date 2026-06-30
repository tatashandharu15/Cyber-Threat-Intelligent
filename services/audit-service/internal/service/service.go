// Package service implements the Audit Log service's business logic: recording
// tamper-evident audit events (signed with an HMAC), verifying that a stored event
// has not been altered, and ingesting audit.event.written events from Kafka.
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/audit"
	"github.com/siberindo/cti/services/audit-service/internal/domain"
	"github.com/siberindo/cti/services/audit-service/internal/store"
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

// ErrNotFound is re-exported from the store for the API layer.
var ErrNotFound = store.ErrNotFound

var allowedActorTypes = map[string]bool{
	"user": true, "service_account": true, "system": true,
}

var allowedOutcomes = map[string]bool{
	"success": true, "failure": true, "partial": true,
}

// Store is the persistence contract (an interface so the service is unit-testable).
type Store interface {
	Insert(ctx context.Context, e *domain.AuditEvent) (*domain.AuditEvent, error)
	Get(ctx context.Context, tenantID, id string) (*domain.AuditEvent, error)
	List(ctx context.Context, tenantID string, fil domain.AuditFilter) ([]domain.AuditEvent, error)
}

// Service holds the Audit Log business logic dependencies.
type Service struct {
	store  Store
	signer *audit.Signer
	log    *slog.Logger
}

// New constructs a Service.
func New(s Store, signer *audit.Signer, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: s, signer: signer, log: log}
}

// RecordInput carries the fields for a new audit event written via the API.
type RecordInput struct {
	ActorID      string
	ActorType    string
	EventType    string
	ResourceType string
	ResourceID   *string
	Action       string
	Outcome      string
	IP           *string
	UserAgent    *string
	RequestID    *string
	Payload      []byte
}

// Record validates, signs, and persists an audit event, returning the stored row.
// The HMAC is computed over the canonical security-relevant fields with the exact
// created_at that is also persisted, so the signature can be re-verified later.
func (s *Service) Record(ctx context.Context, tenantID string, in RecordInput) (*domain.AuditEvent, error) {
	if tenantID == "" {
		return nil, newValidation("tenant_id is required")
	}
	if in.ActorID == "" {
		return nil, newValidation("actor_id is required")
	}
	if in.EventType == "" {
		return nil, newValidation("event_type is required")
	}
	if in.ResourceType == "" {
		return nil, newValidation("resource_type is required")
	}
	if in.Action == "" {
		return nil, newValidation("action is required")
	}

	actorType := in.ActorType
	if actorType == "" {
		actorType = "user"
	}
	if !allowedActorTypes[actorType] {
		return nil, newValidation("invalid actor_type %q", actorType)
	}
	outcome := in.Outcome
	if outcome == "" {
		outcome = "success"
	}
	if !allowedOutcomes[outcome] {
		return nil, newValidation("invalid outcome %q", outcome)
	}

	createdAt := time.Now()
	resourceID := ""
	if in.ResourceID != nil {
		resourceID = *in.ResourceID
	}
	ev := audit.Event{
		TenantID:     tenantID,
		ActorID:      in.ActorID,
		ActorType:    actorType,
		EventType:    in.EventType,
		ResourceType: in.ResourceType,
		ResourceID:   resourceID,
		Action:       in.Action,
		Outcome:      outcome,
		CreatedAt:    createdAt,
	}
	sig := s.signer.Sign(ev)

	return s.store.Insert(ctx, &domain.AuditEvent{
		TenantID:      tenantID,
		ActorID:       in.ActorID,
		ActorType:     actorType,
		EventType:     in.EventType,
		ResourceType:  in.ResourceType,
		ResourceID:    in.ResourceID,
		Action:        in.Action,
		Outcome:       outcome,
		IPAddress:     in.IP,
		UserAgent:     in.UserAgent,
		RequestID:     in.RequestID,
		EventPayload:  in.Payload,
		HMACSignature: sig,
		CreatedAt:     createdAt,
	})
}

// List returns audit events for a tenant.
func (s *Service) List(ctx context.Context, tenantID string, fil domain.AuditFilter) ([]domain.AuditEvent, error) {
	return s.store.List(ctx, tenantID, fil)
}

// Get returns one audit event.
func (s *Service) Get(ctx context.Context, tenantID, id string) (*domain.AuditEvent, error) {
	return s.store.Get(ctx, tenantID, id)
}

// Verify loads the stored event, rebuilds the canonical signed form from its stored
// fields, and reports whether the stored HMAC still matches. A false result means
// the record (or its signature) has been tampered with.
func (s *Service) Verify(ctx context.Context, tenantID, id string) (bool, error) {
	e, err := s.store.Get(ctx, tenantID, id)
	if err != nil {
		return false, err
	}
	return s.signer.Verify(eventFor(e), e.HMACSignature), nil
}

// RecordFromEvent persists an audit.event.written received over Kafka. If the event
// carries an HMAC it is verified (an invalid signature is logged but the record is
// still stored, since dropping it would lose the audit trail); otherwise a fresh
// signature is computed. The emitter-supplied created_at is preserved.
func (s *Service) RecordFromEvent(ctx context.Context, ev types.AuditEventWritten) (*domain.AuditEvent, error) {
	actorType := ev.ActorType
	if actorType == "" {
		actorType = "user"
	}
	outcome := ev.Outcome
	if outcome == "" {
		outcome = "success"
	}
	signed := audit.Event{
		TenantID:     ev.TenantID,
		ActorID:      ev.ActorID,
		ActorType:    actorType,
		EventType:    ev.EventType,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Action:       ev.Action,
		Outcome:      outcome,
		CreatedAt:    ev.CreatedAt,
	}
	sig := ev.HMAC
	if sig != "" {
		if !s.signer.Verify(signed, sig) {
			s.log.WarnContext(ctx, "audit.event.written has an invalid HMAC; persisting anyway",
				slog.String("tenant_id", ev.TenantID), slog.String("event_id", ev.EventID))
		}
	} else {
		sig = s.signer.Sign(signed)
	}

	return s.store.Insert(ctx, &domain.AuditEvent{
		TenantID:      ev.TenantID,
		ActorID:       ev.ActorID,
		ActorType:     actorType,
		EventType:     ev.EventType,
		ResourceType:  ev.ResourceType,
		ResourceID:    nullableID(ev.ResourceID),
		Action:        ev.Action,
		Outcome:       outcome,
		RequestID:     nullableID(ev.RequestID),
		HMACSignature: sig,
		CreatedAt:     ev.CreatedAt,
	})
}

// eventFor rebuilds the canonical audit.Event from a stored record so its signature
// can be re-verified (ResourceID is "" when the column is NULL).
func eventFor(e *domain.AuditEvent) audit.Event {
	resourceID := ""
	if e.ResourceID != nil {
		resourceID = *e.ResourceID
	}
	return audit.Event{
		TenantID:     e.TenantID,
		ActorID:      e.ActorID,
		ActorType:    e.ActorType,
		EventType:    e.EventType,
		ResourceType: e.ResourceType,
		ResourceID:   resourceID,
		Action:       e.Action,
		Outcome:      e.Outcome,
		CreatedAt:    e.CreatedAt,
	}
}

// nullableID returns a pointer to s, or nil when s is empty, so empty cross-context
// ids are stored as SQL NULL in the uuid columns.
func nullableID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
