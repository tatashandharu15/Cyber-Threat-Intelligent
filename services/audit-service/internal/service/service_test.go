package service

import (
	"context"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/audit"
	"github.com/siberindo/cti/services/audit-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	events map[string]*domain.AuditEvent
	seq    int
}

func newFakeStore() *fakeStore { return &fakeStore{events: map[string]*domain.AuditEvent{}} }

func (f *fakeStore) Insert(_ context.Context, e *domain.AuditEvent) (*domain.AuditEvent, error) {
	f.seq++
	e.ID = "audit-" + itoa(f.seq)
	stored := *e
	f.events[e.ID] = &stored
	return e, nil
}
func (f *fakeStore) Get(_ context.Context, _, id string) (*domain.AuditEvent, error) {
	if e, ok := f.events[id]; ok {
		return e, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) List(_ context.Context, _ string, _ domain.AuditFilter) ([]domain.AuditEvent, error) {
	out := []domain.AuditEvent{}
	for _, e := range f.events {
		out = append(out, *e)
	}
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func newSvc() (*Service, *fakeStore) {
	st := newFakeStore()
	signer := audit.NewSigner("test-key")
	return New(st, signer, nil), st
}

func validInput() RecordInput {
	return RecordInput{
		ActorID: "actor-1", ActorType: "user", EventType: "finding.suppressed",
		ResourceType: "finding", Action: "suppress", Outcome: "success",
	}
}

func TestRecordPersistsAndSignatureVerifies(t *testing.T) {
	svc, st := newSvc()
	e, err := svc.Record(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e.ID == "" || e.HMACSignature == "" {
		t.Fatalf("expected a persisted, signed event, got %+v", e)
	}
	if _, ok := st.events[e.ID]; !ok {
		t.Fatalf("event %s was not persisted to the store", e.ID)
	}

	ok, err := svc.Verify(context.Background(), "tenant-1", e.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected stored HMAC to verify true for an untampered event")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	svc, st := newSvc()
	e, err := svc.Record(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	// Tamper with a signed field directly in the store, leaving the HMAC intact.
	st.events[e.ID].Outcome = "failure"

	ok, err := svc.Verify(context.Background(), "tenant-1", e.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatalf("expected verify to return false after a field was mutated")
	}
}

func TestRecordValidation(t *testing.T) {
	svc, _ := newSvc()
	cases := []func(*RecordInput){
		func(in *RecordInput) { in.EventType = "" },
		func(in *RecordInput) { in.ResourceType = "" },
		func(in *RecordInput) { in.Action = "" },
		func(in *RecordInput) { in.ActorID = "" },
		func(in *RecordInput) { in.ActorType = "alien" },
		func(in *RecordInput) { in.Outcome = "maybe" },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.Record(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestRecordDefaultsActorTypeAndOutcome(t *testing.T) {
	svc, _ := newSvc()
	in := validInput()
	in.ActorType = ""
	in.Outcome = ""
	e, err := svc.Record(context.Background(), "tenant-1", in)
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if e.ActorType != "user" || e.Outcome != "success" {
		t.Fatalf("expected defaults actor_type=user outcome=success, got actor_type=%s outcome=%s", e.ActorType, e.Outcome)
	}
}

func TestRecordFromEventPersists(t *testing.T) {
	svc, st := newSvc()
	ev := types.AuditEventWritten{
		EventID: "e1", EventType: "user.login", TenantID: "tenant-1", ActorID: "actor-1",
		ActorType: "user", ResourceType: "session", ResourceID: "sess-1",
		Action: "create", Outcome: "success",
	}
	e, err := svc.RecordFromEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("record from event: %v", err)
	}
	if _, ok := st.events[e.ID]; !ok {
		t.Fatalf("event %s was not persisted", e.ID)
	}
	if e.HMACSignature == "" {
		t.Fatalf("expected a computed HMAC for an event with no supplied signature")
	}
	// With no supplied HMAC the service computes one, so it must verify true.
	ok, err := svc.Verify(context.Background(), "tenant-1", e.ID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatalf("expected computed signature to verify true")
	}
}
