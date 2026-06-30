package service

import (
	"context"
	"testing"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/takedown-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	takedowns map[string]*domain.Takedown
	events    map[string][]domain.TakedownEvent
	seq       int
}

func newFakeStore() *fakeStore {
	return &fakeStore{takedowns: map[string]*domain.Takedown{}, events: map[string][]domain.TakedownEvent{}}
}

func (f *fakeStore) CreateTakedown(_ context.Context, t *domain.Takedown) (*domain.Takedown, error) {
	f.seq++
	t.ID = "takedown-" + itoa(f.seq)
	t.Status = "draft"
	t.CreatedAt = time.Now()
	t.UpdatedAt = t.CreatedAt
	f.takedowns[t.ID] = t
	f.events[t.ID] = append(f.events[t.ID], domain.TakedownEvent{
		TakedownID: t.ID, EventType: "created", CreatedAt: t.CreatedAt,
	})
	return t, nil
}

func (f *fakeStore) GetTakedown(_ context.Context, _, id string) (*domain.Takedown, error) {
	if t, ok := f.takedowns[id]; ok {
		cp := *t
		return &cp, nil
	}
	return nil, ErrNotFound
}

func (f *fakeStore) ListTakedowns(_ context.Context, _ string, _ domain.TakedownFilter) ([]domain.Takedown, error) {
	out := []domain.Takedown{}
	for _, t := range f.takedowns {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeStore) Transition(_ context.Context, _, id, newStatus, operatorResponse, _ string) error {
	t, ok := f.takedowns[id]
	if !ok {
		return ErrNotFound
	}
	old := t.Status
	now := time.Now()
	t.Status = newStatus
	switch newStatus {
	case "submitted":
		t.SubmittedAt = &now
	case "acknowledged":
		t.AcknowledgedAt = &now
	case "actioned":
		t.ActionedAt = &now
	case "rejected":
		t.RejectedAt = &now
	case "closed":
		t.ClosedAt = &now
	}
	if operatorResponse != "" {
		t.OperatorResponse = &operatorResponse
	}
	detail := old + " -> " + newStatus
	f.events[id] = append(f.events[id], domain.TakedownEvent{
		TakedownID: id, EventType: "status_changed", Detail: &detail, CreatedAt: now,
	})
	return nil
}

func (f *fakeStore) ListEvents(_ context.Context, _, takedownID string) ([]domain.TakedownEvent, error) {
	return f.events[takedownID], nil
}

// fakePublisher records published events.
type fakePublisher struct {
	events []published
}
type published struct {
	topic string
	key   string
	value any
}

func (f *fakePublisher) Publish(_ context.Context, topic, key string, value any) error {
	f.events = append(f.events, published{topic, key, value})
	return nil
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

func newSvc() (*Service, *fakeStore, *fakePublisher) {
	st := newFakeStore()
	pub := &fakePublisher{}
	return New(st, pub, nil), st, pub
}

func validInput() CreateTakedownInput {
	return CreateTakedownInput{
		SourceModule: "brm", SourceFindingID: "finding-1",
		SubmissionTarget: "registrar@example.com", SubmissionTargetType: "registrar",
		EvidencePackageRef: "s3://evidence/pkg-1",
	}
}

func TestCreateTakedownDraft(t *testing.T) {
	svc, _, pub := newSvc()
	td, err := svc.CreateTakedown(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if td.Status != "draft" {
		t.Fatalf("expected status draft, got %s", td.Status)
	}
	if len(pub.events) != 0 {
		t.Fatalf("expected no events on create (still draft), got %+v", pub.events)
	}
}

func TestCreateTakedownValidation(t *testing.T) {
	svc, _, _ := newSvc()
	cases := []func(*CreateTakedownInput){
		func(in *CreateTakedownInput) { in.SourceModule = "dlm" },
		func(in *CreateTakedownInput) { in.SourceFindingID = "" },
		func(in *CreateTakedownInput) { in.SubmissionTarget = "" },
		func(in *CreateTakedownInput) { in.SubmissionTargetType = "bogus" },
		func(in *CreateTakedownInput) { in.EvidencePackageRef = "" },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.CreateTakedown(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestSubmitMovesDraftToSubmittedAndPublishes(t *testing.T) {
	svc, _, pub := newSvc()
	td, _ := svc.CreateTakedown(context.Background(), "tenant-1", validInput())

	out, err := svc.Submit(context.Background(), "tenant-1", td.ID, "analyst-1")
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if out.Status != "submitted" {
		t.Fatalf("expected status submitted, got %s", out.Status)
	}
	if out.SubmittedAt == nil {
		t.Fatalf("expected submitted_at to be set")
	}
	if len(pub.events) != 2 {
		t.Fatalf("expected 2 events on submit, got %d: %+v", len(pub.events), pub.events)
	}
	if pub.events[0].topic != types.TopicTakedownRequested {
		t.Fatalf("expected first event %s, got %s", types.TopicTakedownRequested, pub.events[0].topic)
	}
	req, ok := pub.events[0].value.(types.TakedownRequested)
	if !ok || req.TakedownID != td.ID || req.RequestedBy != "analyst-1" {
		t.Fatalf("unexpected takedown.requested payload: %+v", pub.events[0].value)
	}
	if pub.events[1].topic != types.TopicTakedownStatusUpdate {
		t.Fatalf("expected second event %s, got %s", types.TopicTakedownStatusUpdate, pub.events[1].topic)
	}
	upd, ok := pub.events[1].value.(types.TakedownStatusUpdate)
	if !ok || upd.TakedownID != td.ID || upd.Status != "submitted" {
		t.Fatalf("unexpected takedown.status.updated payload: %+v", pub.events[1].value)
	}
}

func TestSubmitRejectsNonDraft(t *testing.T) {
	svc, _, _ := newSvc()
	td, _ := svc.CreateTakedown(context.Background(), "tenant-1", validInput())
	if _, err := svc.Submit(context.Background(), "tenant-1", td.ID, "analyst-1"); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	// Already submitted: a second submit must be rejected.
	if _, err := svc.Submit(context.Background(), "tenant-1", td.ID, "analyst-1"); !IsValidation(err) {
		t.Fatalf("expected validation error submitting a non-draft, got %v", err)
	}
}

func TestUpdateStatusValidTransitionPublishes(t *testing.T) {
	svc, _, pub := newSvc()
	td, _ := svc.CreateTakedown(context.Background(), "tenant-1", validInput())
	if _, err := svc.Submit(context.Background(), "tenant-1", td.ID, "analyst-1"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	pub.events = nil // discard the submit events

	out, err := svc.UpdateStatus(context.Background(), "tenant-1", td.ID, "acknowledged", "received", "operator-1")
	if err != nil {
		t.Fatalf("update status: %v", err)
	}
	if out.Status != "acknowledged" {
		t.Fatalf("expected acknowledged, got %s", out.Status)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicTakedownStatusUpdate {
		t.Fatalf("expected one takedown.status.updated event, got %+v", pub.events)
	}
	upd := pub.events[0].value.(types.TakedownStatusUpdate)
	if upd.Status != "acknowledged" || upd.OperatorResponse != "received" {
		t.Fatalf("unexpected status update payload: %+v", upd)
	}
}

func TestUpdateStatusInvalidTransition(t *testing.T) {
	svc, _, _ := newSvc()
	td, _ := svc.CreateTakedown(context.Background(), "tenant-1", validInput())

	// draft -> actioned is not allowed.
	if _, err := svc.UpdateStatus(context.Background(), "tenant-1", td.ID, "actioned", "", "operator-1"); !IsValidation(err) {
		t.Fatalf("expected validation error for draft->actioned, got %v", err)
	}

	// Drive to closed, then attempt closed -> submitted.
	mustTransition(t, svc, td.ID, "submitted", true)
	mustTransition(t, svc, td.ID, "rejected", false)
	mustTransition(t, svc, td.ID, "closed", false)
	if _, err := svc.UpdateStatus(context.Background(), "tenant-1", td.ID, "submitted", "", "operator-1"); !IsValidation(err) {
		t.Fatalf("expected validation error for closed->submitted, got %v", err)
	}
}

func mustTransition(t *testing.T, svc *Service, id, to string, viaSubmit bool) {
	t.Helper()
	var err error
	if viaSubmit {
		_, err = svc.Submit(context.Background(), "tenant-1", id, "analyst-1")
	} else {
		_, err = svc.UpdateStatus(context.Background(), "tenant-1", id, to, "", "operator-1")
	}
	if err != nil {
		t.Fatalf("transition to %s: %v", to, err)
	}
}
