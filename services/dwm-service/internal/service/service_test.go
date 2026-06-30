package service

import (
	"context"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/dwm-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	findings map[string]*domain.Finding
	actors   map[string]*domain.ThreatActorProfile
	links    []link
	seq      int
}

type link struct {
	findingID, actorID, confirmedBy, justification string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		findings: map[string]*domain.Finding{},
		actors:   map[string]*domain.ThreatActorProfile{},
	}
}

func (f *fakeStore) CreateFinding(_ context.Context, fn *domain.Finding) (*domain.Finding, error) {
	f.seq++
	fn.ID = "finding-" + itoa(f.seq)
	f.findings[fn.ID] = fn
	return fn, nil
}
func (f *fakeStore) GetFinding(_ context.Context, _, id string) (*domain.Finding, error) {
	if fn, ok := f.findings[id]; ok {
		return fn, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) ListFindings(_ context.Context, _ string, _ domain.FindingFilter) ([]domain.Finding, error) {
	out := []domain.Finding{}
	for _, fn := range f.findings {
		out = append(out, *fn)
	}
	return out, nil
}
func (f *fakeStore) UpdateStatus(_ context.Context, _, id, status string) error {
	if fn, ok := f.findings[id]; ok {
		fn.Status = status
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) Escalate(_ context.Context, _, id string) error {
	if fn, ok := f.findings[id]; ok {
		fn.Status = "escalated"
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) Suppress(_ context.Context, _, id, reason string) error {
	if fn, ok := f.findings[id]; ok {
		fn.Status = "suppressed"
		fn.SuppressionReason = &reason
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) OverrideSeverity(_ context.Context, _, id, severity, reason string) error {
	if fn, ok := f.findings[id]; ok {
		prior := fn.Severity
		fn.PriorSeverity = &prior
		fn.Severity = severity
		fn.SeverityOverrideReason = &reason
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) AddEvidence(_ context.Context, e *domain.Evidence) (*domain.Evidence, error) {
	e.ID = "evidence-1"
	return e, nil
}
func (f *fakeStore) ListEvidence(_ context.Context, _, _ string) ([]domain.Evidence, error) {
	return nil, nil
}
func (f *fakeStore) CreateThreatActor(_ context.Context, a *domain.ThreatActorProfile) (*domain.ThreatActorProfile, error) {
	f.seq++
	a.ID = "actor-" + itoa(f.seq)
	a.Status = "active"
	f.actors[a.ID] = a
	return a, nil
}
func (f *fakeStore) ListThreatActors(_ context.Context, _ string) ([]domain.ThreatActorProfile, error) {
	out := []domain.ThreatActorProfile{}
	for _, a := range f.actors {
		out = append(out, *a)
	}
	return out, nil
}
func (f *fakeStore) LinkThreatActor(_ context.Context, _, findingID, actorID, confirmedBy, justification string) error {
	if _, ok := f.findings[findingID]; !ok {
		return ErrNotFound
	}
	if _, ok := f.actors[actorID]; !ok {
		return ErrNotFound
	}
	f.links = append(f.links, link{findingID, actorID, confirmedBy, justification})
	return nil
}
func (f *fakeStore) AddEnrichment(_ context.Context, e *domain.Enrichment) (*domain.Enrichment, error) {
	if _, ok := f.findings[e.FindingID]; !ok {
		return nil, ErrNotFound
	}
	e.ID = "enrichment-1"
	return e, nil
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

func validInput() CreateFindingInput {
	return CreateFindingInput{
		FindingType: "sale_listing", Title: "Credential dump for sale on dark forum",
		Severity: "high", ConfidenceScore: 0.9, DedupKey: "abc123",
	}
}

func TestCreateFindingPublishes(t *testing.T) {
	svc, _, pub := newSvc()
	f, err := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Status != "new" {
		t.Fatalf("expected status new, got %s", f.Status)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingCreatedDWM {
		t.Fatalf("expected one finding.created.dwm event, got %+v", pub.events)
	}
	ev, ok := pub.events[0].value.(types.FindingCreated)
	if !ok || ev.FindingID != f.ID || ev.SourceModule != types.ModuleDWM {
		t.Fatalf("unexpected event payload: %+v", pub.events[0].value)
	}
}

func TestNetworkAccessSaleSeverityElevated(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.FindingType = "network_access_sale"
	in.Severity = "low"
	f, err := svc.CreateFinding(context.Background(), "tenant-1", in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Severity != "high" {
		t.Fatalf("expected network_access_sale severity bumped to high, got %s", f.Severity)
	}
}

func TestNetworkAccessSaleSeverityNotLowered(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.FindingType = "network_access_sale"
	in.Severity = "critical"
	f, err := svc.CreateFinding(context.Background(), "tenant-1", in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Severity != "critical" {
		t.Fatalf("expected critical preserved, got %s", f.Severity)
	}
}

func TestCreateFindingRejectsLiveURL(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	live := "https://evil.example.com/market"
	in.ContentURLDefanged = &live
	_, err := svc.CreateFinding(context.Background(), "tenant-1", in)
	if !IsValidation(err) {
		t.Fatalf("expected validation error for live URL, got %v", err)
	}
}

func TestCreateFindingAcceptsDefangedURL(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	defanged := "hXXps://evil.example.com/market"
	in.ContentURLDefanged = &defanged
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", in); err != nil {
		t.Fatalf("expected defanged URL to be accepted, got %v", err)
	}
}

func TestCreateFindingValidation(t *testing.T) {
	svc, _, _ := newSvc()
	cases := []func(*CreateFindingInput){
		func(in *CreateFindingInput) { in.FindingType = "bogus" },
		func(in *CreateFindingInput) { in.Severity = "extreme" },
		func(in *CreateFindingInput) { in.ConfidenceScore = 1.5 },
		func(in *CreateFindingInput) { in.DedupKey = "" },
		func(in *CreateFindingInput) { in.Title = "" },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.CreateFinding(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestEscalatePublishes(t *testing.T) {
	svc, _, pub := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	pub.events = nil // discard the create event

	out, err := svc.Escalate(context.Background(), "tenant-1", f.ID, "analyst-1")
	if err != nil {
		t.Fatalf("escalate: %v", err)
	}
	if out.Status != "escalated" {
		t.Fatalf("expected escalated, got %s", out.Status)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingEscalatedDWM {
		t.Fatalf("expected finding.escalated.dwm event, got %+v", pub.events)
	}
	ev := pub.events[0].value.(types.FindingEscalated)
	if ev.FindingID != f.ID || ev.EscalatedBy != "analyst-1" || ev.SourceModule != types.ModuleDWM {
		t.Fatalf("unexpected escalation payload: %+v", ev)
	}
}

func TestOverrideSeverityPreservesPrior(t *testing.T) {
	svc, st, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput()) // severity high

	if err := svc.OverrideSeverity(context.Background(), "tenant-1", f.ID, "critical", "confirmed active breach"); err != nil {
		t.Fatalf("override: %v", err)
	}
	got := st.findings[f.ID]
	if got.Severity != "critical" || got.PriorSeverity == nil || *got.PriorSeverity != "high" {
		t.Fatalf("expected prior=high severity=critical, got severity=%s prior=%v", got.Severity, got.PriorSeverity)
	}

	if err := svc.OverrideSeverity(context.Background(), "tenant-1", f.ID, "low", ""); !IsValidation(err) {
		t.Fatalf("expected validation error without justification, got %v", err)
	}
}

func TestSuppressRequiresJustification(t *testing.T) {
	svc, _, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	if err := svc.Suppress(context.Background(), "tenant-1", f.ID, ""); !IsValidation(err) {
		t.Fatalf("expected validation error, got %v", err)
	}
	if err := svc.Suppress(context.Background(), "tenant-1", f.ID, "known test data"); err != nil {
		t.Fatalf("suppress with justification: %v", err)
	}
}

func TestLinkThreatActorRequiresJustification(t *testing.T) {
	svc, _, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	a, _ := svc.CreateThreatActor(context.Background(), "tenant-1", "Spider Group", nil, nil)

	if err := svc.LinkThreatActor(context.Background(), "tenant-1", f.ID, a.ID, "analyst-1", ""); !IsValidation(err) {
		t.Fatalf("expected validation error without justification, got %v", err)
	}
	if err := svc.LinkThreatActor(context.Background(), "tenant-1", f.ID, a.ID, "analyst-1", "matching TTP and infrastructure"); err != nil {
		t.Fatalf("link with justification: %v", err)
	}
}

func TestCreateThreatActorNeverAutoConfirmsIdentity(t *testing.T) {
	svc, _, _ := newSvc()
	a, err := svc.CreateThreatActor(context.Background(), "tenant-1", "Spider Group", nil, nil)
	if err != nil {
		t.Fatalf("create threat actor: %v", err)
	}
	if a.IdentityConfirmed {
		t.Fatalf("expected identity_confirmed to default false (DWM-BR-002)")
	}
}
