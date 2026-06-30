package service

import (
	"context"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/phm-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	findings map[string]*domain.Finding
	seq      int
}

func newFakeStore() *fakeStore { return &fakeStore{findings: map[string]*domain.Finding{}} }

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
func (f *fakeStore) PromoteUrgency(_ context.Context, _, id, newSeverity string) error {
	if fn, ok := f.findings[id]; ok {
		fn.UrgencyPromoted = true
		fn.Severity = newSeverity
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) CreateCampaign(_ context.Context, c *domain.Campaign) (*domain.Campaign, error) {
	c.ID = "campaign-1"
	c.Status = "active"
	return c, nil
}
func (f *fakeStore) ListCampaigns(_ context.Context, _ string) ([]domain.Campaign, error) {
	return nil, nil
}
func (f *fakeStore) AddIndicator(_ context.Context, i *domain.Indicator) (*domain.Indicator, error) {
	i.ID = "indicator-1"
	return i, nil
}
func (f *fakeStore) ListIndicators(_ context.Context, _, _ string) ([]domain.Indicator, error) {
	return nil, nil
}
func (f *fakeStore) AddCertificate(_ context.Context, c *domain.SSLCertificate) (*domain.SSLCertificate, error) {
	c.ID = "cert-1"
	return c, nil
}
func (f *fakeStore) ListCertificates(_ context.Context, _, _ string) ([]domain.SSLCertificate, error) {
	return nil, nil
}
func (f *fakeStore) AddEvidence(_ context.Context, e *domain.Evidence) (*domain.Evidence, error) {
	e.ID = "evidence-1"
	return e, nil
}
func (f *fakeStore) ListEvidence(_ context.Context, _, _ string) ([]domain.Evidence, error) {
	return nil, nil
}
func (f *fakeStore) ListSources(_ context.Context, _ string) ([]domain.CollectionSource, error) {
	return nil, nil
}
func (f *fakeStore) CreateSource(_ context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error) {
	c.ID = "source-1"
	return c, nil
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
		FindingType: "credential_harvesting_page", Title: "Fake bank login page",
		Severity: "high", ConfidenceScore: 0.9, DedupKey: "abc123",
		PhishingURLDefanged: "hXXps://evil.example.com/login",
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
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingCreatedPHM {
		t.Fatalf("expected one finding.created.phm event, got %+v", pub.events)
	}
	ev, ok := pub.events[0].value.(types.FindingCreated)
	if !ok || ev.FindingID != f.ID || ev.SourceModule != types.ModulePHM {
		t.Fatalf("unexpected event payload: %+v", pub.events[0].value)
	}
}

func TestCreateFindingRejectsLiveURL(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.PhishingURLDefanged = "https://evil.example.com/login"
	_, err := svc.CreateFinding(context.Background(), "tenant-1", in)
	if !IsValidation(err) {
		t.Fatalf("expected validation error for live URL, got %v", err)
	}
}

func TestCreateFindingRejectsEmptyURL(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.PhishingURLDefanged = ""
	_, err := svc.CreateFinding(context.Background(), "tenant-1", in)
	if !IsValidation(err) {
		t.Fatalf("expected validation error for empty phishing_url_defanged, got %v", err)
	}
}

func TestCreateFindingAcceptsDefangedURL(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.PhishingURLDefanged = "hXXp://evil.example.com/login"
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
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingEscalatedPHM {
		t.Fatalf("expected finding.escalated.phm event, got %+v", pub.events)
	}
	ev := pub.events[0].value.(types.FindingEscalated)
	if ev.FindingID != f.ID || ev.EscalatedBy != "analyst-1" {
		t.Fatalf("unexpected escalation payload: %+v", ev)
	}
}

func TestPromoteUrgencyRaisesSeverity(t *testing.T) {
	svc, st, pub := newSvc()
	in := validInput()
	in.Severity = "low" // start below high
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", in)
	pub.events = nil

	out, err := svc.PromoteUrgency(context.Background(), "tenant-1", f.ID, "analyst-1")
	if err != nil {
		t.Fatalf("promote urgency: %v", err)
	}
	if !out.UrgencyPromoted {
		t.Fatalf("expected urgency_promoted=true, got %+v", out)
	}
	got := st.findings[f.ID]
	if !got.UrgencyPromoted {
		t.Fatalf("expected stored urgency_promoted=true")
	}
	if types.Severity(got.Severity).Rank() < types.SeverityHigh.Rank() {
		t.Fatalf("expected severity raised to at least high, got %s", got.Severity)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingEscalatedPHM {
		t.Fatalf("expected finding.escalated.phm event on urgency promotion, got %+v", pub.events)
	}
}

func TestPromoteUrgencyDoesNotDowngrade(t *testing.T) {
	svc, st, _ := newSvc()
	in := validInput()
	in.Severity = "critical"
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", in)

	if _, err := svc.PromoteUrgency(context.Background(), "tenant-1", f.ID, "analyst-1"); err != nil {
		t.Fatalf("promote urgency: %v", err)
	}
	if got := st.findings[f.ID]; got.Severity != "critical" {
		t.Fatalf("expected critical severity preserved, got %s", got.Severity)
	}
}

func TestAddIndicatorRejectsInvalidTLP(t *testing.T) {
	svc, _, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	_, err := svc.AddIndicator(context.Background(), "tenant-1", f.ID, AddIndicatorInput{
		IndicatorType: "domain", Value: "evil.example.com", TLPMarking: "TLP:PURPLE",
	})
	if !IsValidation(err) {
		t.Fatalf("expected validation error for invalid TLP, got %v", err)
	}
}

func TestAddIndicatorDefaultsTLP(t *testing.T) {
	svc, _, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	ind, err := svc.AddIndicator(context.Background(), "tenant-1", f.ID, AddIndicatorInput{
		IndicatorType: "domain", Value: "evil.example.com",
	})
	if err != nil {
		t.Fatalf("add indicator: %v", err)
	}
	if ind.TLPMarking != string(types.TLPAmber) {
		t.Fatalf("expected default TLP:AMBER, got %s", ind.TLPMarking)
	}
}

func TestAddIndicatorRejectsInvalidType(t *testing.T) {
	svc, _, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput())
	_, err := svc.AddIndicator(context.Background(), "tenant-1", f.ID, AddIndicatorInput{
		IndicatorType: "bogus", Value: "x",
	})
	if !IsValidation(err) {
		t.Fatalf("expected validation error for invalid indicator_type, got %v", err)
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
