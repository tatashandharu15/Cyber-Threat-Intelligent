package service

import (
	"context"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/brm-service/internal/domain"
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
func (f *fakeStore) InitiateTakedown(_ context.Context, _, id string) error {
	if fn, ok := f.findings[id]; ok {
		fn.Status = "takedown_initiated"
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

func strptr(s string) *string { return &s }
func f64ptr(f float64) *float64 { return &f }

func validInput() CreateFindingInput {
	return CreateFindingInput{
		FindingType: "lookalike_domain", Title: "Lookalike domain s1berindo.io",
		Severity: "high", ConfidenceScore: 0.9, CandidateValue: "s1berindo.io", DedupKey: "abc123",
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
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingCreatedBRM {
		t.Fatalf("expected one finding.created.brm event, got %+v", pub.events)
	}
	ev, ok := pub.events[0].value.(types.FindingCreated)
	if !ok || ev.FindingID != f.ID || ev.SourceModule != types.ModuleBRM {
		t.Fatalf("unexpected event payload: %+v", pub.events[0].value)
	}
}

func TestCreateFindingValidation(t *testing.T) {
	svc, _, _ := newSvc()
	cases := []func(*CreateFindingInput){
		func(in *CreateFindingInput) { in.FindingType = "bogus" },
		func(in *CreateFindingInput) { in.Severity = "extreme" },
		func(in *CreateFindingInput) { in.ConfidenceScore = 1.5 },
		func(in *CreateFindingInput) { in.CandidateValue = "" },
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

// BRM-BR-002: a similarity score requires a recorded algorithm version.
func TestCreateFindingSimilarityRequiresAlgorithmVersion(t *testing.T) {
	svc, _, _ := newSvc()
	in := validInput()
	in.SimilarityScore = f64ptr(0.87)
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", in); !IsValidation(err) {
		t.Fatalf("expected validation error for similarity_score without algorithm version, got %v", err)
	}

	in.SimilarityAlgorithmVersion = strptr("levenshtein-v2")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", in); err != nil {
		t.Fatalf("expected similarity_score + version to be accepted, got %v", err)
	}

	// Out-of-range similarity score is rejected.
	bad := validInput()
	bad.SimilarityScore = f64ptr(1.5)
	bad.SimilarityAlgorithmVersion = strptr("levenshtein-v2")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", bad); !IsValidation(err) {
		t.Fatalf("expected validation error for out-of-range similarity_score, got %v", err)
	}
}

// BRM-VR-009: fake social media profile findings require platform + handle or URL.
func TestCreateFindingSocialFieldsRequired(t *testing.T) {
	svc, _, _ := newSvc()

	missing := validInput()
	missing.FindingType = "fake_social_media_profile"
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", missing); !IsValidation(err) {
		t.Fatalf("expected validation error for missing social fields, got %v", err)
	}

	platformOnly := validInput()
	platformOnly.FindingType = "fake_social_media_profile"
	platformOnly.SocialPlatformID = strptr("twitter")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", platformOnly); !IsValidation(err) {
		t.Fatalf("expected validation error when handle and url both missing, got %v", err)
	}

	ok := validInput()
	ok.FindingType = "fake_social_media_profile"
	ok.SocialPlatformID = strptr("twitter")
	ok.SocialAccountHandle = strptr("@fake_siberindo")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", ok); err != nil {
		t.Fatalf("expected social finding with platform + handle to be accepted, got %v", err)
	}
}

// BRM-VR-010: rogue mobile application findings require store, platform, and listing/package.
func TestCreateFindingAppFieldsRequired(t *testing.T) {
	svc, _, _ := newSvc()

	missing := validInput()
	missing.FindingType = "rogue_mobile_application"
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", missing); !IsValidation(err) {
		t.Fatalf("expected validation error for missing app fields, got %v", err)
	}

	noListing := validInput()
	noListing.FindingType = "rogue_mobile_application"
	noListing.AppStoreID = strptr("com.fake.app")
	noListing.AppPlatform = strptr("android")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", noListing); !IsValidation(err) {
		t.Fatalf("expected validation error when listing url and package id both missing, got %v", err)
	}

	ok := validInput()
	ok.FindingType = "rogue_mobile_application"
	ok.AppStoreID = strptr("com.fake.app")
	ok.AppPlatform = strptr("android")
	ok.AppPackageID = strptr("com.fake.siberindo")
	if _, err := svc.CreateFinding(context.Background(), "tenant-1", ok); err != nil {
		t.Fatalf("expected app finding with store + platform + package to be accepted, got %v", err)
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
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicFindingEscalatedBRM {
		t.Fatalf("expected finding.escalated.brm event, got %+v", pub.events)
	}
	ev := pub.events[0].value.(types.FindingEscalated)
	if ev.FindingID != f.ID || ev.EscalatedBy != "analyst-1" {
		t.Fatalf("unexpected escalation payload: %+v", ev)
	}
}

func TestInitiateTakedownRequiresEligibleStatus(t *testing.T) {
	svc, st, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput()) // status new

	if _, err := svc.InitiateTakedown(context.Background(), "tenant-1", f.ID); !IsValidation(err) {
		t.Fatalf("expected validation error for takedown of 'new' finding, got %v", err)
	}

	// Move to confirmed: takedown is now allowed.
	st.findings[f.ID].Status = "confirmed"
	out, err := svc.InitiateTakedown(context.Background(), "tenant-1", f.ID)
	if err != nil {
		t.Fatalf("takedown of confirmed finding: %v", err)
	}
	if out.Status != "takedown_initiated" {
		t.Fatalf("expected takedown_initiated, got %s", out.Status)
	}

	// Escalated findings are also eligible.
	g, _ := svc.CreateFinding(context.Background(), "tenant-1", func() CreateFindingInput {
		in := validInput()
		in.DedupKey = "esc-1"
		return in
	}())
	st.findings[g.ID].Status = "escalated"
	if _, err := svc.InitiateTakedown(context.Background(), "tenant-1", g.ID); err != nil {
		t.Fatalf("takedown of escalated finding: %v", err)
	}
}

func TestOverrideSeverityPreservesPrior(t *testing.T) {
	svc, st, _ := newSvc()
	f, _ := svc.CreateFinding(context.Background(), "tenant-1", validInput()) // severity high

	if err := svc.OverrideSeverity(context.Background(), "tenant-1", f.ID, "critical", "confirmed active impersonation"); err != nil {
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
	if err := svc.Suppress(context.Background(), "tenant-1", f.ID, "known internal test domain"); err != nil {
		t.Fatalf("suppress with justification: %v", err)
	}
}
