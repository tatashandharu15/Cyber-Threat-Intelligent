package consumer

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/alert-engine/internal/domain"
	"github.com/siberindo/cti/services/alert-engine/internal/rules"
)

type fakeStore struct {
	rules   []rules.Rule
	created []*domain.Alert
}

func (f *fakeStore) ListActiveRules(_ context.Context, _ string) ([]rules.Rule, error) {
	return f.rules, nil
}
func (f *fakeStore) CreateAlert(_ context.Context, a *domain.Alert) (*domain.Alert, error) {
	a.ID = "alert-" + a.SourceFindingID
	f.created = append(f.created, a)
	return a, nil
}

type fakePublisher struct{ events []types.AlertCreated }

func (f *fakePublisher) Publish(_ context.Context, _, _ string, value any) error {
	if ac, ok := value.(types.AlertCreated); ok {
		f.events = append(f.events, ac)
	}
	return nil
}

func escalatedJSON(t *testing.T, ev types.FindingEscalated) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestHandleCreatesAlertOnMatch(t *testing.T) {
	fs := &fakeStore{rules: []rules.Rule{
		{ID: "r1", Status: "active", Conditions: rules.Conditions{Severity: []string{"high", "critical"}}},
	}}
	fp := &fakePublisher{}
	h := New(fs, fp, nil)

	ev := types.FindingEscalated{
		TenantID: "t1", FindingID: "f1", SourceModule: types.ModuleDLM,
		Severity: types.SeverityHigh, FindingType: "credential_reference",
		ConfidenceScore: 0.9, Title: "Leaked creds",
	}
	if err := h.Handle(context.Background(), nil, escalatedJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fs.created) != 1 {
		t.Fatalf("expected 1 alert created, got %d", len(fs.created))
	}
	if fs.created[0].SourceFindingID != "f1" || fs.created[0].Severity != "high" {
		t.Fatalf("unexpected alert: %+v", fs.created[0])
	}
	if len(fp.events) != 1 || fp.events[0].AlertID != "alert-f1" {
		t.Fatalf("expected 1 alert.created event, got %+v", fp.events)
	}
}

func TestHandleNoMatchCreatesNothing(t *testing.T) {
	fs := &fakeStore{rules: []rules.Rule{
		{ID: "r1", Status: "active", Conditions: rules.Conditions{Severity: []string{"critical"}}},
	}}
	fp := &fakePublisher{}
	h := New(fs, fp, nil)

	ev := types.FindingEscalated{
		TenantID: "t1", FindingID: "f2", SourceModule: types.ModuleDLM, Severity: types.SeverityLow,
	}
	if err := h.Handle(context.Background(), nil, escalatedJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fs.created) != 0 {
		t.Fatalf("expected no alerts, got %d", len(fs.created))
	}
	if len(fp.events) != 0 {
		t.Fatalf("expected no events, got %d", len(fp.events))
	}
}

func TestHandleDropsMalformed(t *testing.T) {
	h := New(&fakeStore{}, &fakePublisher{}, nil)
	if err := h.Handle(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("malformed payload should be dropped, not errored: %v", err)
	}
}

func TestHandleMultipleRules(t *testing.T) {
	fs := &fakeStore{rules: []rules.Rule{
		{ID: "r1", Status: "active", Conditions: rules.Conditions{Severity: []string{"high"}}},
		{ID: "r2", Status: "active", SourceModule: "dlm"},
		{ID: "r3", Status: "paused"},
	}}
	fp := &fakePublisher{}
	h := New(fs, fp, nil)

	ev := types.FindingEscalated{
		TenantID: "t1", FindingID: "f3", SourceModule: types.ModuleDLM,
		Severity: types.SeverityHigh, ConfidenceScore: 1,
	}
	if err := h.Handle(context.Background(), nil, escalatedJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fs.created) != 2 {
		t.Fatalf("expected 2 alerts (r1,r2), got %d", len(fs.created))
	}
}
