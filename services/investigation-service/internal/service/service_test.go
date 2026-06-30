package service

import (
	"context"
	"testing"

	"github.com/siberindo/cti/services/investigation-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	investigations map[string]*domain.Investigation
	findings       map[string][]domain.LinkedFinding
	timeline       map[string][]domain.TimelineEntry
	seq            int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		investigations: map[string]*domain.Investigation{},
		findings:       map[string][]domain.LinkedFinding{},
		timeline:       map[string][]domain.TimelineEntry{},
	}
}

func (f *fakeStore) CreateInvestigation(_ context.Context, inv *domain.Investigation) (*domain.Investigation, error) {
	f.seq++
	inv.ID = "inv-" + itoa(f.seq)
	f.investigations[inv.ID] = inv
	f.timeline[inv.ID] = append(f.timeline[inv.ID], domain.TimelineEntry{
		InvestigationID: inv.ID, EntryType: "created",
	})
	return inv, nil
}

func (f *fakeStore) GetInvestigation(_ context.Context, _, id string) (*domain.Investigation, error) {
	if inv, ok := f.investigations[id]; ok {
		return inv, nil
	}
	return nil, ErrNotFound
}

func (f *fakeStore) ListInvestigations(_ context.Context, _ string, _ domain.InvestigationFilter) ([]domain.Investigation, error) {
	out := []domain.Investigation{}
	for _, inv := range f.investigations {
		out = append(out, *inv)
	}
	return out, nil
}

func (f *fakeStore) UpdateStatus(_ context.Context, _, id, status string) error {
	if inv, ok := f.investigations[id]; ok {
		inv.Status = status
		return nil
	}
	return ErrNotFound
}

func (f *fakeStore) Assign(_ context.Context, _, id, assignedTo string) error {
	if inv, ok := f.investigations[id]; ok {
		inv.AssignedTo = &assignedTo
		return nil
	}
	return ErrNotFound
}

func (f *fakeStore) AddNote(_ context.Context, _, id, note string) error {
	if _, ok := f.investigations[id]; !ok {
		return ErrNotFound
	}
	f.timeline[id] = append(f.timeline[id], domain.TimelineEntry{
		InvestigationID: id, EntryType: "note", Detail: &note,
	})
	return nil
}

func (f *fakeStore) Close(_ context.Context, _, id string) error {
	if inv, ok := f.investigations[id]; ok {
		inv.Status = "closed"
		return nil
	}
	return ErrNotFound
}

func (f *fakeStore) LinkFinding(_ context.Context, lf *domain.LinkedFinding) error {
	if _, ok := f.investigations[lf.InvestigationID]; !ok {
		return ErrNotFound
	}
	f.findings[lf.InvestigationID] = append(f.findings[lf.InvestigationID], *lf)
	return nil
}

func (f *fakeStore) ListLinkedFindings(_ context.Context, _, id string) ([]domain.LinkedFinding, error) {
	return f.findings[id], nil
}

func (f *fakeStore) ListTimeline(_ context.Context, _, id string) ([]domain.TimelineEntry, error) {
	return f.timeline[id], nil
}

func (f *fakeStore) ListInbox(_ context.Context, _ string) ([]domain.InboxAlert, error) {
	return nil, nil
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
	return New(st, nil), st
}

func TestCreateInvestigation(t *testing.T) {
	svc, _ := newSvc()
	inv, err := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{
		Title: "Suspicious credential leak",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inv.Status != "open" {
		t.Fatalf("expected status open, got %s", inv.Status)
	}
	if inv.Priority != "medium" {
		t.Fatalf("expected default priority medium, got %s", inv.Priority)
	}
}

func TestCreateInvestigationRequiresTitle(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{}); !IsValidation(err) {
		t.Fatalf("expected validation error for missing title, got %v", err)
	}
}

func TestLinkFindingAddsLinkedFinding(t *testing.T) {
	svc, st := newSvc()
	inv, _ := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{Title: "Case"})

	if err := svc.LinkFinding(context.Background(), "tenant-1", inv.ID, LinkFindingInput{
		SourceModule: "dlm", SourceFindingID: "finding-1",
	}); err != nil {
		t.Fatalf("link finding: %v", err)
	}
	linked, err := svc.ListLinkedFindings(context.Background(), "tenant-1", inv.ID)
	if err != nil {
		t.Fatalf("list linked: %v", err)
	}
	if len(linked) != 1 || linked[0].SourceFindingID != "finding-1" || linked[0].SourceModule != "dlm" {
		t.Fatalf("expected one linked dlm finding, got %+v", linked)
	}
	if len(st.findings[inv.ID]) != 1 {
		t.Fatalf("expected store to hold one linked finding, got %d", len(st.findings[inv.ID]))
	}
}

func TestLinkFindingValidation(t *testing.T) {
	svc, _ := newSvc()
	inv, _ := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{Title: "Case"})
	cases := []LinkFindingInput{
		{SourceModule: "bogus", SourceFindingID: "f1"},
		{SourceModule: "dlm", SourceFindingID: ""},
	}
	for i, in := range cases {
		if err := svc.LinkFinding(context.Background(), "tenant-1", inv.ID, in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestUpdateStatusInvalidValue(t *testing.T) {
	svc, _ := newSvc()
	inv, _ := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{Title: "Case"})
	if err := svc.UpdateStatus(context.Background(), "tenant-1", inv.ID, "bogus"); !IsValidation(err) {
		t.Fatalf("expected validation error for invalid status, got %v", err)
	}
}

func TestCannotChangeStatusOfClosed(t *testing.T) {
	svc, _ := newSvc()
	inv, _ := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{Title: "Case"})
	if err := svc.Close(context.Background(), "tenant-1", inv.ID); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := svc.UpdateStatus(context.Background(), "tenant-1", inv.ID, "in_progress"); !IsValidation(err) {
		t.Fatalf("expected validation error changing status of closed investigation, got %v", err)
	}
}

func TestAddNoteRequiresText(t *testing.T) {
	svc, _ := newSvc()
	inv, _ := svc.CreateInvestigation(context.Background(), "tenant-1", CreateInvestigationInput{Title: "Case"})
	if err := svc.AddNote(context.Background(), "tenant-1", inv.ID, ""); !IsValidation(err) {
		t.Fatalf("expected validation error for empty note, got %v", err)
	}
	if err := svc.AddNote(context.Background(), "tenant-1", inv.ID, "looked into it"); err != nil {
		t.Fatalf("add note with text: %v", err)
	}
}
