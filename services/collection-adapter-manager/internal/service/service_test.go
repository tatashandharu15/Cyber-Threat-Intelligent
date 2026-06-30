package service

import (
	"context"
	"testing"

	"github.com/siberindo/cti/services/collection-adapter-manager/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	adapters map[string]*domain.Adapter
	runs     map[string][]domain.RunEvent
	seq      int
}

func newFakeStore() *fakeStore {
	return &fakeStore{adapters: map[string]*domain.Adapter{}, runs: map[string][]domain.RunEvent{}}
}

func (f *fakeStore) CreateAdapter(_ context.Context, a *domain.Adapter) (*domain.Adapter, error) {
	f.seq++
	a.ID = "adapter-" + itoa(f.seq)
	a.Status = "active"
	f.adapters[a.ID] = a
	return a, nil
}

func (f *fakeStore) GetAdapter(_ context.Context, _, id string) (*domain.Adapter, error) {
	if a, ok := f.adapters[id]; ok {
		return a, nil
	}
	return nil, ErrNotFound
}

func (f *fakeStore) ListAdapters(_ context.Context, _ string, _ domain.AdapterFilter) ([]domain.Adapter, error) {
	out := []domain.Adapter{}
	for _, a := range f.adapters {
		out = append(out, *a)
	}
	return out, nil
}

func (f *fakeStore) UpdateAdapter(_ context.Context, _, id string, scheduleCron, configRef *string) error {
	a, ok := f.adapters[id]
	if !ok {
		return ErrNotFound
	}
	if scheduleCron != nil {
		a.ScheduleCron = scheduleCron
	}
	if configRef != nil {
		a.ConfigRef = configRef
	}
	return nil
}

func (f *fakeStore) SetStatus(_ context.Context, _, id, status string) error {
	a, ok := f.adapters[id]
	if !ok {
		return ErrNotFound
	}
	a.Status = status
	return nil
}

func (f *fakeStore) ListRuns(_ context.Context, _, adapterID string) ([]domain.RunEvent, error) {
	return f.runs[adapterID], nil
}

func (f *fakeStore) RecordRunByAdapterID(_ context.Context, _, adapterID, module, outcome string, findingsIngested, errorsCount *int, detail string) error {
	a, ok := f.adapters[adapterID]
	if !ok {
		// Mirror the real store: an unresolved adapter id is skipped, not an error.
		return nil
	}
	a.LastStatus = &outcome
	a.FindingsLastRun = findingsIngested
	if outcome == "failed" {
		a.Status = "error"
		if detail != "" {
			d := detail
			a.LastError = &d
		}
	}
	f.runs[adapterID] = append(f.runs[adapterID], domain.RunEvent{
		TenantID: "tenant-1", AdapterID: &adapterID, Outcome: outcome,
		FindingsIngested: findingsIngested, ErrorsCount: errorsCount,
	})
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

func newSvc() (*Service, *fakeStore) {
	st := newFakeStore()
	return New(st, nil), st
}

func validInput() CreateAdapterInput {
	return CreateAdapterInput{Module: "dlm", AdapterType: "paste_site", Name: "Pastebin watcher"}
}

func intp(n int) *int { return &n }

func TestCreateAdapterValidation(t *testing.T) {
	svc, _ := newSvc()
	cases := []func(*CreateAdapterInput){
		func(in *CreateAdapterInput) { in.Module = "bogus" },
		func(in *CreateAdapterInput) { in.AdapterType = "" },
		func(in *CreateAdapterInput) { in.Name = "" },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.CreateAdapter(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
	// A valid input succeeds and defaults to active.
	a, err := svc.CreateAdapter(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Status != "active" {
		t.Fatalf("expected status active, got %s", a.Status)
	}
}

func TestPauseResumeStatus(t *testing.T) {
	svc, _ := newSvc()
	a, _ := svc.CreateAdapter(context.Background(), "tenant-1", validInput())

	if err := svc.Pause(context.Background(), "tenant-1", a.ID); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if a.Status != "paused" {
		t.Fatalf("expected paused, got %s", a.Status)
	}
	if err := svc.Resume(context.Background(), "tenant-1", a.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if a.Status != "active" {
		t.Fatalf("expected active, got %s", a.Status)
	}
}

func TestRetireIsTerminal(t *testing.T) {
	svc, _ := newSvc()
	a, _ := svc.CreateAdapter(context.Background(), "tenant-1", validInput())

	if err := svc.Retire(context.Background(), "tenant-1", a.ID); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if a.Status != "retired" {
		t.Fatalf("expected retired, got %s", a.Status)
	}
	// Resuming a retired adapter is a validation error.
	if err := svc.Resume(context.Background(), "tenant-1", a.ID); !IsValidation(err) {
		t.Fatalf("expected validation error resuming retired adapter, got %v", err)
	}
	// Pausing a retired adapter is also a validation error.
	if err := svc.Pause(context.Background(), "tenant-1", a.ID); !IsValidation(err) {
		t.Fatalf("expected validation error pausing retired adapter, got %v", err)
	}
}

func TestTriggerRequiresActive(t *testing.T) {
	svc, _ := newSvc()
	a, _ := svc.CreateAdapter(context.Background(), "tenant-1", validInput())

	if err := svc.Trigger(context.Background(), "tenant-1", a.ID); err != nil {
		t.Fatalf("trigger active adapter: %v", err)
	}
	_ = svc.Pause(context.Background(), "tenant-1", a.ID)
	if err := svc.Trigger(context.Background(), "tenant-1", a.ID); !IsValidation(err) {
		t.Fatalf("expected validation error triggering paused adapter, got %v", err)
	}
}

func TestIngestRunCompletedUpdatesHealth(t *testing.T) {
	svc, st := newSvc()
	a, _ := svc.CreateAdapter(context.Background(), "tenant-1", validInput())

	err := svc.IngestRun(context.Background(), Run{
		TenantID: "tenant-1", AdapterID: a.ID, Module: "dlm", Outcome: "completed",
		FindingsIngested: intp(12), ErrorsCount: intp(0),
	})
	if err != nil {
		t.Fatalf("ingest completed: %v", err)
	}
	got := st.adapters[a.ID]
	if got.LastStatus == nil || *got.LastStatus != "completed" {
		t.Fatalf("expected last_status completed, got %v", got.LastStatus)
	}
	if got.FindingsLastRun == nil || *got.FindingsLastRun != 12 {
		t.Fatalf("expected findings_last_run 12, got %v", got.FindingsLastRun)
	}
	if got.Status != "active" {
		t.Fatalf("expected completed run to keep status active, got %s", got.Status)
	}
}

func TestIngestRunFailedSetsErrorStatus(t *testing.T) {
	svc, st := newSvc()
	a, _ := svc.CreateAdapter(context.Background(), "tenant-1", validInput())

	err := svc.IngestRun(context.Background(), Run{
		TenantID: "tenant-1", AdapterID: a.ID, Module: "dlm", Outcome: "failed",
		Detail: "auth failed",
	})
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	got := st.adapters[a.ID]
	if got.Status != "error" {
		t.Fatalf("expected status error after failed run, got %s", got.Status)
	}
	if got.LastStatus == nil || *got.LastStatus != "failed" {
		t.Fatalf("expected last_status failed, got %v", got.LastStatus)
	}
	if got.LastError == nil || *got.LastError != "auth failed" {
		t.Fatalf("expected last_error 'auth failed', got %v", got.LastError)
	}
}

func TestIngestRunDropsEmptyTenantOrAdapter(t *testing.T) {
	svc, _ := newSvc()
	if err := svc.IngestRun(context.Background(), Run{AdapterID: "adapter-1", Outcome: "completed"}); err != nil {
		t.Fatalf("expected empty tenant dropped, got %v", err)
	}
	if err := svc.IngestRun(context.Background(), Run{TenantID: "tenant-1", Outcome: "completed"}); err != nil {
		t.Fatalf("expected empty adapter dropped, got %v", err)
	}
}
