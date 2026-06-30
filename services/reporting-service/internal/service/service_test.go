package service

import (
	"context"
	"errors"
	"testing"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/reporting-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	reports map[string]*domain.Report
	seq     int
	failOn  string // method name that should return an error
}

func newFakeStore() *fakeStore { return &fakeStore{reports: map[string]*domain.Report{}} }

func (f *fakeStore) CreateReport(_ context.Context, r *domain.Report) (*domain.Report, error) {
	if f.failOn == "CreateReport" {
		return nil, errors.New("boom")
	}
	f.seq++
	r.ID = "report-" + itoa(f.seq)
	now := time.Now()
	r.CreatedAt = now
	r.UpdatedAt = now
	f.reports[r.ID] = r
	return r, nil
}
func (f *fakeStore) GetReport(_ context.Context, _, id string) (*domain.Report, error) {
	if r, ok := f.reports[id]; ok {
		return r, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) ListReports(_ context.Context, _ string, _ domain.ReportFilter) ([]domain.Report, error) {
	out := []domain.Report{}
	for _, r := range f.reports {
		out = append(out, *r)
	}
	return out, nil
}
func (f *fakeStore) MarkGenerating(_ context.Context, _, id string) error {
	if f.failOn == "MarkGenerating" {
		return errors.New("boom")
	}
	if r, ok := f.reports[id]; ok {
		r.Status = "generating"
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) MarkComplete(_ context.Context, _, id, outputRef string, generatedAt time.Time) error {
	if f.failOn == "MarkComplete" {
		return errors.New("boom")
	}
	if r, ok := f.reports[id]; ok {
		r.Status = "complete"
		r.OutputRef = &outputRef
		r.GeneratedAt = &generatedAt
		return nil
	}
	return ErrNotFound
}
func (f *fakeStore) MarkFailed(_ context.Context, _, id, reason string) error {
	if r, ok := f.reports[id]; ok {
		r.Status = "failed"
		r.FailureReason = &reason
		return nil
	}
	return ErrNotFound
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

func validInput() RequestReportInput {
	return RequestReportInput{
		ReportType: "executive_summary", Title: "Q2 Executive Summary",
	}
}

func TestRequestReportQueuesAndPublishes(t *testing.T) {
	svc, _, pub := newSvc()
	r, err := svc.RequestReport(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Status != "queued" {
		t.Fatalf("expected status queued, got %s", r.Status)
	}
	if r.OutputFormat != "pdf" {
		t.Fatalf("expected default format pdf, got %s", r.OutputFormat)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicReportRequested {
		t.Fatalf("expected one report.requested event, got %+v", pub.events)
	}
	ev, ok := pub.events[0].value.(types.ReportRequested)
	if !ok || ev.ReportID != r.ID || ev.EventType != "report.requested" {
		t.Fatalf("unexpected event payload: %+v", pub.events[0].value)
	}
}

func TestRequestReportValidation(t *testing.T) {
	svc, _, _ := newSvc()
	cases := []func(*RequestReportInput){
		func(in *RequestReportInput) { in.ReportType = "bogus" },
		func(in *RequestReportInput) { in.Format = "docx" },
		func(in *RequestReportInput) { in.Title = "" },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.RequestReport(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestGenerateMarksCompleteAndPublishes(t *testing.T) {
	svc, st, pub := newSvc()
	r, _ := svc.RequestReport(context.Background(), "tenant-1", validInput())
	pub.events = nil // discard the request event

	ev := types.ReportRequested{TenantID: "tenant-1", ReportID: r.ID, ReportType: r.ReportType, Format: "pdf"}
	if err := svc.Generate(context.Background(), ev); err != nil {
		t.Fatalf("generate: %v", err)
	}

	got := st.reports[r.ID]
	if got.Status != "complete" {
		t.Fatalf("expected status complete, got %s", got.Status)
	}
	wantRef := "s3://siberindo-reports/tenant-1/" + r.ID + ".pdf"
	if got.OutputRef == nil || *got.OutputRef != wantRef {
		t.Fatalf("expected output_ref %q, got %v", wantRef, got.OutputRef)
	}
	if got.GeneratedAt == nil {
		t.Fatalf("expected generated_at to be set")
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicReportCompleted {
		t.Fatalf("expected one report.completed event, got %+v", pub.events)
	}
	done, ok := pub.events[0].value.(types.ReportCompleted)
	if !ok || done.Status != "complete" || done.OutputRef != wantRef || done.ReportID != r.ID {
		t.Fatalf("unexpected report.completed payload: %+v", pub.events[0].value)
	}
}

func TestGenerateFailureMarksFailed(t *testing.T) {
	st := newFakeStore()
	pub := &fakePublisher{}
	svc := New(st, pub, nil)

	// Seed a queued report directly, then force MarkComplete to fail.
	r, _ := st.CreateReport(context.Background(), &domain.Report{
		TenantID: "tenant-1", ReportType: "executive_summary", Title: "x", Status: "queued", OutputFormat: "pdf",
	})
	st.failOn = "MarkComplete"

	ev := types.ReportRequested{TenantID: "tenant-1", ReportID: r.ID, ReportType: r.ReportType, Format: "pdf"}
	if err := svc.Generate(context.Background(), ev); err != nil {
		t.Fatalf("generate should record failure without returning error, got %v", err)
	}

	got := st.reports[r.ID]
	if got.Status != "failed" {
		t.Fatalf("expected status failed, got %s", got.Status)
	}
	if got.FailureReason == nil || *got.FailureReason == "" {
		t.Fatalf("expected failure_reason to be set")
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicReportCompleted {
		t.Fatalf("expected one report.completed event, got %+v", pub.events)
	}
	done := pub.events[0].value.(types.ReportCompleted)
	if done.Status != "failed" || done.ReportID != r.ID {
		t.Fatalf("unexpected report.completed payload: %+v", done)
	}
}
