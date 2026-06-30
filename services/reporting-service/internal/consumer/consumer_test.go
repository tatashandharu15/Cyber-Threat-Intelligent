package consumer

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
)

// fakeGenerator records the events it was asked to generate.
type fakeGenerator struct {
	calls []types.ReportRequested
	err   error
}

func (f *fakeGenerator) Generate(_ context.Context, ev types.ReportRequested) error {
	f.calls = append(f.calls, ev)
	return f.err
}

func requestedJSON(t *testing.T, ev types.ReportRequested) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestHandleTriggersGenerate(t *testing.T) {
	fg := &fakeGenerator{}
	h := New(fg, nil)

	ev := types.ReportRequested{
		TenantID: "t1", ReportID: "r1", ReportType: "executive_summary", Format: "pdf",
	}
	if err := h.Handle(context.Background(), nil, requestedJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fg.calls) != 1 {
		t.Fatalf("expected Generate called once, got %d", len(fg.calls))
	}
	if fg.calls[0].ReportID != "r1" {
		t.Fatalf("unexpected event passed to Generate: %+v", fg.calls[0])
	}
}

func TestHandleDropsMalformed(t *testing.T) {
	fg := &fakeGenerator{}
	h := New(fg, nil)
	if err := h.Handle(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("malformed payload should be dropped, not errored: %v", err)
	}
	if len(fg.calls) != 0 {
		t.Fatalf("expected no Generate calls for malformed payload, got %d", len(fg.calls))
	}
}

func TestHandleDropsMissingTenant(t *testing.T) {
	fg := &fakeGenerator{}
	h := New(fg, nil)
	ev := types.ReportRequested{ReportID: "r1", ReportType: "executive_summary"}
	if err := h.Handle(context.Background(), nil, requestedJSON(t, ev)); err != nil {
		t.Fatalf("missing tenant should be dropped, not errored: %v", err)
	}
	if len(fg.calls) != 0 {
		t.Fatalf("expected no Generate calls for empty-tenant payload, got %d", len(fg.calls))
	}
}
