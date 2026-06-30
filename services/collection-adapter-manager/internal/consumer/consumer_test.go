package consumer

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/service"
)

// fakeIngester records the runs passed to it.
type fakeIngester struct {
	runs []service.Run
}

func (f *fakeIngester) IngestRun(_ context.Context, run service.Run) error {
	f.runs = append(f.runs, run)
	return nil
}

func TestHandleCompletedRecordsCompletedRun(t *testing.T) {
	ing := &fakeIngester{}
	h := New(ing, nil)
	ev := types.CollectionJobResult{
		EventID: "e1", EventType: "collection.job.completed", TenantID: "tenant-1",
		JobID: "job-1", Module: types.ModuleDLM, SourceAdapterID: "adapter-1",
		FindingsIngested: 7, ErrorsCount: 0, StartedAt: time.Now(), CompletedAt: time.Now(),
	}
	body, _ := json.Marshal(ev)
	if err := h.HandleCompleted(context.Background(), nil, body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ing.runs) != 1 {
		t.Fatalf("expected one run, got %d", len(ing.runs))
	}
	got := ing.runs[0]
	if got.Outcome != "completed" || got.AdapterID != "adapter-1" || got.TenantID != "tenant-1" {
		t.Fatalf("unexpected run: %+v", got)
	}
	if got.FindingsIngested == nil || *got.FindingsIngested != 7 {
		t.Fatalf("expected findings_ingested=7, got %v", got.FindingsIngested)
	}
	if got.Module != "dlm" {
		t.Fatalf("expected module dlm, got %q", got.Module)
	}
}

func TestHandleFailedRecordsFailedRun(t *testing.T) {
	ing := &fakeIngester{}
	h := New(ing, nil)
	ev := types.CollectionJobFailed{
		EventID: "e2", EventType: "collection.job.failed", TenantID: "tenant-1",
		JobID: "job-2", Module: types.ModuleBRM, SourceAdapterID: "adapter-2",
		Error: "connection refused", FailedAt: time.Now(),
	}
	body, _ := json.Marshal(ev)
	if err := h.HandleFailed(context.Background(), nil, body); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ing.runs) != 1 {
		t.Fatalf("expected one run, got %d", len(ing.runs))
	}
	got := ing.runs[0]
	if got.Outcome != "failed" || got.AdapterID != "adapter-2" || got.Detail != "connection refused" {
		t.Fatalf("unexpected run: %+v", got)
	}
	if got.Module != "brm" {
		t.Fatalf("expected module brm, got %q", got.Module)
	}
}

func TestHandleDropsMalformedAndEmptyTenant(t *testing.T) {
	ing := &fakeIngester{}
	h := New(ing, nil)

	// Malformed JSON is dropped without error and without an ingest.
	if err := h.HandleCompleted(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("expected malformed completed to be dropped, got %v", err)
	}
	if err := h.HandleFailed(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("expected malformed failed to be dropped, got %v", err)
	}

	// Empty tenant / adapter is dropped without an ingest.
	emptyTenant, _ := json.Marshal(types.CollectionJobResult{SourceAdapterID: "adapter-1"})
	if err := h.HandleCompleted(context.Background(), nil, emptyTenant); err != nil {
		t.Fatalf("expected empty-tenant completed to be dropped, got %v", err)
	}
	emptyAdapter, _ := json.Marshal(types.CollectionJobFailed{TenantID: "tenant-1"})
	if err := h.HandleFailed(context.Background(), nil, emptyAdapter); err != nil {
		t.Fatalf("expected empty-adapter failed to be dropped, got %v", err)
	}

	if len(ing.runs) != 0 {
		t.Fatalf("expected no runs recorded, got %d: %+v", len(ing.runs), ing.runs)
	}
}
