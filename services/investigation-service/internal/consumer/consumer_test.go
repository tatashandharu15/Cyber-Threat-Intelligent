package consumer

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/investigation-service/internal/domain"
)

type fakeStore struct {
	inserted []*domain.InboxAlert
}

func (f *fakeStore) InsertInboxAlert(_ context.Context, a *domain.InboxAlert) error {
	f.inserted = append(f.inserted, a)
	return nil
}

func alertJSON(t *testing.T, ev types.AlertCreated) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestHandleInsertsInboxAlert(t *testing.T) {
	fs := &fakeStore{}
	h := New(fs, nil)

	ev := types.AlertCreated{
		EventID: "e1", EventType: "alert.created", TenantID: "t1", AlertID: "a1",
		SourceModule: types.ModuleDLM, SourceFindingID: "f1", Severity: types.SeverityHigh,
		Title: "Leaked creds",
	}
	if err := h.Handle(context.Background(), nil, alertJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fs.inserted) != 1 {
		t.Fatalf("expected 1 inbox row, got %d", len(fs.inserted))
	}
	got := fs.inserted[0]
	if got.AlertID != "a1" || got.TenantID != "t1" || got.SourceModule != "dlm" || got.SourceFindingID != "f1" {
		t.Fatalf("unexpected inbox row: %+v", got)
	}
	if got.Severity == nil || *got.Severity != "high" {
		t.Fatalf("expected severity high, got %v", got.Severity)
	}
	if got.Title == nil || *got.Title != "Leaked creds" {
		t.Fatalf("expected title, got %v", got.Title)
	}
}

func TestHandleDropsMalformed(t *testing.T) {
	fs := &fakeStore{}
	h := New(fs, nil)
	if err := h.Handle(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("malformed payload should be dropped, not errored: %v", err)
	}
	if len(fs.inserted) != 0 {
		t.Fatalf("expected no inbox rows for malformed payload, got %d", len(fs.inserted))
	}
}

func TestHandleDropsMissingIDs(t *testing.T) {
	fs := &fakeStore{}
	h := New(fs, nil)
	ev := types.AlertCreated{EventType: "alert.created", SourceModule: types.ModuleDLM}
	if err := h.Handle(context.Background(), nil, alertJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fs.inserted) != 0 {
		t.Fatalf("expected no inbox rows when tenant/alert id missing, got %d", len(fs.inserted))
	}
}
