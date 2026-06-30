package consumer

import (
	"context"
	"encoding/json"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/audit-service/internal/domain"
)

// fakeRecorder records the events handed to it.
type fakeRecorder struct {
	recorded []types.AuditEventWritten
}

func (f *fakeRecorder) RecordFromEvent(_ context.Context, ev types.AuditEventWritten) (*domain.AuditEvent, error) {
	f.recorded = append(f.recorded, ev)
	return &domain.AuditEvent{ID: "audit-1", TenantID: ev.TenantID, ActorID: ev.ActorID}, nil
}

func writtenJSON(t *testing.T, ev types.AuditEventWritten) []byte {
	t.Helper()
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func TestHandleRecordsValidEvent(t *testing.T) {
	fr := &fakeRecorder{}
	h := New(fr, nil)

	ev := types.AuditEventWritten{
		EventID: "e1", EventType: "user.login", TenantID: "t1", ActorID: "a1",
		ActorType: "user", ResourceType: "session", ResourceID: "s1",
		Action: "create", Outcome: "success",
	}
	if err := h.Handle(context.Background(), nil, writtenJSON(t, ev)); err != nil {
		t.Fatalf("handle: %v", err)
	}
	if len(fr.recorded) != 1 {
		t.Fatalf("expected 1 recorded event, got %d", len(fr.recorded))
	}
	if fr.recorded[0].EventType != "user.login" || fr.recorded[0].TenantID != "t1" {
		t.Fatalf("unexpected recorded event: %+v", fr.recorded[0])
	}
}

func TestHandleDropsMalformed(t *testing.T) {
	fr := &fakeRecorder{}
	h := New(fr, nil)
	if err := h.Handle(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("malformed payload should be dropped, not errored: %v", err)
	}
	if len(fr.recorded) != 0 {
		t.Fatalf("expected nothing recorded for malformed payload, got %d", len(fr.recorded))
	}
}

func TestHandleDropsMissingIDs(t *testing.T) {
	fr := &fakeRecorder{}
	h := New(fr, nil)
	ev := types.AuditEventWritten{EventType: "user.login", Action: "create"} // no tenant/actor
	if err := h.Handle(context.Background(), nil, writtenJSON(t, ev)); err != nil {
		t.Fatalf("incomplete payload should be dropped, not errored: %v", err)
	}
	if len(fr.recorded) != 0 {
		t.Fatalf("expected nothing recorded for incomplete payload, got %d", len(fr.recorded))
	}
}
