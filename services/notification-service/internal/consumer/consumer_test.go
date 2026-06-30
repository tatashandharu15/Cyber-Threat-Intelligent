package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/notification-service/internal/domain"
)

// fakeNotifier records the alerts it is asked to notify on.
type fakeNotifier struct {
	calls []types.AlertCreated
	err   error
	seq   int
}

func (f *fakeNotifier) NotifyForAlert(_ context.Context, alert types.AlertCreated) (*domain.Notification, error) {
	f.calls = append(f.calls, alert)
	if f.err != nil {
		return nil, f.err
	}
	f.seq++
	return &domain.Notification{ID: "notif-1", TenantID: alert.TenantID, Status: "sent"}, nil
}

func TestHandleHighSeverityProducesNotification(t *testing.T) {
	fake := &fakeNotifier{}
	h := New(fake, nil)

	ev := types.AlertCreated{
		EventType: "alert.created", TenantID: "tenant-1", AlertID: "alert-1",
		SourceModule: types.ModuleDLM, Severity: types.SeverityHigh, Title: "Critical breach",
	}
	value, _ := json.Marshal(ev)

	if err := h.Handle(context.Background(), nil, value); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("expected one NotifyForAlert call, got %d", len(fake.calls))
	}
	if fake.calls[0].AlertID != "alert-1" {
		t.Fatalf("unexpected alert forwarded: %+v", fake.calls[0])
	}
}

func TestHandleMalformedPayloadIsDropped(t *testing.T) {
	fake := &fakeNotifier{}
	h := New(fake, nil)

	if err := h.Handle(context.Background(), nil, []byte("{not json")); err != nil {
		t.Fatalf("expected malformed payload to be dropped (nil), got %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no NotifyForAlert calls for malformed payload, got %d", len(fake.calls))
	}
}

func TestHandleMissingTenantIsDropped(t *testing.T) {
	fake := &fakeNotifier{}
	h := New(fake, nil)

	ev := types.AlertCreated{EventType: "alert.created", AlertID: "alert-1", Severity: types.SeverityHigh}
	value, _ := json.Marshal(ev)

	if err := h.Handle(context.Background(), nil, value); err != nil {
		t.Fatalf("expected missing-tenant event to be dropped (nil), got %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no NotifyForAlert calls for missing tenant, got %d", len(fake.calls))
	}
}

func TestHandleInfraFailureRetries(t *testing.T) {
	fake := &fakeNotifier{err: errors.New("db down")}
	h := New(fake, nil)

	ev := types.AlertCreated{
		EventType: "alert.created", TenantID: "tenant-1", AlertID: "alert-1",
		SourceModule: types.ModuleDLM, Severity: types.SeverityHigh,
	}
	value, _ := json.Marshal(ev)

	if err := h.Handle(context.Background(), nil, value); err == nil {
		t.Fatalf("expected infra failure to return an error so the message is retried")
	}
}
