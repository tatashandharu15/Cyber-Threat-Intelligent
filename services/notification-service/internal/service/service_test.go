package service

import (
	"context"
	"testing"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/notification-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests.
type fakeStore struct {
	notifications map[string]*domain.Notification
	prefs         map[string]*domain.Preference // key: user|channel|event
	seq           int
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		notifications: map[string]*domain.Notification{},
		prefs:         map[string]*domain.Preference{},
	}
}

func prefKey(userID, channel, eventType string) string {
	return userID + "|" + channel + "|" + eventType
}

func (f *fakeStore) CreateNotification(_ context.Context, n *domain.Notification) (*domain.Notification, error) {
	f.seq++
	n.ID = "notif-" + itoa(f.seq)
	f.notifications[n.ID] = n
	return n, nil
}
func (f *fakeStore) ListNotifications(_ context.Context, _ string, _ domain.NotificationFilter) ([]domain.Notification, error) {
	out := []domain.Notification{}
	for _, n := range f.notifications {
		out = append(out, *n)
	}
	return out, nil
}
func (f *fakeStore) GetNotification(_ context.Context, _, id string) (*domain.Notification, error) {
	if n, ok := f.notifications[id]; ok {
		return n, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) MarkRead(_ context.Context, _, id string) error {
	n, ok := f.notifications[id]
	if !ok {
		return ErrNotFound
	}
	now := nowMarker
	n.ReadAt = &now
	return nil
}
func (f *fakeStore) GetPreference(_ context.Context, _, userID, channel, eventType string) (*domain.Preference, error) {
	if p, ok := f.prefs[prefKey(userID, channel, eventType)]; ok {
		return p, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) UpsertPreference(_ context.Context, p *domain.Preference) (*domain.Preference, error) {
	key := prefKey(p.UserID, p.Channel, p.EventType)
	if existing, ok := f.prefs[key]; ok {
		existing.Enabled = p.Enabled
		return existing, nil
	}
	f.seq++
	p.ID = "pref-" + itoa(f.seq)
	f.prefs[key] = p
	return p, nil
}
func (f *fakeStore) ListPreferences(_ context.Context, _, userID string) ([]domain.Preference, error) {
	out := []domain.Preference{}
	for _, p := range f.prefs {
		if p.UserID == userID {
			out = append(out, *p)
		}
	}
	return out, nil
}

// nowMarker is a sentinel non-zero time used by the fake MarkRead.
var nowMarker = time.Now()

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

func alertEvent(severity types.Severity) types.AlertCreated {
	return types.AlertCreated{
		EventID: "evt-1", EventType: "alert.created", TenantID: "tenant-1",
		AlertID: "alert-1", SourceModule: types.ModuleDLM, SourceFindingID: "finding-1",
		Severity: severity, Title: "Leaked credentials detected",
	}
}

// disablePref stores a disabling tenant-default preference for in_app/alert.created.
func disablePref(st *fakeStore) {
	st.prefs[prefKey("", "in_app", alertCreatedEvent)] = &domain.Preference{
		TenantID: "tenant-1", UserID: "", Channel: "in_app", EventType: alertCreatedEvent, Enabled: false,
	}
}

func TestNotifyForAlertHighIsAlwaysSent(t *testing.T) {
	svc, st := newSvc()
	disablePref(st) // even with a disabling preference, high severity must be sent.

	n, err := svc.NotifyForAlert(context.Background(), alertEvent(types.SeverityHigh))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Status != "sent" {
		t.Fatalf("expected high-severity alert to be sent, got status %q", n.Status)
	}
	if n.Channel != "in_app" {
		t.Fatalf("expected in_app channel, got %q", n.Channel)
	}
	if n.SentAt == nil {
		t.Fatalf("expected sent_at to be set")
	}
	if n.ReferenceType == nil || *n.ReferenceType != "alert" {
		t.Fatalf("expected reference_type alert, got %v", n.ReferenceType)
	}
	if n.ReferenceID == nil || *n.ReferenceID != "alert-1" {
		t.Fatalf("expected reference_id alert-1, got %v", n.ReferenceID)
	}
}

func TestNotifyForAlertCriticalIsAlwaysSent(t *testing.T) {
	svc, st := newSvc()
	disablePref(st)

	n, err := svc.NotifyForAlert(context.Background(), alertEvent(types.SeverityCritical))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Status != "sent" {
		t.Fatalf("expected critical-severity alert to be sent, got status %q", n.Status)
	}
}

func TestNotifyForAlertLowWithDisablingPreferenceIsSuppressed(t *testing.T) {
	svc, st := newSvc()
	disablePref(st)

	n, err := svc.NotifyForAlert(context.Background(), alertEvent(types.SeverityLow))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Status != "suppressed" {
		t.Fatalf("expected suppressed status for disabled low alert, got %q", n.Status)
	}
	if n.SentAt != nil {
		t.Fatalf("suppressed notification should not have sent_at")
	}
	// Still recorded and queryable.
	if _, ok := st.notifications[n.ID]; !ok {
		t.Fatalf("suppressed notification should still be stored")
	}
}

func TestNotifyForAlertLowWithNoPreferenceIsSent(t *testing.T) {
	svc, _ := newSvc()

	n, err := svc.NotifyForAlert(context.Background(), alertEvent(types.SeverityLow))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Status != "sent" {
		t.Fatalf("expected sent status when no preference exists, got %q", n.Status)
	}
}

func TestMarkReadSetsRead(t *testing.T) {
	svc, _ := newSvc()
	n, err := svc.NotifyForAlert(context.Background(), alertEvent(types.SeverityHigh))
	if err != nil {
		t.Fatalf("notify: %v", err)
	}
	if err := svc.MarkRead(context.Background(), "tenant-1", n.ID); err != nil {
		t.Fatalf("mark read: %v", err)
	}
	got, err := svc.GetNotification(context.Background(), "tenant-1", n.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ReadAt == nil {
		t.Fatalf("expected read_at to be set after MarkRead")
	}

	if err := svc.MarkRead(context.Background(), "tenant-1", "missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for missing notification, got %v", err)
	}
}

func TestCreateNotificationValidation(t *testing.T) {
	svc, _ := newSvc()

	// Bad channel.
	if _, err := svc.CreateNotification(context.Background(), "tenant-1", CreateNotificationInput{
		Channel: "carrier_pigeon", EventType: "alert.created",
	}); !IsValidation(err) {
		t.Fatalf("expected validation error for bad channel, got %v", err)
	}

	// Missing event_type.
	if _, err := svc.CreateNotification(context.Background(), "tenant-1", CreateNotificationInput{
		Channel: "in_app",
	}); !IsValidation(err) {
		t.Fatalf("expected validation error for missing event_type, got %v", err)
	}
}

func TestCreateNotificationInAppIsSent(t *testing.T) {
	svc, _ := newSvc()
	n, err := svc.CreateNotification(context.Background(), "tenant-1", CreateNotificationInput{
		Channel: "in_app", EventType: "system.message",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n.Status != "sent" || n.SentAt == nil {
		t.Fatalf("expected in_app to be sent with sent_at, got status %q sent_at %v", n.Status, n.SentAt)
	}
}

func TestCreateNotificationEmailIsPending(t *testing.T) {
	svc, _ := newSvc()
	n, err := svc.CreateNotification(context.Background(), "tenant-1", CreateNotificationInput{
		Channel: "email", EventType: "system.message",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if n.Status != "pending" {
		t.Fatalf("expected email channel to be pending, got %q", n.Status)
	}
}
