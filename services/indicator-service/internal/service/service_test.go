package service

import (
	"context"
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/indicator-service/internal/domain"
	"github.com/siberindo/cti/services/indicator-service/internal/store"
)

// fakeStore is an in-memory Store for unit tests. It models the
// (tenant_id, indicator_type, value) dedup key so the upsert path returns
// inserted=false on re-observation.
type fakeStore struct {
	byID    map[string]*domain.Indicator
	byDedup map[string]string // dedup key -> id
	seq     int
}

func newFakeStore() *fakeStore {
	return &fakeStore{byID: map[string]*domain.Indicator{}, byDedup: map[string]string{}}
}

func dedupKey(ind *domain.Indicator) string {
	return ind.TenantID + "|" + ind.IndicatorType + "|" + ind.Value
}

func (f *fakeStore) UpsertIndicator(_ context.Context, ind *domain.Indicator) (*domain.Indicator, bool, error) {
	key := dedupKey(ind)
	if id, ok := f.byDedup[key]; ok {
		existing := f.byID[id]
		existing.TLPMarking = ind.TLPMarking
		existing.Tags = ind.Tags
		return existing, false, nil
	}
	f.seq++
	ind.ID = "indicator-" + itoa(f.seq)
	f.byID[ind.ID] = ind
	f.byDedup[key] = ind.ID
	return ind, true, nil
}
func (f *fakeStore) GetIndicator(_ context.Context, _, id string) (*domain.Indicator, error) {
	if ind, ok := f.byID[id]; ok {
		return ind, nil
	}
	return nil, ErrNotFound
}
func (f *fakeStore) ListIndicators(_ context.Context, _ string, _ domain.IndicatorFilter) ([]domain.Indicator, error) {
	out := []domain.Indicator{}
	for _, ind := range f.byID {
		out = append(out, *ind)
	}
	return out, nil
}
func (f *fakeStore) UpdateIndicator(_ context.Context, _, id string, upd store.IndicatorUpdate) (*domain.Indicator, error) {
	ind, ok := f.byID[id]
	if !ok {
		return nil, ErrNotFound
	}
	if upd.TLPMarking != nil {
		ind.TLPMarking = *upd.TLPMarking
	}
	if upd.Confidence != nil {
		ind.Confidence = upd.Confidence
	}
	if upd.Tags != nil {
		ind.Tags = *upd.Tags
	}
	if upd.ExpiresAt != nil {
		ind.ExpiresAt = upd.ExpiresAt
	}
	return ind, nil
}
func (f *fakeStore) DeleteIndicator(_ context.Context, _, id string) error {
	if _, ok := f.byID[id]; !ok {
		return ErrNotFound
	}
	delete(f.byID, id)
	return nil
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

func validInput() RegisterIndicatorInput {
	return RegisterIndicatorInput{
		IndicatorType: "domain", Value: "evil.example.com", TLPMarking: "TLP:AMBER",
	}
}

func TestRegisterIndicatorPublishes(t *testing.T) {
	svc, _, pub := newSvc()
	ind, err := svc.RegisterIndicator(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ind.TLPMarking != "TLP:AMBER" {
		t.Fatalf("expected TLP:AMBER, got %s", ind.TLPMarking)
	}
	if len(pub.events) != 1 || pub.events[0].topic != types.TopicIndicatorCreated {
		t.Fatalf("expected one indicator.created event, got %+v", pub.events)
	}
	ev, ok := pub.events[0].value.(types.IndicatorCreated)
	if !ok || ev.IndicatorID != ind.ID || ev.IndicatorType != "domain" {
		t.Fatalf("unexpected event payload: %+v", pub.events[0].value)
	}
}

func TestRegisterDuplicateDoesNotPublishAgain(t *testing.T) {
	svc, _, pub := newSvc()
	first, err := svc.RegisterIndicator(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("first register: %v", err)
	}
	second, err := svc.RegisterIndicator(context.Background(), "tenant-1", validInput())
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("expected upsert to return same id, got %s and %s", first.ID, second.ID)
	}
	if len(pub.events) != 1 {
		t.Fatalf("expected exactly one event after duplicate register, got %d: %+v", len(pub.events), pub.events)
	}
}

func TestRegisterIndicatorValidation(t *testing.T) {
	svc, _, _ := newSvc()
	cases := []func(*RegisterIndicatorInput){
		func(in *RegisterIndicatorInput) { in.IndicatorType = "bogus" },
		func(in *RegisterIndicatorInput) { in.Value = "" },
		func(in *RegisterIndicatorInput) { in.TLPMarking = "TLP:PURPLE" },
		func(in *RegisterIndicatorInput) { c := 1.5; in.Confidence = &c },
	}
	for i, mut := range cases {
		in := validInput()
		mut(&in)
		if _, err := svc.RegisterIndicator(context.Background(), "tenant-1", in); !IsValidation(err) {
			t.Fatalf("case %d: expected validation error, got %v", i, err)
		}
	}
}

func TestRegisterIndicatorDefaultsTLP(t *testing.T) {
	svc, _, pub := newSvc()
	in := validInput()
	in.TLPMarking = ""
	ind, err := svc.RegisterIndicator(context.Background(), "tenant-1", in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ind.TLPMarking != string(types.TLPAmber) {
		t.Fatalf("expected default TLP:AMBER, got %s", ind.TLPMarking)
	}
	ev := pub.events[0].value.(types.IndicatorCreated)
	if ev.TLP != types.TLPAmber {
		t.Fatalf("expected event TLP:AMBER, got %s", ev.TLP)
	}
}
