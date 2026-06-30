package service

import (
	"context"
	"testing"

	"github.com/siberindo/cti/services/attack-reference-service/internal/domain"
)

// fakeStore is an in-memory Store for unit tests, keyed by technique_id.
type fakeStore struct {
	techniques map[string]*domain.Technique
}

func newFakeStore() *fakeStore {
	return &fakeStore{techniques: map[string]*domain.Technique{}}
}

func (f *fakeStore) UpsertTechnique(_ context.Context, t *domain.Technique) (*domain.Technique, error) {
	cp := *t
	if cp.ID == "" {
		cp.ID = "id-" + cp.TechniqueID
	}
	f.techniques[cp.TechniqueID] = &cp
	return &cp, nil
}

func (f *fakeStore) GetByTechniqueID(_ context.Context, techniqueID string) (*domain.Technique, error) {
	if t, ok := f.techniques[techniqueID]; ok {
		return t, nil
	}
	return nil, ErrNotFound
}

func (f *fakeStore) ListTechniques(_ context.Context, fil domain.TechniqueFilter) ([]domain.Technique, error) {
	out := []domain.Technique{}
	for _, t := range f.techniques {
		if fil.Tactic != "" && !contains(t.TacticRefs, fil.Tactic) {
			continue
		}
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeStore) Count(_ context.Context) (int, error) {
	return len(f.techniques), nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func newSvc() (*Service, *fakeStore) {
	st := newFakeStore()
	return New(st, nil), st
}

func TestSyncUpsertsValidTechniques(t *testing.T) {
	svc, st := newSvc()
	in := []domain.Technique{
		{TechniqueID: "T1566", Name: "Phishing", TacticRefs: []string{"initial-access"}},
		{TechniqueID: "T1566.001", Name: "Spearphishing Attachment", IsSubtechnique: true, ParentTechniqueID: ptr("T1566")},
	}
	n, err := svc.Sync(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 inserted, got %d", n)
	}
	if _, ok := st.techniques["T1566"]; !ok {
		t.Fatalf("expected T1566 to be stored")
	}
	if _, ok := st.techniques["T1566.001"]; !ok {
		t.Fatalf("expected T1566.001 to be stored")
	}
}

func TestSyncUpsertOverwrites(t *testing.T) {
	svc, st := newSvc()
	if _, err := svc.Sync(context.Background(), []domain.Technique{
		{TechniqueID: "T1078", Name: "Old Name"},
	}); err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if _, err := svc.Sync(context.Background(), []domain.Technique{
		{TechniqueID: "T1078", Name: "Valid Accounts"},
	}); err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if got := st.techniques["T1078"].Name; got != "Valid Accounts" {
		t.Fatalf("expected upsert to overwrite name, got %q", got)
	}
	if len(st.techniques) != 1 {
		t.Fatalf("expected upsert (not duplicate), got %d rows", len(st.techniques))
	}
}

func TestSyncRejectsInvalidTechniqueID(t *testing.T) {
	svc, st := newSvc()
	_, err := svc.Sync(context.Background(), []domain.Technique{
		{TechniqueID: "X1", Name: "Bogus"},
	})
	if !IsValidation(err) {
		t.Fatalf("expected validation error for bad technique_id, got %v", err)
	}
	if len(st.techniques) != 0 {
		t.Fatalf("expected nothing stored on validation failure, got %d", len(st.techniques))
	}
}

func TestSyncRejectsEmptyName(t *testing.T) {
	svc, _ := newSvc()
	_, err := svc.Sync(context.Background(), []domain.Technique{
		{TechniqueID: "T1566", Name: ""},
	})
	if !IsValidation(err) {
		t.Fatalf("expected validation error for empty name, got %v", err)
	}
}

func TestSyncRejectsEmptyBatch(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.Sync(context.Background(), nil); !IsValidation(err) {
		t.Fatalf("expected validation error for empty batch, got %v", err)
	}
}

func TestSeedDefaults(t *testing.T) {
	svc, st := newSvc()
	n, err := svc.SeedDefaults(context.Background())
	if err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	want := len(defaultTechniques())
	if n != want {
		t.Fatalf("expected %d seeded, got %d", want, n)
	}
	if got, _ := st.Count(context.Background()); got != want {
		t.Fatalf("expected %d techniques stored, got %d", want, got)
	}
	if _, ok := st.techniques["T1566"]; !ok {
		t.Fatalf("expected built-in set to include T1566 Phishing")
	}
	// A sub-technique must be marked and linked to its parent.
	sub := st.techniques["T1566.001"]
	if sub == nil || !sub.IsSubtechnique || sub.ParentTechniqueID == nil || *sub.ParentTechniqueID != "T1566" {
		t.Fatalf("expected T1566.001 to be a sub-technique of T1566, got %+v", sub)
	}
}

func TestSeedDefaultsIsIdempotent(t *testing.T) {
	svc, st := newSvc()
	if _, err := svc.SeedDefaults(context.Background()); err != nil {
		t.Fatalf("first seed: %v", err)
	}
	if _, err := svc.SeedDefaults(context.Background()); err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if got, _ := st.Count(context.Background()); got != len(defaultTechniques()) {
		t.Fatalf("expected re-seed to upsert in place, got %d rows", got)
	}
}

func TestGetTechniquePassthrough(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.SeedDefaults(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := svc.GetTechnique(context.Background(), "T1486")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "Data Encrypted for Impact" {
		t.Fatalf("unexpected name: %q", got.Name)
	}
	if _, err := svc.GetTechnique(context.Background(), "T9999"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound for missing technique, got %v", err)
	}
}

func TestListTechniquesPassthrough(t *testing.T) {
	svc, _ := newSvc()
	if _, err := svc.SeedDefaults(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	all, err := svc.ListTechniques(context.Background(), domain.TechniqueFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != len(defaultTechniques()) {
		t.Fatalf("expected %d techniques, got %d", len(defaultTechniques()), len(all))
	}
	exfil, err := svc.ListTechniques(context.Background(), domain.TechniqueFilter{Tactic: "exfiltration"})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	for _, tq := range exfil {
		if !contains(tq.TacticRefs, "exfiltration") {
			t.Fatalf("tactic filter leaked %s", tq.TechniqueID)
		}
	}
	if len(exfil) == 0 {
		t.Fatalf("expected at least one exfiltration technique in the seed set")
	}
}
