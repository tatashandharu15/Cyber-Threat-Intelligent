package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/siberindo/cti/services/asset-service/internal/domain"
	"github.com/siberindo/cti/services/asset-service/internal/store"
)

// fakeStore is an in-memory Store for unit tests. It implements just enough of the
// asset lifecycle to exercise the service's business rules without a database.
type fakeStore struct {
	assets   map[string]*domain.Asset
	linkages map[string]*domain.DirectoryLinkage
	seq      int
}

func newFakeStore() *fakeStore {
	return &fakeStore{assets: map[string]*domain.Asset{}, linkages: map[string]*domain.DirectoryLinkage{}}
}

func (f *fakeStore) ListAssets(_ context.Context, tenantID string, fl store.AssetFilters) ([]domain.Asset, error) {
	var out []domain.Asset
	for _, a := range f.assets {
		if a.TenantID != tenantID {
			continue
		}
		if fl.AssetType != "" && a.AssetType != fl.AssetType {
			continue
		}
		if fl.Status != "" && a.Status != fl.Status {
			continue
		}
		if fl.Criticality != "" && a.Criticality != fl.Criticality {
			continue
		}
		if fl.ApprovalStatus != "" && a.ApprovalStatus != fl.ApprovalStatus {
			continue
		}
		out = append(out, *a)
	}
	return out, nil
}

func (f *fakeStore) GetAsset(_ context.Context, tenantID, id string) (*domain.Asset, error) {
	a, ok := f.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeStore) CreateAsset(_ context.Context, tenantID string, a *domain.Asset, createdBy string) (*domain.Asset, error) {
	for _, ex := range f.assets {
		if ex.TenantID == tenantID && ex.Value == a.Value && ex.AssetType == a.AssetType {
			return nil, store.ErrConflict
		}
	}
	f.seq++
	cp := *a
	cp.ID = "asset-" + itoa(f.seq)
	cp.TenantID = tenantID
	if createdBy != "" {
		cb := createdBy
		cp.CreatedBy = &cb
		cp.UpdatedBy = &cb
	}
	cp.CreatedAt = time.Now()
	cp.UpdatedAt = cp.CreatedAt
	f.assets[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (f *fakeStore) UpdateAsset(_ context.Context, tenantID, id, displayName, criticality, status string) (*domain.Asset, error) {
	a, ok := f.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	if displayName != "" {
		dn := displayName
		a.DisplayName = &dn
	}
	if criticality != "" {
		a.Criticality = criticality
	}
	if status != "" {
		a.Status = status
	}
	out := *a
	return &out, nil
}

func (f *fakeStore) ApproveAsset(_ context.Context, tenantID, id, approvedBy string) (*domain.Asset, error) {
	a, ok := f.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	a.ApprovalStatus = "approved"
	if approvedBy != "" {
		ab := approvedBy
		a.ApprovedBy = &ab
	}
	now := time.Now()
	a.ApprovedAt = &now
	if a.Status == "pending_approval" {
		a.Status = "active"
	}
	out := *a
	return &out, nil
}

func (f *fakeStore) SetAssetStatus(_ context.Context, tenantID, id, status string) (*domain.Asset, error) {
	a, ok := f.assets[id]
	if !ok || a.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	a.Status = status
	out := *a
	return &out, nil
}

func (f *fakeStore) UpsertDirectoryLinkage(_ context.Context, tenantID, assetID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	a, ok := f.assets[assetID]
	if !ok || a.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	l := &domain.DirectoryLinkage{
		ID: "link-" + assetID, TenantID: tenantID, AssetID: assetID,
		DirectoryType: dirType, DirectoryRef: dirRef, Status: "active",
	}
	f.linkages[assetID] = l
	out := *l
	return &out, nil
}

func (f *fakeStore) GetDirectoryLinkage(_ context.Context, tenantID, assetID string) (*domain.DirectoryLinkage, error) {
	l, ok := f.linkages[assetID]
	if !ok || l.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	out := *l
	return &out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

const tenant = "tenant-1"

func newTestService() (*Service, *fakeStore) {
	fs := newFakeStore()
	return New(fs), fs
}

func TestCreateBrandKeywordEntersApprovalGate(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "brand_keyword", Value: "siberindo",
	}, "actor-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ApprovalStatus != "pending" {
		t.Fatalf("expected approval_status=pending, got %q", a.ApprovalStatus)
	}
	if a.Status != "pending_approval" {
		t.Fatalf("expected status=pending_approval, got %q", a.Status)
	}
}

func TestCreateDomainIsApprovedAndActive(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "domain", Value: "siberindo.io",
	}, "actor-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.ApprovalStatus != "approved" {
		t.Fatalf("expected approval_status=approved, got %q", a.ApprovalStatus)
	}
	if a.Status != "active" {
		t.Fatalf("expected status=active, got %q", a.Status)
	}
	if a.Criticality != "medium" {
		t.Fatalf("expected default criticality=medium, got %q", a.Criticality)
	}
}

func TestApprovePendingKeywordActivatesIt(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "brand_keyword", Value: "siberindo",
	}, "actor-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	approved, err := svc.ApproveAsset(context.Background(), tenant, a.ID, "approver-1")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.ApprovalStatus != "approved" {
		t.Fatalf("expected approval_status=approved, got %q", approved.ApprovalStatus)
	}
	if approved.Status != "active" {
		t.Fatalf("expected status=active after approval, got %q", approved.Status)
	}
	if approved.ApprovedBy == nil || *approved.ApprovedBy != "approver-1" {
		t.Fatalf("expected approved_by=approver-1, got %v", approved.ApprovedBy)
	}
}

func TestApproveAlreadyApprovedReturnsValidation(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "domain", Value: "siberindo.io",
	}, "actor-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = svc.ApproveAsset(context.Background(), tenant, a.ID, "approver-1")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation approving an already-approved asset, got %v", err)
	}
}

func TestCreateInvalidAssetType(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "not_a_type", Value: "x",
	}, "actor-1")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for invalid asset_type, got %v", err)
	}
}

func TestCreateEmptyValue(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "domain", Value: "   ",
	}, "actor-1")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for empty value, got %v", err)
	}
}

func TestCreateInvalidCriticality(t *testing.T) {
	svc, _ := newTestService()
	_, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "domain", Value: "siberindo.io", Criticality: "extreme",
	}, "actor-1")
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for invalid criticality, got %v", err)
	}
}

func TestCreateDuplicateReturnsConflict(t *testing.T) {
	svc, _ := newTestService()
	in := CreateInput{AssetType: "domain", Value: "siberindo.io"}
	if _, err := svc.CreateAsset(context.Background(), tenant, in, "actor-1"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := svc.CreateAsset(context.Background(), tenant, in, "actor-1")
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate value+type, got %v", err)
	}
}

func TestPauseResumeDecommissionKeepRecord(t *testing.T) {
	svc, fs := newTestService()
	a, err := svc.CreateAsset(context.Background(), tenant, CreateInput{
		AssetType: "domain", Value: "siberindo.io",
	}, "actor-1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if got, _ := svc.PauseAsset(context.Background(), tenant, a.ID); got.Status != "paused" {
		t.Fatalf("expected paused, got %q", got.Status)
	}
	if got, _ := svc.ResumeAsset(context.Background(), tenant, a.ID); got.Status != "active" {
		t.Fatalf("expected active, got %q", got.Status)
	}
	if got, _ := svc.DecommissionAsset(context.Background(), tenant, a.ID); got.Status != "decommissioned" {
		t.Fatalf("expected decommissioned, got %q", got.Status)
	}
	if _, ok := fs.assets[a.ID]; !ok {
		t.Fatal("decommission must keep the record, not delete it")
	}
}
