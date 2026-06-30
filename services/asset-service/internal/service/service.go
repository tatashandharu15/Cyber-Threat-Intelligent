// Package service implements the Asset service's business logic: asset
// registration with the brand-keyword approval gate (BRM-BR-001), the approval
// workflow, and lifecycle transitions (pause/resume/decommission).
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/services/asset-service/internal/domain"
	"github.com/siberindo/cti/services/asset-service/internal/store"
)

// ErrValidation is returned when input fails validation or a business rule (e.g.
// approving an asset that is not pending). The store sentinels ErrNotFound and
// ErrConflict are passed through unchanged.
var ErrValidation = errors.New("validation error")

// Re-export store sentinels so the API layer can map them without importing store.
var (
	ErrNotFound = store.ErrNotFound
	ErrConflict = store.ErrConflict
)

// allowedAssetTypes is the set of asset types the registry accepts. It mirrors the
// CHECK constraint on core_platform.assets.asset_type.
var allowedAssetTypes = map[string]bool{
	"domain":            true,
	"ip_address":        true,
	"ip_range":          true,
	"email_address":     true,
	"email_domain":      true,
	"brand_keyword":     true,
	"executive_profile": true,
	"mobile_app":        true,
	"social_handle":     true,
}

const (
	assetTypeBrandKeyword = "brand_keyword"

	approvalPending  = "pending"
	approvalApproved = "approved"

	statusActive          = "active"
	statusPaused          = "paused"
	statusDecommissioned  = "decommissioned"
	statusPendingApproval = "pending_approval"

	visibilityTenant = "tenant"
)

var allowedVisibility = map[string]bool{"tenant": true, "restricted": true}

// Store is the persistence contract the service depends on.
type Store interface {
	ListAssets(ctx context.Context, tenantID string, f store.AssetFilters) ([]domain.Asset, error)
	GetAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error)
	CreateAsset(ctx context.Context, tenantID string, a *domain.Asset, createdBy string) (*domain.Asset, error)
	UpdateAsset(ctx context.Context, tenantID, id, displayName, criticality, status string) (*domain.Asset, error)
	ApproveAsset(ctx context.Context, tenantID, id, approvedBy string) (*domain.Asset, error)
	SetAssetStatus(ctx context.Context, tenantID, id, status string) (*domain.Asset, error)
	UpsertDirectoryLinkage(ctx context.Context, tenantID, assetID, dirType, dirRef string) (*domain.DirectoryLinkage, error)
	GetDirectoryLinkage(ctx context.Context, tenantID, assetID string) (*domain.DirectoryLinkage, error)
}

// Service holds dependencies for asset operations.
type Service struct {
	store Store
}

// New constructs a Service.
func New(store Store) *Service { return &Service{store: store} }

// CreateInput carries the fields needed to register an asset.
type CreateInput struct {
	AssetType   string
	Value       string
	DisplayName string
	Criticality string
	Visibility  string
}

// ListFilters is the service-level filter struct; it maps directly onto the
// store's AssetFilters.
type ListFilters struct {
	AssetType      string
	Status         string
	Criticality    string
	ApprovalStatus string
	Limit          int
	Offset         int
}

// ListAssets returns assets matching the filters within the tenant.
func (s *Service) ListAssets(ctx context.Context, tenantID string, f ListFilters) ([]domain.Asset, error) {
	return s.store.ListAssets(ctx, tenantID, store.AssetFilters{
		AssetType:      f.AssetType,
		Status:         f.Status,
		Criticality:    f.Criticality,
		ApprovalStatus: f.ApprovalStatus,
		Limit:          f.Limit,
		Offset:         f.Offset,
	})
}

// GetAsset returns a single asset by id.
func (s *Service) GetAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error) {
	return s.store.GetAsset(ctx, tenantID, id)
}

// CreateAsset validates and registers a new asset. Brand-keyword assets enter the
// approval gate (BRM-BR-001): they start as approval_status="pending" and
// status="pending_approval" and cannot be monitored until approved. All other
// asset types default to approved+active.
func (s *Service) CreateAsset(ctx context.Context, tenantID string, in CreateInput, createdBy string) (*domain.Asset, error) {
	assetType := strings.TrimSpace(in.AssetType)
	if !allowedAssetTypes[assetType] {
		return nil, validationf("invalid asset_type: %q", in.AssetType)
	}
	value := strings.TrimSpace(in.Value)
	if value == "" {
		return nil, validationf("value is required")
	}

	criticality := strings.TrimSpace(in.Criticality)
	if criticality == "" {
		criticality = string(types.CriticalityMedium)
	}
	if !types.Criticality(criticality).Valid() {
		return nil, validationf("invalid criticality: %q", in.Criticality)
	}

	visibility := strings.TrimSpace(in.Visibility)
	if visibility == "" {
		visibility = visibilityTenant
	}
	if !allowedVisibility[visibility] {
		return nil, validationf("invalid visibility: %q", in.Visibility)
	}

	a := &domain.Asset{
		AssetType:      assetType,
		Value:          value,
		Criticality:    criticality,
		Visibility:     visibility,
		ApprovalStatus: approvalApproved,
		Status:         statusActive,
	}
	if dn := strings.TrimSpace(in.DisplayName); dn != "" {
		a.DisplayName = &dn
	}

	// BRM-BR-001 keyword approval gate.
	if assetType == assetTypeBrandKeyword {
		a.ApprovalStatus = approvalPending
		a.Status = statusPendingApproval
	}

	return s.store.CreateAsset(ctx, tenantID, a, createdBy)
}

// UpdateAsset applies editable metadata to an asset.
func (s *Service) UpdateAsset(ctx context.Context, tenantID, id, displayName, criticality, status string) (*domain.Asset, error) {
	if c := strings.TrimSpace(criticality); c != "" && !types.Criticality(c).Valid() {
		return nil, validationf("invalid criticality: %q", criticality)
	}
	if st := strings.TrimSpace(status); st != "" && !isValidStatus(st) {
		return nil, validationf("invalid status: %q", status)
	}
	return s.store.UpdateAsset(ctx, tenantID, id, displayName, criticality, status)
}

// ApproveAsset flips a pending asset to approved+active. Approving an asset that
// is not pending approval is a business-rule violation.
func (s *Service) ApproveAsset(ctx context.Context, tenantID, id, approvedBy string) (*domain.Asset, error) {
	a, err := s.store.GetAsset(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if a.ApprovalStatus != approvalPending {
		return nil, validationf("asset is not pending approval")
	}
	return s.store.ApproveAsset(ctx, tenantID, id, approvedBy)
}

// PauseAsset stops monitoring an asset without deleting it.
func (s *Service) PauseAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error) {
	return s.store.SetAssetStatus(ctx, tenantID, id, statusPaused)
}

// ResumeAsset returns a paused asset to active monitoring.
func (s *Service) ResumeAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error) {
	return s.store.SetAssetStatus(ctx, tenantID, id, statusActive)
}

// DecommissionAsset retires an asset (soft delete: the record is retained).
func (s *Service) DecommissionAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error) {
	return s.store.SetAssetStatus(ctx, tenantID, id, statusDecommissioned)
}

// SetDirectoryLinkage creates or replaces the directory linkage for an asset.
func (s *Service) SetDirectoryLinkage(ctx context.Context, tenantID, assetID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	dt := strings.TrimSpace(dirType)
	if !isValidDirectoryType(dt) {
		return nil, validationf("invalid directory_type: %q", dirType)
	}
	if strings.TrimSpace(dirRef) == "" {
		return nil, validationf("directory_ref is required")
	}
	return s.store.UpsertDirectoryLinkage(ctx, tenantID, assetID, dt, strings.TrimSpace(dirRef))
}

// GetDirectoryLinkage returns the directory linkage for an asset.
func (s *Service) GetDirectoryLinkage(ctx context.Context, tenantID, assetID string) (*domain.DirectoryLinkage, error) {
	return s.store.GetDirectoryLinkage(ctx, tenantID, assetID)
}

func isValidStatus(s string) bool {
	switch s {
	case statusActive, statusPaused, statusDecommissioned, statusPendingApproval:
		return true
	}
	return false
}

func isValidDirectoryType(s string) bool {
	switch s {
	case "azure_ad", "ldap", "okta", "manual":
		return true
	}
	return false
}

func validationf(format string, args ...any) error {
	if len(args) == 0 {
		return &ValidationError{msg: format}
	}
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// ValidationError wraps ErrValidation while carrying a human-readable message so
// the API layer can surface the cause while still matching errors.Is(err, ErrValidation).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }
func (e *ValidationError) Unwrap() error { return ErrValidation }
