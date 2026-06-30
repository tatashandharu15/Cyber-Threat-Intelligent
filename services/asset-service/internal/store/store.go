// Package store is the Asset service's data-access layer over the core_platform
// asset tables. All tenant-scoped reads and writes run inside DB.WithTenant so the
// RLS policies apply.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/asset-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Sentinel errors returned by the store and mapped to HTTP responses by the API
// layer.
var (
	// ErrNotFound is returned when a requested row does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict is returned when a unique constraint is violated (duplicate
	// value+type for the tenant).
	ErrConflict = errors.New("conflict")
)

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the asset schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "core_platform.schema_migrations_asset")
}

// AssetFilters narrows a ListAssets query. Empty string fields are ignored.
type AssetFilters struct {
	AssetType      string
	Status         string
	Criticality    string
	ApprovalStatus string
	Limit          int
	Offset         int
}

const assetColumns = `id, tenant_id, asset_type, value, display_name, criticality,
		status, approval_status, approved_by, approved_at, visibility,
		created_at, updated_at, created_by, updated_by`

// ListAssets returns assets in the tenant matching the supplied filters, newest
// first. Only the non-empty filter fields contribute to the WHERE clause.
func (s *Store) ListAssets(ctx context.Context, tenantID string, f AssetFilters) ([]domain.Asset, error) {
	var (
		conds []string
		args  []any
	)
	add := func(col, val string) {
		if val != "" {
			args = append(args, val)
			conds = append(conds, col+" = $"+strconv.Itoa(len(args)))
		}
	}
	add("asset_type", f.AssetType)
	add("status", f.Status)
	add("criticality", f.Criticality)
	add("approval_status", f.ApprovalStatus)

	query := `SELECT ` + assetColumns + ` FROM core_platform.assets`
	if len(conds) > 0 {
		query += " WHERE " + strings.Join(conds, " AND ")
	}
	query += " ORDER BY created_at DESC"

	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit)
	query += " LIMIT $" + strconv.Itoa(len(args))
	if f.Offset > 0 {
		args = append(args, f.Offset)
		query += " OFFSET $" + strconv.Itoa(len(args))
	}

	var assets []domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAsset(rows)
			if err != nil {
				return err
			}
			assets = append(assets, *a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	return assets, nil
}

// GetAsset returns a single asset by id within the tenant.
func (s *Store) GetAsset(ctx context.Context, tenantID, id string) (*domain.Asset, error) {
	var a *domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM core_platform.assets WHERE id = $1`, id)
		var scanErr error
		a, scanErr = scanAsset(row)
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get asset: %w", err)
	}
	return a, nil
}

// CreateAsset inserts a new asset, returning the persisted row. A duplicate
// value+asset_type within the tenant maps to ErrConflict.
func (s *Store) CreateAsset(ctx context.Context, tenantID string, a *domain.Asset, createdBy string) (*domain.Asset, error) {
	var out *domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`INSERT INTO core_platform.assets
			    (tenant_id, asset_type, value, display_name, criticality, status,
			     approval_status, visibility, created_by, updated_by)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
			 RETURNING `+assetColumns,
			tenantID, a.AssetType, a.Value, nullify(a.DisplayName), a.Criticality, a.Status,
			a.ApprovalStatus, a.Visibility, nullifyStr(createdBy))
		var scanErr error
		out, scanErr = scanAsset(row)
		return scanErr
	})
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("create asset: %w", err)
	}
	return out, nil
}

// UpdateAsset applies editable metadata to an asset. Empty arguments leave the
// corresponding column unchanged.
func (s *Store) UpdateAsset(ctx context.Context, tenantID, id, displayName, criticality, status string) (*domain.Asset, error) {
	var out *domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE core_platform.assets
			    SET display_name = COALESCE(NULLIF($2, ''), display_name),
			        criticality  = COALESCE(NULLIF($3, ''), criticality),
			        status       = COALESCE(NULLIF($4, ''), status)
			  WHERE id = $1
			 RETURNING `+assetColumns,
			id, displayName, criticality, status)
		var scanErr error
		out, scanErr = scanAsset(row)
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update asset: %w", err)
	}
	return out, nil
}

// ApproveAsset marks an asset approved, recording the approver and timestamp. An
// asset previously held in pending_approval is activated.
func (s *Store) ApproveAsset(ctx context.Context, tenantID, id, approvedBy string) (*domain.Asset, error) {
	var out *domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE core_platform.assets
			    SET approval_status = 'approved',
			        approved_by     = $2,
			        approved_at     = NOW(),
			        status          = CASE WHEN status = 'pending_approval' THEN 'active' ELSE status END
			  WHERE id = $1
			 RETURNING `+assetColumns,
			id, nullifyStr(approvedBy))
		var scanErr error
		out, scanErr = scanAsset(row)
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("approve asset: %w", err)
	}
	return out, nil
}

// SetAssetStatus transitions an asset's lifecycle status (pause/resume/decommission).
func (s *Store) SetAssetStatus(ctx context.Context, tenantID, id, status string) (*domain.Asset, error) {
	var out *domain.Asset
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`UPDATE core_platform.assets SET status = $2 WHERE id = $1 RETURNING `+assetColumns,
			id, status)
		var scanErr error
		out, scanErr = scanAsset(row)
		return scanErr
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("set asset status: %w", err)
	}
	return out, nil
}

// UpsertDirectoryLinkage creates or replaces the directory linkage for an asset.
// There is at most one linkage per asset.
func (s *Store) UpsertDirectoryLinkage(ctx context.Context, tenantID, assetID, dirType, dirRef string) (*domain.DirectoryLinkage, error) {
	var out *domain.DirectoryLinkage
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Ensure the asset exists (and is visible to this tenant) before linking.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM core_platform.assets WHERE id = $1)`, assetID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return pgx.ErrNoRows
		}
		if _, err := tx.Exec(ctx,
			`DELETE FROM core_platform.asset_directory_linkages WHERE asset_id = $1`, assetID); err != nil {
			return err
		}
		row := tx.QueryRow(ctx,
			`INSERT INTO core_platform.asset_directory_linkages
			    (tenant_id, asset_id, directory_type, directory_ref)
			 VALUES ($1, $2, $3, $4)
			 RETURNING id, tenant_id, asset_id, directory_type, directory_ref, status, created_at, updated_at`,
			tenantID, assetID, dirType, dirRef)
		out = &domain.DirectoryLinkage{}
		return row.Scan(&out.ID, &out.TenantID, &out.AssetID, &out.DirectoryType,
			&out.DirectoryRef, &out.Status, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("upsert directory linkage: %w", err)
	}
	return out, nil
}

// GetDirectoryLinkage returns the directory linkage for an asset.
func (s *Store) GetDirectoryLinkage(ctx context.Context, tenantID, assetID string) (*domain.DirectoryLinkage, error) {
	var out domain.DirectoryLinkage
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT id, tenant_id, asset_id, directory_type, directory_ref, status, created_at, updated_at
			   FROM core_platform.asset_directory_linkages WHERE asset_id = $1`, assetID).
			Scan(&out.ID, &out.TenantID, &out.AssetID, &out.DirectoryType,
				&out.DirectoryRef, &out.Status, &out.CreatedAt, &out.UpdatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get directory linkage: %w", err)
	}
	return &out, nil
}

// scanRow is satisfied by both pgx.Row and pgx.Rows so scanAsset can serve single
// and multi-row reads.
type scanRow interface {
	Scan(dest ...any) error
}

func scanAsset(row scanRow) (*domain.Asset, error) {
	var a domain.Asset
	if err := row.Scan(
		&a.ID, &a.TenantID, &a.AssetType, &a.Value, &a.DisplayName, &a.Criticality,
		&a.Status, &a.ApprovalStatus, &a.ApprovedBy, &a.ApprovedAt, &a.Visibility,
		&a.CreatedAt, &a.UpdatedAt, &a.CreatedBy, &a.UpdatedBy,
	); err != nil {
		return nil, err
	}
	return &a, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func nullify(s *string) any {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func nullifyStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
