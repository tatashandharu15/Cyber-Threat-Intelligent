// Package store is the Indicator service's data-access layer over the
// platform_services.indicators table. All tenant-scoped operations run inside
// DB.WithTenant so the RLS tenant_isolation policy applies.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/indicator-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Sentinel errors.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the Indicator schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_indicator")
}

const indicatorCols = `id, tenant_id, indicator_type, value, tlp_marking,
	confidence::float8, source_module, source_finding_id, tags,
	first_seen_at, last_seen_at, expires_at, created_at, updated_at`

func scanIndicator(row pgx.Row) (*domain.Indicator, error) {
	var ind domain.Indicator
	err := row.Scan(&ind.ID, &ind.TenantID, &ind.IndicatorType, &ind.Value, &ind.TLPMarking,
		&ind.Confidence, &ind.SourceModule, &ind.SourceFindingID, &ind.Tags,
		&ind.FirstSeenAt, &ind.LastSeenAt, &ind.ExpiresAt, &ind.CreatedAt, &ind.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &ind, nil
}

// UpsertIndicator inserts an indicator or, when one already exists for
// (tenant_id, indicator_type, value), refreshes it. The boolean return reports
// whether a NEW row was inserted (via the xmax = 0 trick) so the caller only
// publishes indicator.created on first creation.
func (s *Store) UpsertIndicator(ctx context.Context, ind *domain.Indicator) (*domain.Indicator, bool, error) {
	var out *domain.Indicator
	var inserted bool
	err := s.db.WithTenant(ctx, ind.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var ins bool
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.indicators
			   (tenant_id, indicator_type, value, tlp_marking, confidence,
			    source_module, source_finding_id, tags, expires_at, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$10)
			 ON CONFLICT (tenant_id, indicator_type, value) DO UPDATE SET
			   last_seen_at = NOW(),
			   tlp_marking = EXCLUDED.tlp_marking,
			   confidence = COALESCE(EXCLUDED.confidence, indicators.confidence),
			   tags = EXCLUDED.tags,
			   source_module = COALESCE(EXCLUDED.source_module, indicators.source_module),
			   source_finding_id = COALESCE(EXCLUDED.source_finding_id, indicators.source_finding_id),
			   expires_at = EXCLUDED.expires_at,
			   updated_by = EXCLUDED.updated_by
			 RETURNING (xmax = 0) AS inserted, id`,
			ind.TenantID, ind.IndicatorType, ind.Value, ind.TLPMarking, ind.Confidence,
			ind.SourceModule, ind.SourceFindingID, ind.Tags, ind.ExpiresAt, actor(ctx)).
			Scan(&ins, &id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		inserted = ins
		out, err = scanIndicator(tx.QueryRow(ctx,
			`SELECT `+indicatorCols+` FROM platform_services.indicators WHERE id = $1`, id))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, false, ErrConflict
		}
		return nil, false, fmt.Errorf("upsert indicator: %w", err)
	}
	return out, inserted, nil
}

// GetIndicator returns one indicator by id.
func (s *Store) GetIndicator(ctx context.Context, tenantID, id string) (*domain.Indicator, error) {
	var out *domain.Indicator
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanIndicator(tx.QueryRow(ctx,
			`SELECT `+indicatorCols+` FROM platform_services.indicators WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get indicator: %w", err)
	}
	return out, nil
}

// ListIndicators returns indicators matching the filter.
func (s *Store) ListIndicators(ctx context.Context, tenantID string, fil domain.IndicatorFilter) ([]domain.Indicator, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.IndicatorType != "" {
		add("indicator_type = $%d", fil.IndicatorType)
	}
	if fil.TLPMarking != "" {
		add("tlp_marking = $%d", fil.TLPMarking)
	}
	if fil.SourceModule != "" {
		add("source_module = $%d", fil.SourceModule)
	}
	if fil.Value != "" {
		add("value ILIKE '%%'||$%d||'%%'", fil.Value)
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}
	limit := fil.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit, fil.Offset)
	query := fmt.Sprintf(`SELECT %s FROM platform_services.indicators %s
		ORDER BY last_seen_at DESC LIMIT $%d OFFSET $%d`,
		indicatorCols, clause, len(args)-1, len(args))

	var indicators []domain.Indicator
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			ind, err := scanIndicator(rows)
			if err != nil {
				return err
			}
			indicators = append(indicators, *ind)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list indicators: %w", err)
	}
	return indicators, nil
}

// IndicatorUpdate carries the partially-updatable fields of an indicator. A nil
// pointer leaves the corresponding column unchanged.
type IndicatorUpdate struct {
	TLPMarking *string
	Confidence *float64
	Tags       *[]string
	ExpiresAt  *time.Time
}

// UpdateIndicator applies a partial update to an indicator, leaving any field
// whose pointer is nil unchanged. Returns the updated row.
func (s *Store) UpdateIndicator(ctx context.Context, tenantID, id string, upd IndicatorUpdate) (*domain.Indicator, error) {
	sets := []string{}
	args := []any{}
	add := func(col string, val any) {
		args = append(args, val)
		sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if upd.TLPMarking != nil {
		add("tlp_marking", *upd.TLPMarking)
	}
	if upd.Confidence != nil {
		add("confidence", *upd.Confidence)
	}
	if upd.Tags != nil {
		add("tags", *upd.Tags)
	}
	if upd.ExpiresAt != nil {
		add("expires_at", *upd.ExpiresAt)
	}
	if len(sets) == 0 {
		return s.GetIndicator(ctx, tenantID, id)
	}
	args = append(args, actor(ctx))
	sets = append(sets, fmt.Sprintf("updated_by = $%d", len(args)))
	args = append(args, id)
	query := fmt.Sprintf(`UPDATE platform_services.indicators SET %s WHERE id = $%d RETURNING %s`,
		strings.Join(sets, ", "), len(args), indicatorCols)

	var out *domain.Indicator
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanIndicator(tx.QueryRow(ctx, query, args...))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update indicator: %w", err)
	}
	return out, nil
}

// DeleteIndicator removes an indicator, returning ErrNotFound if absent.
func (s *Store) DeleteIndicator(ctx context.Context, tenantID, id string) error {
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM platform_services.indicators WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("delete indicator: %w", err)
	}
	return nil
}

// actorKey is the context key under which the API layer stores the acting user id.
type actorKey struct{}

// WithActor returns a context carrying the acting user id for created_by/updated_by.
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

func actor(ctx context.Context) any {
	if v, ok := ctx.Value(actorKey{}).(string); ok && v != "" {
		return v
	}
	return nil
}
