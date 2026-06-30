// Package store is the Reporting service's data-access layer over the
// platform_services.reports table. All tenant-scoped operations run inside
// DB.WithTenant so the tenant_isolation RLS policy applies.
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
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/reporting-service/internal/domain"
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

// Migrate applies the Reporting schema migrations, recording applied versions in
// the reporting service's own ledger table.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_reporting")
}

const reportCols = `id, tenant_id, report_type, title, status, parameters, output_ref,
	output_format, requested_by, generated_at, expires_at, failure_reason, created_at, updated_at`

func scanReport(row pgx.Row) (*domain.Report, error) {
	var r domain.Report
	err := row.Scan(&r.ID, &r.TenantID, &r.ReportType, &r.Title, &r.Status, &r.Parameters,
		&r.OutputRef, &r.OutputFormat, &r.RequestedBy, &r.GeneratedAt, &r.ExpiresAt,
		&r.FailureReason, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// CreateReport inserts a report in the 'queued' state and returns the stored row.
func (s *Store) CreateReport(ctx context.Context, r *domain.Report) (*domain.Report, error) {
	var out *domain.Report
	err := s.db.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		params := r.Parameters
		if len(params) == 0 {
			params = []byte("{}")
		}
		var id string
		if err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.reports
			   (tenant_id, report_type, title, status, parameters, output_format, requested_by)
			 VALUES ($1,$2,$3,'queued',$4,$5,$6)
			 RETURNING id`,
			r.TenantID, r.ReportType, r.Title, params, r.OutputFormat, r.RequestedBy).Scan(&id); err != nil {
			return err
		}
		var err error
		out, err = scanReport(tx.QueryRow(ctx,
			`SELECT `+reportCols+` FROM platform_services.reports WHERE id = $1`, id))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create report: %w", err)
	}
	return out, nil
}

// GetReport returns one report by id.
func (s *Store) GetReport(ctx context.Context, tenantID, id string) (*domain.Report, error) {
	var out *domain.Report
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanReport(tx.QueryRow(ctx,
			`SELECT `+reportCols+` FROM platform_services.reports WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get report: %w", err)
	}
	return out, nil
}

// ListReports returns reports matching the filter, newest first.
func (s *Store) ListReports(ctx context.Context, tenantID string, fil domain.ReportFilter) ([]domain.Report, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.ReportType != "" {
		add("report_type = $%d", fil.ReportType)
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.reports %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		reportCols, clause, len(args)-1, len(args))

	var reports []domain.Report
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rowsq, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rowsq.Close()
		for rowsq.Next() {
			r, err := scanReport(rowsq)
			if err != nil {
				return err
			}
			reports = append(reports, *r)
		}
		return rowsq.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list reports: %w", err)
	}
	return reports, nil
}

// MarkGenerating transitions a report to the 'generating' state.
func (s *Store) MarkGenerating(ctx context.Context, tenantID, id string) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.reports SET status='generating' WHERE id=$1`, id)
}

// MarkComplete records a successful generation: the output reference, the
// generated_at timestamp, and the 'complete' status.
func (s *Store) MarkComplete(ctx context.Context, tenantID, id, outputRef string, generatedAt time.Time) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.reports
		    SET status='complete', output_ref=$2, generated_at=$3, failure_reason=NULL
		  WHERE id=$1`, id, outputRef, generatedAt)
}

// MarkFailed records a failed generation with its reason.
func (s *Store) MarkFailed(ctx context.Context, tenantID, id, reason string) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.reports SET status='failed', failure_reason=$2 WHERE id=$1`,
		id, reason)
}

func (s *Store) exec(ctx context.Context, tenantID, sql string, args ...any) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// actorKey is the context key under which the API layer stores the acting user id.
type actorKey struct{}

// WithActor returns a context carrying the acting user id for requested_by columns.
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

// Actor returns the acting user id stored on ctx, or "".
func Actor(ctx context.Context) string {
	if v, ok := ctx.Value(actorKey{}).(string); ok {
		return v
	}
	return ""
}
