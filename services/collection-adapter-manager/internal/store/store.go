// Package store is the Collection Adapter Manager's data-access layer over the
// platform_services collection_adapters and collection_run_events tables. All
// tenant-scoped operations run inside DB.WithTenant so the tenant_isolation RLS
// policy applies.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/domain"
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
	db  *database.DB
	log *slog.Logger
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db, log: slog.Default()} }

// WithLogger returns a copy of the Store that logs through log. It is used by the
// consumer path so that skipped (unresolvable) run events are visible.
func (s *Store) WithLogger(log *slog.Logger) *Store {
	if log == nil {
		return s
	}
	return &Store{db: s.db, log: log}
}

// Migrate applies the Collection Adapter Manager schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_adapters")
}

const adapterCols = `id, tenant_id, module, adapter_type, name, status, schedule_cron, config_ref,
	last_run_at, last_status, last_error, findings_last_run, created_at, updated_at, created_by, updated_by`

func scanAdapter(row pgx.Row) (*domain.Adapter, error) {
	var a domain.Adapter
	err := row.Scan(&a.ID, &a.TenantID, &a.Module, &a.AdapterType, &a.Name, &a.Status,
		&a.ScheduleCron, &a.ConfigRef, &a.LastRunAt, &a.LastStatus, &a.LastError, &a.FindingsLastRun,
		&a.CreatedAt, &a.UpdatedAt, &a.CreatedBy, &a.UpdatedBy)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateAdapter inserts an adapter and returns the stored row. A unique-constraint
// violation on (tenant_id, module, name) is reported as ErrConflict.
func (s *Store) CreateAdapter(ctx context.Context, a *domain.Adapter) (*domain.Adapter, error) {
	var out *domain.Adapter
	err := s.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.collection_adapters
			   (tenant_id, module, adapter_type, name, schedule_cron, config_ref, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			 RETURNING id`,
			a.TenantID, a.Module, a.AdapterType, a.Name, a.ScheduleCron, a.ConfigRef, actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		out, err = scanAdapter(tx.QueryRow(ctx,
			`SELECT `+adapterCols+` FROM platform_services.collection_adapters WHERE id = $1`, id))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create adapter: %w", err)
	}
	return out, nil
}

// GetAdapter returns one adapter by id.
func (s *Store) GetAdapter(ctx context.Context, tenantID, id string) (*domain.Adapter, error) {
	var out *domain.Adapter
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanAdapter(tx.QueryRow(ctx,
			`SELECT `+adapterCols+` FROM platform_services.collection_adapters WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get adapter: %w", err)
	}
	return out, nil
}

// GetAdapterBySourceID returns one adapter by its id within the given tenant. It is
// the lookup the consumer uses to resolve the source_adapter_id carried in
// collection.job.* events. ErrNotFound is returned when the id does not resolve.
func (s *Store) GetAdapterBySourceID(ctx context.Context, tenantID, adapterID string) (*domain.Adapter, error) {
	return s.GetAdapter(ctx, tenantID, adapterID)
}

// ListAdapters returns adapters matching the filter, newest first.
func (s *Store) ListAdapters(ctx context.Context, tenantID string, fil domain.AdapterFilter) ([]domain.Adapter, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Module != "" {
		add("module = $%d", fil.Module)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.collection_adapters %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, adapterCols, clause, len(args)-1, len(args))

	var adapters []domain.Adapter
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			a, err := scanAdapter(rows)
			if err != nil {
				return err
			}
			adapters = append(adapters, *a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list adapters: %w", err)
	}
	return adapters, nil
}

// UpdateAdapter applies a partial update of the mutable presentation fields
// (config_ref, schedule_cron). Only non-nil fields are changed.
func (s *Store) UpdateAdapter(ctx context.Context, tenantID, id string, scheduleCron, configRef *string) error {
	sets := []string{"updated_by = $2"}
	args := []any{id, actor(ctx)}
	if scheduleCron != nil {
		args = append(args, *scheduleCron)
		sets = append(sets, fmt.Sprintf("schedule_cron = $%d", len(args)))
	}
	if configRef != nil {
		args = append(args, *configRef)
		sets = append(sets, fmt.Sprintf("config_ref = $%d", len(args)))
	}
	query := fmt.Sprintf("UPDATE platform_services.collection_adapters SET %s WHERE id = $1", strings.Join(sets, ", "))
	return s.exec(ctx, tenantID, query, args...)
}

// SetStatus sets an adapter's lifecycle status.
func (s *Store) SetStatus(ctx context.Context, tenantID, id, status string) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.collection_adapters SET status = $2, updated_by = $3 WHERE id = $1`,
		id, status, actor(ctx))
}

// RecordRun updates an adapter's health from a reported collection run AND appends
// an immutable run-event row, atomically. A failed run sets the adapter status to
// 'error'; a completed run leaves the lifecycle status untouched. last_error is set
// to detail only for a failed run, and cleared on a completed run.
func (s *Store) RecordRun(ctx context.Context, tenantID, adapterID, module, outcome string, findingsIngested, errorsCount *int, detail string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return s.recordRunTx(ctx, tx, tenantID, adapterID, module, outcome, findingsIngested, errorsCount, detail)
	})
}

// RecordRunByAdapterID is the consumer entry point: it runs RecordRun inside the
// event's own tenant context. When adapterID does not resolve to an adapter row the
// run is logged and skipped rather than erroring, so a stray event cannot stall the
// consumer.
func (s *Store) RecordRunByAdapterID(ctx context.Context, tenantID, adapterID, module, outcome string, findingsIngested, errorsCount *int, detail string) error {
	if tenantID == "" || adapterID == "" {
		s.log.WarnContext(ctx, "skip collection run event missing tenant or adapter id",
			slog.String("tenant_id", tenantID), slog.String("adapter_id", adapterID))
		return nil
	}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		return s.recordRunTx(ctx, tx, tenantID, adapterID, module, outcome, findingsIngested, errorsCount, detail)
	})
	if errors.Is(err, ErrNotFound) {
		s.log.WarnContext(ctx, "skip collection run event for unknown adapter",
			slog.String("tenant_id", tenantID), slog.String("adapter_id", adapterID), slog.String("outcome", outcome))
		return nil
	}
	if err != nil {
		return fmt.Errorf("record run: %w", err)
	}
	return nil
}

// recordRunTx performs the adapter health update and the run-event append inside an
// existing tenant transaction.
func (s *Store) recordRunTx(ctx context.Context, tx pgx.Tx, tenantID, adapterID, module, outcome string, findingsIngested, errorsCount *int, detail string) error {
	var lastError *string
	statusClause := ""
	if outcome == "failed" {
		if detail != "" {
			lastError = &detail
		}
		statusClause = ", status = 'error'"
	}
	tag, err := tx.Exec(ctx, fmt.Sprintf(
		`UPDATE platform_services.collection_adapters
		    SET last_run_at = NOW(), last_status = $2, last_error = $3, findings_last_run = $4, updated_by = $5%s
		  WHERE id = $1`, statusClause),
		adapterID, outcome, lastError, findingsIngested, actor(ctx))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO platform_services.collection_run_events
		   (tenant_id, adapter_id, job_id, module, outcome, findings_ingested, errors_count, detail)
		 VALUES ($1,$2,NULL,$3,$4,$5,$6,$7)`,
		tenantID, adapterID, nullify(module), outcome, findingsIngested, errorsCount, nullify(detail))
	return err
}

// ListRuns returns the run history for an adapter, newest first.
func (s *Store) ListRuns(ctx context.Context, tenantID, adapterID string) ([]domain.RunEvent, error) {
	var out []domain.RunEvent
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, adapter_id, job_id, module, outcome, findings_ingested, errors_count, detail, occurred_at
			   FROM platform_services.collection_run_events WHERE adapter_id = $1 ORDER BY occurred_at DESC`, adapterID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.RunEvent
			if err := rows.Scan(&e.ID, &e.TenantID, &e.AdapterID, &e.JobID, &e.Module, &e.Outcome,
				&e.FindingsIngested, &e.ErrorsCount, &e.Detail, &e.OccurredAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	return out, nil
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

// WithActor returns a context carrying the acting user id for created_by/updated_by
// columns.
func WithActor(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, actorKey{}, userID)
}

func actor(ctx context.Context) any {
	if v, ok := ctx.Value(actorKey{}).(string); ok && v != "" {
		return v
	}
	return nil
}

func nullify(s string) any {
	if s == "" {
		return nil
	}
	return s
}
