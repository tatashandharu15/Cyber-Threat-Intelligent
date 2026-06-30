// Package store is the Takedown service's data-access layer over the
// platform_services schema. All tenant-scoped operations run inside DB.WithTenant
// so RLS applies.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/takedown-service/internal/domain"
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

// Migrate applies the Takedown schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_takedown")
}

const takedownCols = `id, tenant_id, source_module, source_finding_id, status,
	submission_target, submission_target_type, evidence_package_ref, requested_by,
	submitted_at, acknowledged_at, actioned_at, rejected_at, operator_response,
	closed_at, closed_by, created_at, updated_at`

func scanTakedown(row pgx.Row) (*domain.Takedown, error) {
	var t domain.Takedown
	err := row.Scan(&t.ID, &t.TenantID, &t.SourceModule, &t.SourceFindingID, &t.Status,
		&t.SubmissionTarget, &t.SubmissionTargetType, &t.EvidencePackageRef, &t.RequestedBy,
		&t.SubmittedAt, &t.AcknowledgedAt, &t.ActionedAt, &t.RejectedAt, &t.OperatorResponse,
		&t.ClosedAt, &t.ClosedBy, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// CreateTakedown inserts a takedown request in 'draft' status and records a
// 'created' event in the same transaction. Returns the stored row.
func (s *Store) CreateTakedown(ctx context.Context, t *domain.Takedown) (*domain.Takedown, error) {
	var out *domain.Takedown
	err := s.db.WithTenant(ctx, t.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.takedown_requests
			   (tenant_id, source_module, source_finding_id, status, submission_target,
			    submission_target_type, evidence_package_ref, requested_by, created_by, updated_by)
			 VALUES ($1,$2,$3,'draft',$4,$5,$6,$7,$7,$7)
			 RETURNING id`,
			t.TenantID, t.SourceModule, t.SourceFindingID, t.SubmissionTarget,
			t.SubmissionTargetType, t.EvidencePackageRef, actor(ctx)).Scan(&id)
		if err != nil {
			return err
		}
		if err := addEvent(ctx, tx, t.TenantID, id, "created", nil, actor(ctx)); err != nil {
			return err
		}
		out, err = scanTakedown(tx.QueryRow(ctx,
			`SELECT `+takedownCols+` FROM platform_services.takedown_requests WHERE id = $1`, id))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create takedown: %w", err)
	}
	return out, nil
}

// GetTakedown returns one takedown request by id.
func (s *Store) GetTakedown(ctx context.Context, tenantID, id string) (*domain.Takedown, error) {
	var out *domain.Takedown
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanTakedown(tx.QueryRow(ctx,
			`SELECT `+takedownCols+` FROM platform_services.takedown_requests WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get takedown: %w", err)
	}
	return out, nil
}

// ListTakedowns returns takedown requests matching the filter.
func (s *Store) ListTakedowns(ctx context.Context, tenantID string, fil domain.TakedownFilter) ([]domain.Takedown, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
	}
	if fil.SourceModule != "" {
		add("source_module = $%d", fil.SourceModule)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.takedown_requests %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		takedownCols, clause, len(args)-1, len(args))

	var takedowns []domain.Takedown
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTakedown(rows)
			if err != nil {
				return err
			}
			takedowns = append(takedowns, *t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list takedowns: %w", err)
	}
	return takedowns, nil
}

// Transition atomically moves a takedown to newStatus: it stamps the matching
// timestamp column, records operatorResponse when supplied, and appends an
// immutable 'status_changed' event ("old -> new") in the same transaction.
func (s *Store) Transition(ctx context.Context, tenantID, id, newStatus, operatorResponse, actorID string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx,
			`SELECT status FROM platform_services.takedown_requests WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		set := []string{"status = $2", "updated_by = $3"}
		switch newStatus {
		case "submitted":
			set = append(set, "submitted_at = NOW()")
		case "acknowledged":
			set = append(set, "acknowledged_at = NOW()")
		case "actioned":
			set = append(set, "actioned_at = NOW()")
		case "rejected":
			set = append(set, "rejected_at = NOW()")
		case "closed":
			set = append(set, "closed_at = NOW()", "closed_by = $3")
		}
		args := []any{id, newStatus, nullify(actorID)}
		if operatorResponse != "" {
			args = append(args, operatorResponse)
			set = append(set, fmt.Sprintf("operator_response = $%d", len(args)))
		}
		query := fmt.Sprintf(
			`UPDATE platform_services.takedown_requests SET %s WHERE id = $1`,
			strings.Join(set, ", "))
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			return err
		}

		detail := oldStatus + " -> " + newStatus
		return addEvent(ctx, tx, tenantID, id, "status_changed", &detail, nullify(actorID))
	})
}

// ListEvents returns the immutable accountability-chain events for a takedown.
func (s *Store) ListEvents(ctx context.Context, tenantID, takedownID string) ([]domain.TakedownEvent, error) {
	var out []domain.TakedownEvent
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, takedown_id, event_type, detail, actor_id, created_at
			   FROM platform_services.takedown_events WHERE takedown_id = $1 ORDER BY created_at ASC`, takedownID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.TakedownEvent
			if err := rows.Scan(&e.ID, &e.TenantID, &e.TakedownID, &e.EventType, &e.Detail, &e.ActorID, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return out, nil
}

// addEvent inserts an immutable takedown_events row.
func addEvent(ctx context.Context, tx pgx.Tx, tenantID, takedownID, eventType string, detail *string, actorID any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO platform_services.takedown_events (tenant_id, takedown_id, event_type, detail, actor_id)
		 VALUES ($1,$2,$3,$4,$5)`, tenantID, takedownID, eventType, detail, actorID)
	return err
}

// actorKey is the context key under which the API layer stores the acting user id.
type actorKey struct{}

// WithActor returns a context carrying the acting user id for created_by columns.
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
