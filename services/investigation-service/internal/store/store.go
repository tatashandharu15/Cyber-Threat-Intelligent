// Package store is the Investigation service's data-access layer over the
// platform_services investigation tables. All tenant-scoped operations run inside
// DB.WithTenant so RLS applies.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/investigation-service/internal/domain"
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

// Migrate applies the Investigation schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_investigation")
}

const investigationCols = `id, tenant_id, title, description, status, priority, assigned_to,
	closed_at, closed_by, created_at, updated_at, created_by, updated_by`

func scanInvestigation(row pgx.Row) (*domain.Investigation, error) {
	var inv domain.Investigation
	err := row.Scan(&inv.ID, &inv.TenantID, &inv.Title, &inv.Description, &inv.Status, &inv.Priority,
		&inv.AssignedTo, &inv.ClosedAt, &inv.ClosedBy, &inv.CreatedAt, &inv.UpdatedAt,
		&inv.CreatedBy, &inv.UpdatedBy)
	if err != nil {
		return nil, err
	}
	return &inv, nil
}

// CreateInvestigation inserts an investigation and its initial 'created' timeline
// entry atomically. Returns the stored row.
func (s *Store) CreateInvestigation(ctx context.Context, inv *domain.Investigation) (*domain.Investigation, error) {
	var out *domain.Investigation
	err := s.db.WithTenant(ctx, inv.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.investigations
			   (tenant_id, title, description, status, priority, assigned_to, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			 RETURNING id`,
			inv.TenantID, inv.Title, inv.Description, inv.Status, inv.Priority, inv.AssignedTo, actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		if err := addTimeline(ctx, tx, inv.TenantID, id, "created", "investigation created", actor(ctx)); err != nil {
			return err
		}
		out, err = scanInvestigation(tx.QueryRow(ctx,
			`SELECT `+investigationCols+` FROM platform_services.investigations WHERE id = $1`, id))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create investigation: %w", err)
	}
	return out, nil
}

// GetInvestigation returns one investigation by id.
func (s *Store) GetInvestigation(ctx context.Context, tenantID, id string) (*domain.Investigation, error) {
	var out *domain.Investigation
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanInvestigation(tx.QueryRow(ctx,
			`SELECT `+investigationCols+` FROM platform_services.investigations WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get investigation: %w", err)
	}
	return out, nil
}

// ListInvestigations returns investigations matching the filter.
func (s *Store) ListInvestigations(ctx context.Context, tenantID string, fil domain.InvestigationFilter) ([]domain.Investigation, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
	}
	if fil.Priority != "" {
		add("priority = $%d", fil.Priority)
	}
	if fil.AssignedTo != "" {
		add("assigned_to = $%d", fil.AssignedTo)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.investigations %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		investigationCols, clause, len(args)-1, len(args))

	var out []domain.Investigation
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			inv, err := scanInvestigation(rows)
			if err != nil {
				return err
			}
			out = append(out, *inv)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list investigations: %w", err)
	}
	return out, nil
}

// UpdateStatus sets an investigation status and appends a timeline entry, atomically.
func (s *Store) UpdateStatus(ctx context.Context, tenantID, id, status string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM platform_services.investigations WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE platform_services.investigations SET status=$2, updated_by=$3 WHERE id=$1`,
			id, status, actor(ctx)); err != nil {
			return err
		}
		return addTimeline(ctx, tx, tenantID, id, "status_changed",
			fmt.Sprintf("%s -> %s", oldStatus, status), actor(ctx))
	})
}

// Assign sets the assignee and appends a timeline entry, atomically.
func (s *Store) Assign(ctx context.Context, tenantID, id, assignedTo string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE platform_services.investigations SET assigned_to=$2, updated_by=$3 WHERE id=$1`,
			id, nullify(assignedTo), actor(ctx))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return addTimeline(ctx, tx, tenantID, id, "assigned",
			fmt.Sprintf("assigned to %s", assignedTo), actor(ctx))
	})
}

// AddNote appends a note timeline entry to an investigation.
func (s *Store) AddNote(ctx context.Context, tenantID, id, note string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM platform_services.investigations WHERE id = $1)`, id).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return addTimeline(ctx, tx, tenantID, id, "note", note, actor(ctx))
	})
}

// Close marks an investigation closed, records who closed it, and appends a
// timeline entry, atomically.
func (s *Store) Close(ctx context.Context, tenantID, id string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM platform_services.investigations WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE platform_services.investigations
			    SET status='closed', closed_at=NOW(), closed_by=$2, updated_by=$2 WHERE id=$1`,
			id, actor(ctx)); err != nil {
			return err
		}
		return addTimeline(ctx, tx, tenantID, id, "closed",
			fmt.Sprintf("%s -> closed", oldStatus), actor(ctx))
	})
}

// LinkFinding links a detection-module finding into an investigation, appends a
// timeline entry, and marks any matching inbox row linked, atomically.
func (s *Store) LinkFinding(ctx context.Context, lf *domain.LinkedFinding) error {
	return s.db.WithTenant(ctx, lf.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM platform_services.investigations WHERE id = $1)`,
			lf.InvestigationID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO platform_services.investigation_findings
			   (investigation_id, source_module, source_finding_id, tenant_id, notes, linked_by)
			 VALUES ($1,$2,$3,$4,$5,$6)`,
			lf.InvestigationID, lf.SourceModule, lf.SourceFindingID, lf.TenantID, lf.Notes, actor(ctx))
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE platform_services.investigation_alert_inbox
			    SET linked = TRUE
			  WHERE tenant_id = $1 AND source_module = $2 AND source_finding_id = $3`,
			lf.TenantID, lf.SourceModule, lf.SourceFindingID); err != nil {
			return err
		}
		return addTimeline(ctx, tx, lf.TenantID, lf.InvestigationID, "finding_linked",
			fmt.Sprintf("%s/%s", lf.SourceModule, lf.SourceFindingID), actor(ctx))
	})
}

// ListLinkedFindings returns the findings linked into an investigation.
func (s *Store) ListLinkedFindings(ctx context.Context, tenantID, investigationID string) ([]domain.LinkedFinding, error) {
	var out []domain.LinkedFinding
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT investigation_id, source_module, source_finding_id, tenant_id, notes, linked_at, linked_by
			   FROM platform_services.investigation_findings
			  WHERE investigation_id = $1 ORDER BY linked_at DESC`, investigationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lf domain.LinkedFinding
			if err := rows.Scan(&lf.InvestigationID, &lf.SourceModule, &lf.SourceFindingID,
				&lf.TenantID, &lf.Notes, &lf.LinkedAt, &lf.LinkedBy); err != nil {
				return err
			}
			out = append(out, lf)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list linked findings: %w", err)
	}
	return out, nil
}

// ListTimeline returns the timeline entries for an investigation.
func (s *Store) ListTimeline(ctx context.Context, tenantID, investigationID string) ([]domain.TimelineEntry, error) {
	var out []domain.TimelineEntry
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, investigation_id, entry_type, detail, actor_id, created_at
			   FROM platform_services.investigation_timeline
			  WHERE investigation_id = $1 ORDER BY created_at ASC`, investigationID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.TimelineEntry
			if err := rows.Scan(&e.ID, &e.TenantID, &e.InvestigationID, &e.EntryType,
				&e.Detail, &e.ActorID, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list timeline: %w", err)
	}
	return out, nil
}

// addTimeline inserts an immutable timeline entry within the calling transaction.
func addTimeline(ctx context.Context, tx pgx.Tx, tenantID, investigationID, entryType, detail string, actorID any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO platform_services.investigation_timeline
		   (tenant_id, investigation_id, entry_type, detail, actor_id)
		 VALUES ($1,$2,$3,$4,$5)`, tenantID, investigationID, entryType, nullify(detail), actorID)
	return err
}

// InsertInboxAlert records an alert.created event for later linkage. Duplicate
// alert ids for a tenant are ignored.
func (s *Store) InsertInboxAlert(ctx context.Context, a *domain.InboxAlert) error {
	err := s.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO platform_services.investigation_alert_inbox
			   (tenant_id, alert_id, source_module, source_finding_id, severity, title)
			 VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (tenant_id, alert_id) DO NOTHING`,
			a.TenantID, a.AlertID, a.SourceModule, a.SourceFindingID, a.Severity, a.Title)
		return err
	})
	if err != nil {
		return fmt.Errorf("insert inbox alert: %w", err)
	}
	return nil
}

// ListInbox returns the unlinked alert inbox entries for a tenant.
func (s *Store) ListInbox(ctx context.Context, tenantID string) ([]domain.InboxAlert, error) {
	var out []domain.InboxAlert
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, alert_id, source_module, source_finding_id, severity, title, linked, created_at
			   FROM platform_services.investigation_alert_inbox
			  WHERE linked = FALSE ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a domain.InboxAlert
			if err := rows.Scan(&a.ID, &a.TenantID, &a.AlertID, &a.SourceModule, &a.SourceFindingID,
				&a.Severity, &a.Title, &a.Linked, &a.CreatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list inbox: %w", err)
	}
	return out, nil
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
