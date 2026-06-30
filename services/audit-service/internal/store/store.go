// Package store is the Audit Log service's data-access layer over the
// platform_services.audit_events table. All tenant-scoped operations run inside
// DB.WithTenant so the tenant_isolation RLS policy applies.
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
	"github.com/siberindo/cti/services/audit-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when an audit event does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the Audit Log schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_audit")
}

const auditCols = `id, tenant_id, actor_id, actor_type, event_type, resource_type, resource_id::text,
	action, outcome, ip_address::text, user_agent, request_id::text, event_payload, hmac_signature, created_at`

func scanEvent(row pgx.Row) (*domain.AuditEvent, error) {
	var e domain.AuditEvent
	err := row.Scan(&e.ID, &e.TenantID, &e.ActorID, &e.ActorType, &e.EventType, &e.ResourceType, &e.ResourceID,
		&e.Action, &e.Outcome, &e.IPAddress, &e.UserAgent, &e.RequestID, &e.EventPayload, &e.HMACSignature, &e.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// Insert persists an audit event exactly as supplied, including the caller-provided
// created_at and hmac_signature (the DB defaults for those columns are intentionally
// bypassed so the stored values match what was signed). Returns the stored row.
func (s *Store) Insert(ctx context.Context, e *domain.AuditEvent) (*domain.AuditEvent, error) {
	var out *domain.AuditEvent
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		payload := e.EventPayload
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		var err error
		out, err = scanEvent(tx.QueryRow(ctx,
			`INSERT INTO platform_services.audit_events
			   (tenant_id, actor_id, actor_type, event_type, resource_type, resource_id,
			    action, outcome, ip_address, user_agent, request_id, event_payload,
			    hmac_signature, created_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
			 RETURNING `+auditCols,
			e.TenantID, e.ActorID, e.ActorType, e.EventType, e.ResourceType, e.ResourceID,
			e.Action, e.Outcome, e.IPAddress, e.UserAgent, e.RequestID, payload,
			e.HMACSignature, e.CreatedAt))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("insert audit event: %w", err)
	}
	return out, nil
}

// Get returns one audit event by id.
func (s *Store) Get(ctx context.Context, tenantID, id string) (*domain.AuditEvent, error) {
	var out *domain.AuditEvent
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanEvent(tx.QueryRow(ctx,
			`SELECT `+auditCols+` FROM platform_services.audit_events WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get audit event: %w", err)
	}
	return out, nil
}

// List returns audit events matching the filter, newest first.
func (s *Store) List(ctx context.Context, tenantID string, fil domain.AuditFilter) ([]domain.AuditEvent, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.EventType != "" {
		add("event_type = $%d", fil.EventType)
	}
	if fil.ResourceType != "" {
		add("resource_type = $%d", fil.ResourceType)
	}
	if fil.ActorID != "" {
		add("actor_id = $%d", fil.ActorID)
	}
	if fil.Outcome != "" {
		add("outcome = $%d", fil.Outcome)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.audit_events %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		auditCols, clause, len(args)-1, len(args))

	var events []domain.AuditEvent
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanEvent(rows)
			if err != nil {
				return err
			}
			events = append(events, *e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	return events, nil
}
