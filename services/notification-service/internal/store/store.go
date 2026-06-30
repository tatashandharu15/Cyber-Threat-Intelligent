// Package store is the Notification service's data-access layer over the
// platform_services notifications and notification_preferences tables. All
// tenant-scoped operations run inside DB.WithTenant so RLS applies.
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
	"github.com/siberindo/cti/services/notification-service/internal/domain"
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

// Migrate applies the Notification schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_notification")
}

const notificationCols = `id, tenant_id, recipient_user_id, channel, event_type, subject, body,
	reference_type, reference_id, severity, status, sent_at, failure_reason, read_at, created_at`

func scanNotification(row pgx.Row) (*domain.Notification, error) {
	var n domain.Notification
	err := row.Scan(&n.ID, &n.TenantID, &n.RecipientUserID, &n.Channel, &n.EventType, &n.Subject, &n.Body,
		&n.ReferenceType, &n.ReferenceID, &n.Severity, &n.Status, &n.SentAt, &n.FailureReason, &n.ReadAt, &n.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// CreateNotification inserts a notification and returns the stored row. The
// caller is responsible for setting Status (and SentAt for already-sent
// notifications); the in_app fast path is handled in the service layer.
func (s *Store) CreateNotification(ctx context.Context, n *domain.Notification) (*domain.Notification, error) {
	channel := n.Channel
	if channel == "" {
		channel = "in_app"
	}
	status := n.Status
	if status == "" {
		status = "pending"
	}
	var out *domain.Notification
	err := s.db.WithTenant(ctx, n.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.notifications
			   (tenant_id, recipient_user_id, channel, event_type, subject, body,
			    reference_type, reference_id, severity, status, sent_at, failure_reason)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
			 RETURNING id`,
			n.TenantID, n.RecipientUserID, channel, n.EventType, n.Subject, n.Body,
			n.ReferenceType, n.ReferenceID, n.Severity, status, n.SentAt, n.FailureReason).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		out, err = scanNotification(tx.QueryRow(ctx,
			`SELECT `+notificationCols+` FROM platform_services.notifications WHERE id = $1`, id))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create notification: %w", err)
	}
	return out, nil
}

// ListNotifications returns notifications matching the filter.
func (s *Store) ListNotifications(ctx context.Context, tenantID string, fil domain.NotificationFilter) ([]domain.Notification, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
	}
	if fil.Channel != "" {
		add("channel = $%d", fil.Channel)
	}
	if fil.RecipientUserID != "" {
		add("recipient_user_id = $%d", fil.RecipientUserID)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.notifications %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		notificationCols, clause, len(args)-1, len(args))

	var out []domain.Notification
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			n, err := scanNotification(rows)
			if err != nil {
				return err
			}
			out = append(out, *n)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list notifications: %w", err)
	}
	return out, nil
}

// GetNotification returns one notification by id.
func (s *Store) GetNotification(ctx context.Context, tenantID, id string) (*domain.Notification, error) {
	var out *domain.Notification
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanNotification(tx.QueryRow(ctx,
			`SELECT `+notificationCols+` FROM platform_services.notifications WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get notification: %w", err)
	}
	return out, nil
}

// MarkRead sets read_at to NOW for a notification, returning ErrNotFound if the
// row does not exist.
func (s *Store) MarkRead(ctx context.Context, tenantID, id string) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.notifications SET read_at = NOW() WHERE id = $1`, id)
}

const preferenceCols = `id, tenant_id, user_id, channel, event_type, enabled, created_at, updated_at`

func scanPreference(row pgx.Row) (*domain.Preference, error) {
	var p domain.Preference
	err := row.Scan(&p.ID, &p.TenantID, &p.UserID, &p.Channel, &p.EventType, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// GetPreference returns the preference row for a (user, channel, event_type)
// tuple, or ErrNotFound when no explicit preference has been stored.
func (s *Store) GetPreference(ctx context.Context, tenantID, userID, channel, eventType string) (*domain.Preference, error) {
	var out *domain.Preference
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanPreference(tx.QueryRow(ctx,
			`SELECT `+preferenceCols+` FROM platform_services.notification_preferences
			   WHERE user_id = $1 AND channel = $2 AND event_type = $3`, userID, channel, eventType))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get preference: %w", err)
	}
	return out, nil
}

// UpsertPreference inserts or updates a notification preference, returning the
// stored row.
func (s *Store) UpsertPreference(ctx context.Context, p *domain.Preference) (*domain.Preference, error) {
	var out *domain.Preference
	err := s.db.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO platform_services.notification_preferences
			   (tenant_id, user_id, channel, event_type, enabled, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$6)
			 ON CONFLICT (tenant_id, user_id, channel, event_type)
			 DO UPDATE SET enabled = EXCLUDED.enabled, updated_by = EXCLUDED.updated_by
			 RETURNING id`,
			p.TenantID, p.UserID, p.Channel, p.EventType, p.Enabled, actor(ctx)).Scan(&id)
		if err != nil {
			return err
		}
		out, err = scanPreference(tx.QueryRow(ctx,
			`SELECT `+preferenceCols+` FROM platform_services.notification_preferences WHERE id = $1`, id))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("upsert preference: %w", err)
	}
	return out, nil
}

// ListPreferences returns all stored preferences for a user.
func (s *Store) ListPreferences(ctx context.Context, tenantID, userID string) ([]domain.Preference, error) {
	var out []domain.Preference
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT `+preferenceCols+` FROM platform_services.notification_preferences
			   WHERE user_id = $1 ORDER BY channel, event_type`, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanPreference(rows)
			if err != nil {
				return err
			}
			out = append(out, *p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list preferences: %w", err)
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
