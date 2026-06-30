// Package store is the Alert Engine's data-access layer over the platform_services
// alerts and alert_rules tables. All operations run inside DB.WithTenant so RLS
// applies.
package store

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/alert-engine/internal/domain"
	"github.com/siberindo/cti/services/alert-engine/internal/rules"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the Alert Engine schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations")
}

// ListActiveRules returns the active rules for a tenant as evaluation-ready
// rules.Rule values (conditions JSONB parsed).
func (s *Store) ListActiveRules(ctx context.Context, tenantID string) ([]rules.Rule, error) {
	var out []rules.Rule
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rowsq, err := tx.Query(ctx,
			`SELECT id, tenant_id, name, COALESCE(source_module, ''), conditions, status
			   FROM platform_services.alert_rules WHERE status = 'active'`)
		if err != nil {
			return err
		}
		defer rowsq.Close()
		for rowsq.Next() {
			var r rules.Rule
			var conditions []byte
			if err := rowsq.Scan(&r.ID, &r.TenantID, &r.Name, &r.SourceModule, &conditions, &r.Status); err != nil {
				return err
			}
			if len(conditions) > 0 {
				if err := json.Unmarshal(conditions, &r.Conditions); err != nil {
					return fmt.Errorf("parse conditions for rule %s: %w", r.ID, err)
				}
			}
			out = append(out, r)
		}
		return rowsq.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list active rules: %w", err)
	}
	return out, nil
}

// CreateAlert inserts an alert and returns the stored row.
func (s *Store) CreateAlert(ctx context.Context, a *domain.Alert) (*domain.Alert, error) {
	err := s.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO platform_services.alerts
			   (tenant_id, alert_rule_id, source_module, source_finding_id, title, description, severity, status)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,'open')
			 RETURNING id, status, created_at, updated_at`,
			a.TenantID, a.AlertRuleID, a.SourceModule, a.SourceFindingID, a.Title, a.Description, a.Severity).
			Scan(&a.ID, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("create alert: %w", err)
	}
	return a, nil
}

const alertCols = `id, tenant_id, alert_rule_id, source_module, source_finding_id, correlation_id,
	title, description, severity, status, acknowledged_by, acknowledged_at, resolved_by, resolved_at,
	created_at, updated_at`

func scanAlert(row pgx.Row) (*domain.Alert, error) {
	var a domain.Alert
	err := row.Scan(&a.ID, &a.TenantID, &a.AlertRuleID, &a.SourceModule, &a.SourceFindingID, &a.CorrelationID,
		&a.Title, &a.Description, &a.Severity, &a.Status, &a.AcknowledgedBy, &a.AcknowledgedAt,
		&a.ResolvedBy, &a.ResolvedAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ListAlerts returns alerts matching the filter.
func (s *Store) ListAlerts(ctx context.Context, tenantID string, fil domain.AlertFilter) ([]domain.Alert, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
	}
	if fil.Severity != "" {
		add("severity = $%d", fil.Severity)
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
	query := fmt.Sprintf(`SELECT %s FROM platform_services.alerts %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, alertCols, clause, len(args)-1, len(args))

	var alerts []domain.Alert
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rowsq, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rowsq.Close()
		for rowsq.Next() {
			a, err := scanAlert(rowsq)
			if err != nil {
				return err
			}
			alerts = append(alerts, *a)
		}
		return rowsq.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	return alerts, nil
}

// GetAlert returns one alert.
func (s *Store) GetAlert(ctx context.Context, tenantID, id string) (*domain.Alert, error) {
	var out *domain.Alert
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanAlert(tx.QueryRow(ctx,
			`SELECT `+alertCols+` FROM platform_services.alerts WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get alert: %w", err)
	}
	return out, nil
}

// Acknowledge marks an alert acknowledged.
func (s *Store) Acknowledge(ctx context.Context, tenantID, id, actorID string) error {
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.alerts
		    SET status='acknowledged', acknowledged_by=$2, acknowledged_at=NOW()
		  WHERE id=$1`, id, actorID)
}

// UpdateStatus sets an alert status, recording resolution metadata when relevant.
func (s *Store) UpdateStatus(ctx context.Context, tenantID, id, status, actorID string) error {
	if status == "resolved" || status == "closed" {
		return s.exec(ctx, tenantID,
			`UPDATE platform_services.alerts
			    SET status=$3, resolved_by=$2, resolved_at=NOW() WHERE id=$1`, id, actorID, status)
	}
	return s.exec(ctx, tenantID,
		`UPDATE platform_services.alerts SET status=$2 WHERE id=$1`, id, status)
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

// ListRules returns all alert rules for a tenant.
func (s *Store) ListRules(ctx context.Context, tenantID string) ([]domain.AlertRule, error) {
	var out []domain.AlertRule
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rowsq, err := tx.Query(ctx,
			`SELECT id, tenant_id, name, description, source_module, conditions, status, webhook_url, created_at, updated_at
			   FROM platform_services.alert_rules ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rowsq.Close()
		for rowsq.Next() {
			var r domain.AlertRule
			var conditions []byte
			if err := rowsq.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.SourceModule,
				&conditions, &r.Status, &r.WebhookURL, &r.CreatedAt, &r.UpdatedAt); err != nil {
				return err
			}
			if len(conditions) > 0 {
				_ = json.Unmarshal(conditions, &r.Conditions)
			}
			out = append(out, r)
		}
		return rowsq.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	return out, nil
}

// CreateRule inserts an alert rule.
func (s *Store) CreateRule(ctx context.Context, r *domain.AlertRule, actorID string) (*domain.AlertRule, error) {
	conditions, _ := json.Marshal(r.Conditions)
	err := s.db.WithTenant(ctx, r.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO platform_services.alert_rules
			   (tenant_id, name, description, source_module, conditions, webhook_url, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			 RETURNING id, status, created_at, updated_at`,
			r.TenantID, r.Name, r.Description, r.SourceModule, conditions, r.WebhookURL, nullify(actorID)).
			Scan(&r.ID, &r.Status, &r.CreatedAt, &r.UpdatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("create rule: %w", err)
	}
	return r, nil
}

// UpdateRule updates mutable fields of an alert rule.
func (s *Store) UpdateRule(ctx context.Context, tenantID, id string, name, status *string, conditions *rules.Conditions, actorID string) error {
	sets := []string{"updated_by = $2"}
	args := []any{id, nullify(actorID)}
	if name != nil {
		args = append(args, *name)
		sets = append(sets, fmt.Sprintf("name = $%d", len(args)))
	}
	if status != nil {
		args = append(args, *status)
		sets = append(sets, fmt.Sprintf("status = $%d", len(args)))
	}
	if conditions != nil {
		c, _ := json.Marshal(*conditions)
		args = append(args, c)
		sets = append(sets, fmt.Sprintf("conditions = $%d", len(args)))
	}
	query := fmt.Sprintf("UPDATE platform_services.alert_rules SET %s WHERE id = $1", strings.Join(sets, ", "))
	return s.exec(ctx, tenantID, query, args...)
}

// DeleteRule removes an alert rule.
func (s *Store) DeleteRule(ctx context.Context, tenantID, id string) error {
	return s.exec(ctx, tenantID, `DELETE FROM platform_services.alert_rules WHERE id = $1`, id)
}

// Metrics returns counts of open alerts by severity for a tenant.
func (s *Store) Metrics(ctx context.Context, tenantID string) (map[string]int, error) {
	out := map[string]int{}
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rowsq, err := tx.Query(ctx,
			`SELECT severity, COUNT(*) FROM platform_services.alerts
			  WHERE status NOT IN ('resolved','closed','false_positive')
			  GROUP BY severity`)
		if err != nil {
			return err
		}
		defer rowsq.Close()
		for rowsq.Next() {
			var sev string
			var n int
			if err := rowsq.Scan(&sev, &n); err != nil {
				return err
			}
			out[sev] = n
		}
		return rowsq.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("metrics: %w", err)
	}
	return out, nil
}

func nullify(s string) any {
	if s == "" {
		return nil
	}
	return s
}
