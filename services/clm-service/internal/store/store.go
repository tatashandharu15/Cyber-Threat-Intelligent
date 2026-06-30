// Package store is the CLM service's data-access layer over the monitoring_clm
// schema. All tenant-scoped operations run inside DB.WithTenant so RLS applies.
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
	"github.com/siberindo/cti/services/clm-service/internal/domain"
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

// Migrate applies the CLM schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "monitoring_clm.schema_migrations")
}

const findingCols = `id, tenant_id, credential_type, masked_indicator, masking_policy_version,
	severity, status, confidence_score::float8, breach_source_id, job_run_id, breach_name,
	dedup_key, affected_user_count, user_correlation_state, prior_severity, severity_override_reason,
	suppression_reason, suppressed_at, created_at, updated_at,
	COALESCE((SELECT array_agg(fa.asset_id::text) FROM monitoring_clm.finding_assets fa WHERE fa.finding_id = f.id), '{}') AS asset_ids`

func scanFinding(row pgx.Row) (*domain.Finding, error) {
	var f domain.Finding
	err := row.Scan(&f.ID, &f.TenantID, &f.CredentialType, &f.MaskedIndicator, &f.MaskingPolicyVersion,
		&f.Severity, &f.Status, &f.ConfidenceScore, &f.BreachSourceID, &f.JobRunID, &f.BreachName,
		&f.DedupKey, &f.AffectedUserCount, &f.UserCorrelationState, &f.PriorSeverity, &f.SeverityOverrideReason,
		&f.SuppressionReason, &f.SuppressedAt, &f.CreatedAt, &f.UpdatedAt, &f.AssetIDs)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// CreateFinding inserts a finding and links any asset ids. Returns the stored row.
func (s *Store) CreateFinding(ctx context.Context, f *domain.Finding) (*domain.Finding, error) {
	var out *domain.Finding
	err := s.db.WithTenant(ctx, f.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO monitoring_clm.findings
			   (tenant_id, credential_type, masked_indicator, masking_policy_version, severity, status,
			    confidence_score, breach_source_id, breach_name, dedup_key, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11)
			 RETURNING id`,
			f.TenantID, f.CredentialType, f.MaskedIndicator, f.MaskingPolicyVersion, f.Severity, f.Status,
			f.ConfidenceScore, f.BreachSourceID, f.BreachName, f.DedupKey, actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		for _, assetID := range f.AssetIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO monitoring_clm.finding_assets (finding_id, asset_id, tenant_id, linked_by)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				id, assetID, f.TenantID, actor(ctx)); err != nil {
				return err
			}
		}
		out, err = scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM monitoring_clm.findings f WHERE id = $1`, id))
		return err
	})
	if err != nil {
		if errors.Is(err, ErrConflict) {
			return nil, ErrConflict
		}
		return nil, fmt.Errorf("create finding: %w", err)
	}
	return out, nil
}

// GetFinding returns one finding by id.
func (s *Store) GetFinding(ctx context.Context, tenantID, id string) (*domain.Finding, error) {
	var out *domain.Finding
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM monitoring_clm.findings f WHERE id = $1`, id))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get finding: %w", err)
	}
	return out, nil
}

// ListFindings returns findings matching the filter.
func (s *Store) ListFindings(ctx context.Context, tenantID string, fil domain.FindingFilter) ([]domain.Finding, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Status != "" {
		add("status = $%d", fil.Status)
	}
	if fil.CredentialType != "" {
		add("credential_type = $%d", fil.CredentialType)
	}
	if fil.Severity != "" {
		add("severity = $%d", fil.Severity)
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
	query := fmt.Sprintf(`SELECT %s FROM monitoring_clm.findings f %s
		ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		findingCols, clause, len(args)-1, len(args))

	var findings []domain.Finding
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			f, err := scanFinding(rows)
			if err != nil {
				return err
			}
			findings = append(findings, *f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	return findings, nil
}

// UpdateStatus sets a finding status and appends a history row, atomically.
func (s *Store) UpdateStatus(ctx context.Context, tenantID, id, status string) error {
	return s.mutateWithHistory(ctx, tenantID, id, "status", status)
}

// Escalate marks a finding escalated and records history.
func (s *Store) Escalate(ctx context.Context, tenantID, id string) error {
	return s.UpdateStatus(ctx, tenantID, id, "escalated")
}

// Suppress sets suppression fields and records history.
func (s *Store) Suppress(ctx context.Context, tenantID, id, reason string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_clm.findings WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_clm.findings
			    SET status='suppressed', suppression_reason=$2, suppressed_by=$3, suppressed_at=NOW(), updated_by=$3
			  WHERE id=$1`, id, reason, actor(ctx)); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "status", oldStatus, "suppressed", actor(ctx))
	})
}

// OverrideSeverity preserves the prior severity and records history.
func (s *Store) OverrideSeverity(ctx context.Context, tenantID, id, severity, reason string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldSeverity string
		err := tx.QueryRow(ctx, `SELECT severity FROM monitoring_clm.findings WHERE id = $1`, id).Scan(&oldSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_clm.findings
			    SET severity=$2, prior_severity=$3, severity_overridden_by=$4, severity_override_reason=$5, updated_by=$4
			  WHERE id=$1`, id, severity, oldSeverity, actor(ctx), reason); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "severity", oldSeverity, severity, actor(ctx))
	})
}

func (s *Store) mutateWithHistory(ctx context.Context, tenantID, id, field, newValue string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldValue string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_clm.findings WHERE id = $1`, id).Scan(&oldValue)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_clm.findings SET status=$2, updated_by=$3 WHERE id=$1`,
			id, newValue, actor(ctx)); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, field, oldValue, newValue, actor(ctx))
	})
}

func appendHistory(ctx context.Context, tx pgx.Tx, tenantID, findingID, field, oldVal, newVal string, changedBy any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO monitoring_clm.finding_history (tenant_id, finding_id, changed_field, old_value, new_value, changed_by)
		 VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, findingID, field, oldVal, newVal, changedBy)
	return err
}

// AddAffectedUsers links correlated affected users to a finding and updates the
// finding's affected_user_count and user_correlation_state, atomically (CLM-FR-007).
// emailsMasked must already be masked (CLM-BR-001).
func (s *Store) AddAffectedUsers(ctx context.Context, tenantID, findingID string, emailsMasked []string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM monitoring_clm.findings WHERE id = $1)`, findingID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		for _, email := range emailsMasked {
			if _, err := tx.Exec(ctx,
				`INSERT INTO monitoring_clm.affected_users (tenant_id, finding_id, email_masked)
				 VALUES ($1,$2,$3)`, tenantID, findingID, email); err != nil {
				return err
			}
		}
		var count int
		if err := tx.QueryRow(ctx,
			`SELECT COUNT(*) FROM monitoring_clm.affected_users WHERE finding_id = $1`, findingID).Scan(&count); err != nil {
			return err
		}
		_, err = tx.Exec(ctx,
			`UPDATE monitoring_clm.findings
			    SET affected_user_count=$2, user_correlation_state='completed', updated_by=$3
			  WHERE id=$1`, findingID, count, actor(ctx))
		return err
	})
}

// AddEvidence inserts an immutable evidence record.
func (s *Store) AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error) {
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		meta := e.Metadata
		if len(meta) == 0 {
			meta = []byte("{}")
		}
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_clm.evidence
			   (tenant_id, finding_id, evidence_type, content_hash, storage_ref, metadata)
			 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, captured_at`,
			e.TenantID, e.FindingID, e.EvidenceType, e.ContentHash, e.StorageRef, meta).
			Scan(&e.ID, &e.CapturedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("add evidence: %w", err)
	}
	return e, nil
}

// ListEvidence returns evidence for a finding.
func (s *Store) ListEvidence(ctx context.Context, tenantID, findingID string) ([]domain.Evidence, error) {
	var out []domain.Evidence
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, finding_id, evidence_type, content_hash, storage_ref, captured_at, metadata
			   FROM monitoring_clm.evidence WHERE finding_id = $1 ORDER BY captured_at DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.Evidence
			if err := rows.Scan(&e.ID, &e.TenantID, &e.FindingID, &e.EvidenceType, &e.ContentHash,
				&e.StorageRef, &e.CapturedAt, &e.Metadata); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list evidence: %w", err)
	}
	return out, nil
}

// ListSources returns CLM breach sources.
func (s *Store) ListSources(ctx context.Context, tenantID string) ([]domain.BreachSource, error) {
	var out []domain.BreachSource
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, source_name, source_tier, adapter_type, status, last_run_at, created_at
			   FROM monitoring_clm.breach_sources ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c domain.BreachSource
			if err := rows.Scan(&c.ID, &c.TenantID, &c.SourceName, &c.SourceTier, &c.AdapterType,
				&c.Status, &c.LastRunAt, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	return out, nil
}

// CreateSource inserts a CLM breach source.
func (s *Store) CreateSource(ctx context.Context, c *domain.BreachSource) (*domain.BreachSource, error) {
	err := s.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_clm.breach_sources (tenant_id, source_name, source_tier, adapter_type, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$5) RETURNING id, status, created_at`,
			c.TenantID, c.SourceName, c.SourceTier, c.AdapterType, actor(ctx)).
			Scan(&c.ID, &c.Status, &c.CreatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("create source: %w", err)
	}
	return c, nil
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
