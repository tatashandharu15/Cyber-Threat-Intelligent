// Package store is the DWM service's data-access layer over the monitoring_dwm
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
	"github.com/siberindo/cti/services/dwm-service/internal/domain"
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

// Migrate applies the DWM schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "monitoring_dwm.schema_migrations")
}

const findingCols = `id, tenant_id, finding_type, title, severity, status,
	confidence_score::float8, source_tier_id, job_run_id, dedup_key,
	content_excerpt, content_hash, content_url_defanged, observed_at, submission_type,
	prior_severity, severity_override_reason, suppression_reason, suppressed_at,
	created_at, updated_at,
	COALESCE((SELECT array_agg(fa.asset_id::text) FROM monitoring_dwm.finding_assets fa WHERE fa.finding_id = f.id), '{}') AS asset_ids`

func scanFinding(row pgx.Row) (*domain.Finding, error) {
	var f domain.Finding
	err := row.Scan(&f.ID, &f.TenantID, &f.FindingType, &f.Title, &f.Severity, &f.Status,
		&f.ConfidenceScore, &f.SourceTierID, &f.JobRunID, &f.DedupKey,
		&f.ContentExcerpt, &f.ContentHash, &f.ContentURLDefanged, &f.ObservedAt, &f.SubmissionType,
		&f.PriorSeverity, &f.SeverityOverrideReason, &f.SuppressionReason, &f.SuppressedAt,
		&f.CreatedAt, &f.UpdatedAt, &f.AssetIDs)
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// CreateFinding inserts a finding and links any asset ids. Returns the stored row.
func (s *Store) CreateFinding(ctx context.Context, f *domain.Finding) (*domain.Finding, error) {
	var out *domain.Finding
	err := s.db.WithTenant(ctx, f.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		submissionType := f.SubmissionType
		if submissionType == "" {
			submissionType = "automated"
		}
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO monitoring_dwm.findings
			   (tenant_id, finding_type, title, severity, status, confidence_score,
			    source_tier_id, dedup_key, content_excerpt, content_hash,
			    content_url_defanged, observed_at, submission_type, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)
			 RETURNING id`,
			f.TenantID, f.FindingType, f.Title, f.Severity, f.Status, f.ConfidenceScore,
			f.SourceTierID, f.DedupKey, f.ContentExcerpt, f.ContentHash,
			f.ContentURLDefanged, f.ObservedAt, submissionType, actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		for _, assetID := range f.AssetIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO monitoring_dwm.finding_assets (finding_id, asset_id, tenant_id, linked_by)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				id, assetID, f.TenantID, actor(ctx)); err != nil {
				return err
			}
		}
		out, err = scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM monitoring_dwm.findings f WHERE id = $1`, id))
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
			`SELECT `+findingCols+` FROM monitoring_dwm.findings f WHERE id = $1`, id))
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
	if fil.FindingType != "" {
		add("finding_type = $%d", fil.FindingType)
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
	query := fmt.Sprintf(`SELECT %s FROM monitoring_dwm.findings f %s
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
	return s.mutateStatusWithHistory(ctx, tenantID, id, status)
}

// Escalate marks a finding escalated and records history.
func (s *Store) Escalate(ctx context.Context, tenantID, id string) error {
	return s.UpdateStatus(ctx, tenantID, id, "escalated")
}

// Suppress sets suppression fields and records history.
func (s *Store) Suppress(ctx context.Context, tenantID, id, reason string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_dwm.findings WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_dwm.findings
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
		err := tx.QueryRow(ctx, `SELECT severity FROM monitoring_dwm.findings WHERE id = $1`, id).Scan(&oldSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_dwm.findings
			    SET severity=$2, prior_severity=$3, severity_overridden_by=$4, severity_override_reason=$5, updated_by=$4
			  WHERE id=$1`, id, severity, oldSeverity, actor(ctx), reason); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "severity", oldSeverity, severity, actor(ctx))
	})
}

func (s *Store) mutateStatusWithHistory(ctx context.Context, tenantID, id, newStatus string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_dwm.findings WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_dwm.findings SET status=$2, updated_by=$3 WHERE id=$1`,
			id, newStatus, actor(ctx)); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "status", oldStatus, newStatus, actor(ctx))
	})
}

func appendHistory(ctx context.Context, tx pgx.Tx, tenantID, findingID, field, oldVal, newVal string, changedBy any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO monitoring_dwm.finding_history (tenant_id, finding_id, changed_field, old_value, new_value, changed_by)
		 VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, findingID, field, oldVal, newVal, changedBy)
	return err
}

// AddEvidence inserts an immutable evidence record.
func (s *Store) AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error) {
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		meta := e.Metadata
		if len(meta) == 0 {
			meta = []byte("{}")
		}
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_dwm.evidence
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
			   FROM monitoring_dwm.evidence WHERE finding_id = $1 ORDER BY captured_at DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.Evidence
			if err := rows.Scan(&e.ID, &e.TenantID, &e.FindingID, &e.EvidenceType,
				&e.ContentHash, &e.StorageRef, &e.CapturedAt, &e.Metadata); err != nil {
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

// CreateThreatActor inserts a threat actor profile. identity_confirmed is never set
// here: it defaults false and may only be set by an explicit analyst confirmation
// (DWM-BR-002).
func (s *Store) CreateThreatActor(ctx context.Context, a *domain.ThreatActorProfile) (*domain.ThreatActorProfile, error) {
	err := s.db.WithTenant(ctx, a.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_dwm.threat_actor_profiles
			   (tenant_id, codename, description, aliases, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$5)
			 RETURNING id, identity_confirmed, status, created_at, updated_at`,
			a.TenantID, a.Codename, a.Description, a.Aliases, actor(ctx)).
			Scan(&a.ID, &a.IdentityConfirmed, &a.Status, &a.CreatedAt, &a.UpdatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("create threat actor: %w", err)
	}
	return a, nil
}

// ListThreatActors returns threat actor profiles for a tenant.
func (s *Store) ListThreatActors(ctx context.Context, tenantID string) ([]domain.ThreatActorProfile, error) {
	var out []domain.ThreatActorProfile
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, codename, description, identity_confirmed, aliases, tactics, status, created_at, updated_at
			   FROM monitoring_dwm.threat_actor_profiles ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a domain.ThreatActorProfile
			if err := rows.Scan(&a.ID, &a.TenantID, &a.Codename, &a.Description, &a.IdentityConfirmed,
				&a.Aliases, &a.Tactics, &a.Status, &a.CreatedAt, &a.UpdatedAt); err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list threat actors: %w", err)
	}
	return out, nil
}

// LinkThreatActor records an explicit, analyst-confirmed link between a finding and
// a threat actor profile. confirmedBy and justification are mandatory (DWM-FR-013).
func (s *Store) LinkThreatActor(ctx context.Context, tenantID, findingID, actorID, confirmedBy, justification string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Ensure both the finding and the threat actor profile exist in this tenant.
		var exists bool
		err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM monitoring_dwm.findings WHERE id = $1)`, findingID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		err = tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM monitoring_dwm.threat_actor_profiles WHERE id = $1)`, actorID).Scan(&exists)
		if err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO monitoring_dwm.finding_threat_actor_links
			   (finding_id, threat_actor_id, tenant_id, confirmed_by, justification)
			 VALUES ($1,$2,$3,$4,$5)`,
			findingID, actorID, tenantID, confirmedBy, justification)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		return nil
	})
}

// AddEnrichment records structured analyst threat context for a finding (DWM-FR-014).
func (s *Store) AddEnrichment(ctx context.Context, e *domain.Enrichment) (*domain.Enrichment, error) {
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM monitoring_dwm.findings WHERE id = $1)`, e.FindingID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_dwm.finding_enrichments
			   (tenant_id, finding_id, tactics_observed, affected_asset_scope, response_indicators, enriched_by)
			 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, enriched_at`,
			e.TenantID, e.FindingID, e.TacticsObserved, e.AffectedAssetScope, e.ResponseIndicators, actor(ctx)).
			Scan(&e.ID, &e.EnrichedAt)
	})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("add enrichment: %w", err)
	}
	return e, nil
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
