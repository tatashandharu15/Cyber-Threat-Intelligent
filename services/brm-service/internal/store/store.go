// Package store is the BRM service's data-access layer over the monitoring_brm
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
	"github.com/siberindo/cti/services/brm-service/internal/domain"
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

// Migrate applies the BRM schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "monitoring_brm.schema_migrations")
}

const findingCols = `id, tenant_id, finding_type, title, severity, status,
	confidence_score::float8, similarity_score::float8, similarity_algorithm_version,
	candidate_value, source_id, job_run_id, dedup_key, whois_snapshot, registration_date,
	social_platform_id, social_account_handle, social_profile_url,
	app_store_id, app_platform, app_listing_url, app_package_id,
	prior_severity, severity_override_reason, suppression_reason, suppressed_at,
	created_at, updated_at,
	COALESCE((SELECT array_agg(fa.asset_id::text) FROM monitoring_brm.finding_assets fa WHERE fa.finding_id = f.id), '{}') AS asset_ids`

func scanFinding(row pgx.Row) (*domain.Finding, error) {
	var f domain.Finding
	err := row.Scan(&f.ID, &f.TenantID, &f.FindingType, &f.Title, &f.Severity, &f.Status,
		&f.ConfidenceScore, &f.SimilarityScore, &f.SimilarityAlgorithmVersion,
		&f.CandidateValue, &f.SourceID, &f.JobRunID, &f.DedupKey, &f.WhoisSnapshot, &f.RegistrationDate,
		&f.SocialPlatformID, &f.SocialAccountHandle, &f.SocialProfileURL,
		&f.AppStoreID, &f.AppPlatform, &f.AppListingURL, &f.AppPackageID,
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
		whois := f.WhoisSnapshot
		if len(whois) == 0 {
			whois = nil
		}
		var id string
		err := tx.QueryRow(ctx,
			`INSERT INTO monitoring_brm.findings
			   (tenant_id, finding_type, title, severity, status, confidence_score,
			    similarity_score, similarity_algorithm_version, candidate_value,
			    source_id, dedup_key, whois_snapshot, registration_date,
			    social_platform_id, social_account_handle, social_profile_url,
			    app_store_id, app_platform, app_listing_url, app_package_id,
			    created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$21)
			 RETURNING id`,
			f.TenantID, f.FindingType, f.Title, f.Severity, f.Status, f.ConfidenceScore,
			f.SimilarityScore, f.SimilarityAlgorithmVersion, f.CandidateValue,
			f.SourceID, f.DedupKey, whois, f.RegistrationDate,
			f.SocialPlatformID, f.SocialAccountHandle, f.SocialProfileURL,
			f.AppStoreID, f.AppPlatform, f.AppListingURL, f.AppPackageID,
			actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		for _, assetID := range f.AssetIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO monitoring_brm.finding_assets (finding_id, asset_id, tenant_id, linked_by)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				id, assetID, f.TenantID, actor(ctx)); err != nil {
				return err
			}
		}
		out, err = scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM monitoring_brm.findings f WHERE id = $1`, id))
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
			`SELECT `+findingCols+` FROM monitoring_brm.findings f WHERE id = $1`, id))
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
	query := fmt.Sprintf(`SELECT %s FROM monitoring_brm.findings f %s
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
	return s.mutateStatus(ctx, tenantID, id, status)
}

// Escalate marks a finding escalated and records history.
func (s *Store) Escalate(ctx context.Context, tenantID, id string) error {
	return s.UpdateStatus(ctx, tenantID, id, "escalated")
}

// InitiateTakedown sets a finding to takedown_initiated and records history.
func (s *Store) InitiateTakedown(ctx context.Context, tenantID, id string) error {
	return s.UpdateStatus(ctx, tenantID, id, "takedown_initiated")
}

// Suppress sets suppression fields and records history.
func (s *Store) Suppress(ctx context.Context, tenantID, id, reason string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldStatus string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_brm.findings WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_brm.findings
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
		err := tx.QueryRow(ctx, `SELECT severity FROM monitoring_brm.findings WHERE id = $1`, id).Scan(&oldSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_brm.findings
			    SET severity=$2, prior_severity=$3, severity_overridden_by=$4, severity_override_reason=$5, updated_by=$4
			  WHERE id=$1`, id, severity, oldSeverity, actor(ctx), reason); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "severity", oldSeverity, severity, actor(ctx))
	})
}

func (s *Store) mutateStatus(ctx context.Context, tenantID, id, newValue string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldValue string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_brm.findings WHERE id = $1`, id).Scan(&oldValue)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_brm.findings SET status=$2, updated_by=$3 WHERE id=$1`,
			id, newValue, actor(ctx)); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "status", oldValue, newValue, actor(ctx))
	})
}

func appendHistory(ctx context.Context, tx pgx.Tx, tenantID, findingID, field, oldVal, newVal string, changedBy any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO monitoring_brm.finding_history (tenant_id, finding_id, changed_field, old_value, new_value, changed_by)
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
			`INSERT INTO monitoring_brm.evidence
			   (tenant_id, finding_id, evidence_type, content_hash, storage_ref, metadata)
			 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id, capture_timestamp`,
			e.TenantID, e.FindingID, e.EvidenceType, e.ContentHash, e.StorageRef, meta).
			Scan(&e.ID, &e.CaptureTimestamp)
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
			`SELECT id, tenant_id, finding_id, evidence_type, storage_ref, content_hash, capture_timestamp, metadata
			   FROM monitoring_brm.evidence WHERE finding_id = $1 ORDER BY capture_timestamp DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.Evidence
			if err := rows.Scan(&e.ID, &e.TenantID, &e.FindingID, &e.EvidenceType, &e.StorageRef,
				&e.ContentHash, &e.CaptureTimestamp, &e.Metadata); err != nil {
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

// ListSources returns BRM collection sources.
func (s *Store) ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error) {
	var out []domain.CollectionSource
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, source_type, display_name, status, last_run_at, created_at
			   FROM monitoring_brm.collection_sources ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c domain.CollectionSource
			if err := rows.Scan(&c.ID, &c.TenantID, &c.SourceType, &c.DisplayName, &c.Status, &c.LastRunAt, &c.CreatedAt); err != nil {
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

// CreateSource inserts a BRM collection source.
func (s *Store) CreateSource(ctx context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error) {
	err := s.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_brm.collection_sources (tenant_id, source_type, display_name, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$4) RETURNING id, status, created_at`,
			c.TenantID, c.SourceType, c.DisplayName, actor(ctx)).
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
