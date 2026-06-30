// Package store is the PHM service's data-access layer over the monitoring_phm
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
	"github.com/siberindo/cti/services/phm-service/internal/domain"
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

// Migrate applies the PHM schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "monitoring_phm.schema_migrations")
}

const findingCols = `id, tenant_id, finding_type, title, severity, status,
	confidence_score::float8, phishing_url_defanged, host(hosting_ip), registrar,
	campaign_id, source_id, job_run_id, dedup_key, content_fingerprint,
	urgency_promoted, urgency_promoted_at, prior_severity, severity_override_reason,
	suppression_reason, suppressed_at, created_at, updated_at,
	COALESCE((SELECT array_agg(fa.asset_id::text) FROM monitoring_phm.finding_assets fa WHERE fa.finding_id = f.id), '{}') AS asset_ids`

func scanFinding(row pgx.Row) (*domain.Finding, error) {
	var f domain.Finding
	err := row.Scan(&f.ID, &f.TenantID, &f.FindingType, &f.Title, &f.Severity, &f.Status,
		&f.ConfidenceScore, &f.PhishingURLDefanged, &f.HostingIP, &f.Registrar,
		&f.CampaignID, &f.SourceID, &f.JobRunID, &f.DedupKey, &f.ContentFingerprint,
		&f.UrgencyPromoted, &f.UrgencyPromotedAt, &f.PriorSeverity, &f.SeverityOverrideReason,
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
			`INSERT INTO monitoring_phm.findings
			   (tenant_id, finding_type, title, severity, status, confidence_score,
			    phishing_url_defanged, hosting_ip, registrar, campaign_id, source_id,
			    job_run_id, dedup_key, content_fingerprint, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)
			 RETURNING id`,
			f.TenantID, f.FindingType, f.Title, f.Severity, f.Status, f.ConfidenceScore,
			f.PhishingURLDefanged, f.HostingIP, f.Registrar, f.CampaignID, f.SourceID,
			f.JobRunID, f.DedupKey, f.ContentFingerprint, actor(ctx)).Scan(&id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return ErrConflict
			}
			return err
		}
		for _, assetID := range f.AssetIDs {
			if _, err := tx.Exec(ctx,
				`INSERT INTO monitoring_phm.finding_assets (finding_id, asset_id, tenant_id, linked_by)
				 VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
				id, assetID, f.TenantID, actor(ctx)); err != nil {
				return err
			}
		}
		out, err = scanFinding(tx.QueryRow(ctx,
			`SELECT `+findingCols+` FROM monitoring_phm.findings f WHERE id = $1`, id))
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
			`SELECT `+findingCols+` FROM monitoring_phm.findings f WHERE id = $1`, id))
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
	if fil.CampaignID != "" {
		add("campaign_id = $%d", fil.CampaignID)
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
	query := fmt.Sprintf(`SELECT %s FROM monitoring_phm.findings f %s
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
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_phm.findings WHERE id = $1`, id).Scan(&oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_phm.findings
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
		err := tx.QueryRow(ctx, `SELECT severity FROM monitoring_phm.findings WHERE id = $1`, id).Scan(&oldSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_phm.findings
			    SET severity=$2, prior_severity=$3, severity_overridden_by=$4, severity_override_reason=$5, updated_by=$4
			  WHERE id=$1`, id, severity, oldSeverity, actor(ctx), reason); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "severity", oldSeverity, severity, actor(ctx))
	})
}

// PromoteUrgency marks a finding as urgency-promoted, optionally bumping severity,
// and records history (PHM-BR-001). newSeverity is the severity to set; if it is
// unchanged from the current value the severity history row is skipped.
func (s *Store) PromoteUrgency(ctx context.Context, tenantID, id, newSeverity string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldSeverity string
		err := tx.QueryRow(ctx, `SELECT severity FROM monitoring_phm.findings WHERE id = $1`, id).Scan(&oldSeverity)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_phm.findings
			    SET urgency_promoted=TRUE, urgency_promoted_at=NOW(), severity=$2, updated_by=$3
			  WHERE id=$1`, id, newSeverity, actor(ctx)); err != nil {
			return err
		}
		if newSeverity != oldSeverity {
			if err := appendHistory(ctx, tx, tenantID, id, "severity", oldSeverity, newSeverity, actor(ctx)); err != nil {
				return err
			}
		}
		return appendHistory(ctx, tx, tenantID, id, "urgency_promoted", "false", "true", actor(ctx))
	})
}

func (s *Store) mutateStatusWithHistory(ctx context.Context, tenantID, id, newValue string) error {
	return s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		var oldValue string
		err := tx.QueryRow(ctx, `SELECT status FROM monitoring_phm.findings WHERE id = $1`, id).Scan(&oldValue)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE monitoring_phm.findings SET status=$2, updated_by=$3 WHERE id=$1`,
			id, newValue, actor(ctx)); err != nil {
			return err
		}
		return appendHistory(ctx, tx, tenantID, id, "status", oldValue, newValue, actor(ctx))
	})
}

func appendHistory(ctx context.Context, tx pgx.Tx, tenantID, findingID, field, oldVal, newVal string, changedBy any) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO monitoring_phm.finding_history (tenant_id, finding_id, changed_field, old_value, new_value, changed_by)
		 VALUES ($1,$2,$3,$4,$5,$6)`, tenantID, findingID, field, oldVal, newVal, changedBy)
	return err
}

// CreateCampaign inserts a phishing campaign.
func (s *Store) CreateCampaign(ctx context.Context, c *domain.Campaign) (*domain.Campaign, error) {
	err := s.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_phm.campaigns (tenant_id, name, description, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$4)
			 RETURNING id, status, finding_count, first_seen_at, last_seen_at, created_at`,
			c.TenantID, c.Name, c.Description, actor(ctx)).
			Scan(&c.ID, &c.Status, &c.FindingCount, &c.FirstSeenAt, &c.LastSeenAt, &c.CreatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("create campaign: %w", err)
	}
	return c, nil
}

// ListCampaigns returns PHM campaigns.
func (s *Store) ListCampaigns(ctx context.Context, tenantID string) ([]domain.Campaign, error) {
	var out []domain.Campaign
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, name, description, status, finding_count, first_seen_at, last_seen_at, created_at
			   FROM monitoring_phm.campaigns ORDER BY last_seen_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c domain.Campaign
			if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.Description, &c.Status,
				&c.FindingCount, &c.FirstSeenAt, &c.LastSeenAt, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list campaigns: %w", err)
	}
	return out, nil
}

// AddIndicator inserts an indicator extracted from a finding.
func (s *Store) AddIndicator(ctx context.Context, i *domain.Indicator) (*domain.Indicator, error) {
	err := s.db.WithTenant(ctx, i.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_phm.indicators
			   (tenant_id, finding_id, indicator_type, value, tlp_marking, confidence, created_by, updated_by)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$7)
			 RETURNING id, first_seen_at, last_seen_at, created_at`,
			i.TenantID, i.FindingID, i.IndicatorType, i.Value, i.TLPMarking, i.Confidence, actor(ctx)).
			Scan(&i.ID, &i.FirstSeenAt, &i.LastSeenAt, &i.CreatedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("add indicator: %w", err)
	}
	return i, nil
}

// ListIndicators returns indicators for a finding.
func (s *Store) ListIndicators(ctx context.Context, tenantID, findingID string) ([]domain.Indicator, error) {
	var out []domain.Indicator
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, finding_id, indicator_type, value, tlp_marking,
			        confidence::float8, first_seen_at, last_seen_at, created_at
			   FROM monitoring_phm.indicators WHERE finding_id = $1 ORDER BY created_at DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var i domain.Indicator
			if err := rows.Scan(&i.ID, &i.TenantID, &i.FindingID, &i.IndicatorType, &i.Value,
				&i.TLPMarking, &i.Confidence, &i.FirstSeenAt, &i.LastSeenAt, &i.CreatedAt); err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list indicators: %w", err)
	}
	return out, nil
}

// AddCertificate inserts an immutable SSL certificate capture (PHM-BR-006).
func (s *Store) AddCertificate(ctx context.Context, c *domain.SSLCertificate) (*domain.SSLCertificate, error) {
	err := s.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_phm.ssl_certificates
			   (tenant_id, finding_id, serial_number, issuer, subject, san_entries,
			    not_before, not_after, fingerprint_sha256, raw_cert_ref)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			 RETURNING id, captured_at`,
			c.TenantID, c.FindingID, c.SerialNumber, c.Issuer, c.Subject, c.SANEntries,
			c.NotBefore, c.NotAfter, c.FingerprintSHA256, c.RawCertRef).
			Scan(&c.ID, &c.CapturedAt)
	})
	if err != nil {
		return nil, fmt.Errorf("add certificate: %w", err)
	}
	return c, nil
}

// ListCertificates returns certificate captures for a finding.
func (s *Store) ListCertificates(ctx context.Context, tenantID, findingID string) ([]domain.SSLCertificate, error) {
	var out []domain.SSLCertificate
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, finding_id, serial_number, issuer, subject, san_entries,
			        not_before, not_after, fingerprint_sha256, raw_cert_ref, captured_at
			   FROM monitoring_phm.ssl_certificates WHERE finding_id = $1 ORDER BY captured_at DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c domain.SSLCertificate
			if err := rows.Scan(&c.ID, &c.TenantID, &c.FindingID, &c.SerialNumber, &c.Issuer,
				&c.Subject, &c.SANEntries, &c.NotBefore, &c.NotAfter, &c.FingerprintSHA256,
				&c.RawCertRef, &c.CapturedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list certificates: %w", err)
	}
	return out, nil
}

// AddEvidence inserts an immutable evidence record.
func (s *Store) AddEvidence(ctx context.Context, e *domain.Evidence) (*domain.Evidence, error) {
	err := s.db.WithTenant(ctx, e.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		meta := e.Metadata
		if len(meta) == 0 {
			meta = []byte("{}")
		}
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_phm.evidence
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
			`SELECT id, tenant_id, finding_id, evidence_type, capture_timestamp, content_hash, storage_ref, metadata
			   FROM monitoring_phm.evidence WHERE finding_id = $1 ORDER BY capture_timestamp DESC`, findingID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e domain.Evidence
			if err := rows.Scan(&e.ID, &e.TenantID, &e.FindingID, &e.EvidenceType,
				&e.CaptureTimestamp, &e.ContentHash, &e.StorageRef, &e.Metadata); err != nil {
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

// ListSources returns PHM collection sources.
func (s *Store) ListSources(ctx context.Context, tenantID string) ([]domain.CollectionSource, error) {
	var out []domain.CollectionSource
	err := s.db.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT id, tenant_id, source_type, display_name, status, last_run_at, created_at
			   FROM monitoring_phm.collection_sources ORDER BY created_at DESC`)
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

// CreateSource inserts a PHM collection source.
func (s *Store) CreateSource(ctx context.Context, c *domain.CollectionSource) (*domain.CollectionSource, error) {
	err := s.db.WithTenant(ctx, c.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`INSERT INTO monitoring_phm.collection_sources (tenant_id, source_type, display_name, created_by, updated_by)
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
