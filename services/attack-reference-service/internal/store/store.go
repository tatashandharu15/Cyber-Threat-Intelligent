// Package store is the ATT&CK Reference service's data-access layer over the
// platform_services.attack_techniques table. Unlike the other services this table
// is GLOBAL reference data with no row-level security, so every query runs via
// database.WithoutTenant (a plain transaction with no tenant context).
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
	"github.com/siberindo/cti/services/attack-reference-service/internal/domain"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ErrNotFound is returned when a technique does not exist.
var ErrNotFound = errors.New("not found")

// techniqueCols is the canonical column projection for a Technique row.
const techniqueCols = `id, technique_id, name, COALESCE(description, ''),
	COALESCE(tactic_refs, '{}'), COALESCE(platform_refs, '{}'),
	is_subtechnique, parent_technique_id, stix_id, last_synced_at, created_at`

// Store wraps the shared database handle.
type Store struct {
	db *database.DB
}

// New returns a Store.
func New(db *database.DB) *Store { return &Store{db: db} }

// Migrate applies the ATT&CK reference schema migrations.
func (s *Store) Migrate(ctx context.Context) error {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	return s.db.Migrate(ctx, sub, "platform_services.schema_migrations_attack")
}

func scanTechnique(row pgx.Row) (*domain.Technique, error) {
	var t domain.Technique
	err := row.Scan(&t.ID, &t.TechniqueID, &t.Name, &t.Description,
		&t.TacticRefs, &t.PlatformRefs, &t.IsSubtechnique, &t.ParentTechniqueID,
		&t.StixID, &t.LastSyncedAt, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// UpsertTechnique inserts a technique or, when technique_id already exists,
// updates the mutable fields and refreshes last_synced_at. It returns the stored
// row. Operates on global data, so it runs without tenant context.
func (s *Store) UpsertTechnique(ctx context.Context, t *domain.Technique) (*domain.Technique, error) {
	var out *domain.Technique
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanTechnique(tx.QueryRow(ctx,
			`INSERT INTO platform_services.attack_techniques
			   (technique_id, name, description, tactic_refs, platform_refs,
			    is_subtechnique, parent_technique_id, stix_id, last_synced_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
			 ON CONFLICT (technique_id) DO UPDATE SET
			   name = EXCLUDED.name,
			   description = EXCLUDED.description,
			   tactic_refs = EXCLUDED.tactic_refs,
			   platform_refs = EXCLUDED.platform_refs,
			   is_subtechnique = EXCLUDED.is_subtechnique,
			   parent_technique_id = EXCLUDED.parent_technique_id,
			   stix_id = EXCLUDED.stix_id,
			   last_synced_at = NOW()
			 RETURNING `+techniqueCols,
			t.TechniqueID, t.Name, nullify(t.Description), t.TacticRefs, t.PlatformRefs,
			t.IsSubtechnique, t.ParentTechniqueID, t.StixID))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("upsert technique: %w", err)
	}
	return out, nil
}

// GetByTechniqueID returns one technique by its ATT&CK id (e.g. "T1566").
func (s *Store) GetByTechniqueID(ctx context.Context, techniqueID string) (*domain.Technique, error) {
	var out *domain.Technique
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = scanTechnique(tx.QueryRow(ctx,
			`SELECT `+techniqueCols+` FROM platform_services.attack_techniques WHERE technique_id = $1`,
			techniqueID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get technique: %w", err)
	}
	return out, nil
}

// ListTechniques returns techniques matching the filter, ordered by technique_id.
func (s *Store) ListTechniques(ctx context.Context, fil domain.TechniqueFilter) ([]domain.Technique, error) {
	where := []string{}
	args := []any{}
	add := func(clause string, val any) {
		args = append(args, val)
		where = append(where, fmt.Sprintf(clause, len(args)))
	}
	if fil.Tactic != "" {
		add("$%d = ANY(tactic_refs)", fil.Tactic)
	}
	if fil.Search != "" {
		args = append(args, "%"+fil.Search+"%")
		where = append(where, fmt.Sprintf("(name ILIKE $%d OR technique_id ILIKE $%d)", len(args), len(args)))
	}
	clause := ""
	if len(where) > 0 {
		clause = "WHERE " + strings.Join(where, " AND ")
	}
	limit := fil.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := fil.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT %s FROM platform_services.attack_techniques %s
		ORDER BY technique_id ASC LIMIT $%d OFFSET $%d`,
		techniqueCols, clause, len(args)-1, len(args))

	var out []domain.Technique
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTechnique(rows)
			if err != nil {
				return err
			}
			out = append(out, *t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list techniques: %w", err)
	}
	return out, nil
}

// Count returns the total number of techniques in the catalog.
func (s *Store) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT COUNT(*) FROM platform_services.attack_techniques`).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("count techniques: %w", err)
	}
	return n, nil
}

func nullify(s string) any {
	if s == "" {
		return nil
	}
	return s
}
