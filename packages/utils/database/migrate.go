package database

import (
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// Migrate applies all .sql files found in fsys (typically an embed.FS rooted at a
// service's migrations directory) in lexical filename order. Applied versions are
// recorded in a per-schema schema_migrations table so the runner is idempotent.
//
// Migrations are intentionally simple forward-only SQL files named like
// 0001_init.sql, 0002_add_index.sql. Each file is executed in its own
// transaction. This avoids an external migrate CLI dependency.
func (db *DB) Migrate(ctx context.Context, fsys fs.FS, migrationsTable string) error {
	if migrationsTable == "" {
		migrationsTable = "public.schema_migrations"
	}
	if _, err := db.Pool.Exec(ctx, fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS %s (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`, migrationsTable)); err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	applied, err := db.appliedVersions(ctx, migrationsTable)
	if err != nil {
		return err
	}

	files, err := sqlFiles(fsys)
	if err != nil {
		return err
	}

	for _, name := range files {
		version := strings.TrimSuffix(name, ".sql")
		if applied[version] {
			continue
		}
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		tx, err := db.Pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			fmt.Sprintf("INSERT INTO %s (version) VALUES ($1)", migrationsTable), version); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
	}
	return nil
}

func (db *DB) appliedVersions(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := db.Pool.Query(ctx, fmt.Sprintf("SELECT version FROM %s", table))
	if err != nil {
		return nil, fmt.Errorf("query applied migrations: %w", err)
	}
	defer rows.Close()
	applied := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func sqlFiles(fsys fs.FS) ([]string, error) {
	var files []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sql") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk migrations: %w", err)
	}
	sort.Strings(files)
	return files, nil
}
