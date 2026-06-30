// Package database wraps pgxpool and centralizes the row-level-security tenant
// context pattern described in the Database Blueprint section 1.2. Every
// tenant-scoped query must run inside WithTenant so that the database enforces
// the tenant_isolation RLS policy via app.current_tenant_id.
package database

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB is the shared connection pool handle.
type DB struct {
	Pool *pgxpool.Pool
}

// Connect opens a pgx pool against url and verifies connectivity with a ping.
func Connect(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() {
	if db.Pool != nil {
		db.Pool.Close()
	}
}

// Health runs a lightweight ping for readiness checks.
func (db *DB) Health(ctx context.Context) error {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return db.Pool.Ping(c)
}

// TxFunc receives a transaction in which the tenant RLS context has already
// been set. All reads and writes performed on tx are scoped to that tenant.
type TxFunc func(ctx context.Context, tx pgx.Tx) error

// WithTenant runs fn inside a transaction that has app.current_tenant_id set to
// tenantID for the lifetime of the transaction. This is the only supported way
// to execute tenant-scoped statements: the RLS policies depend on the setting.
func (db *DB) WithTenant(ctx context.Context, tenantID string, fn TxFunc) error {
	if tenantID == "" {
		return fmt.Errorf("tenant id is required for tenant-scoped transaction")
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// set_config(..., true) scopes the setting to the current transaction so it
	// is automatically reset when the transaction ends and never leaks across
	// pooled connections.
	if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// WithoutTenant runs fn in a transaction with no tenant context. It is intended
// for platform-level operations (tenant provisioning, system-role lookups) that
// operate on tables not subject to tenant RLS. Use sparingly.
func (db *DB) WithoutTenant(ctx context.Context, fn TxFunc) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}
