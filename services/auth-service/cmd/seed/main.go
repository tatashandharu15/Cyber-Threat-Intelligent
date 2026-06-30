// Command seed provisions a demo tenant, an admin role with broad permissions, and
// a demo user so the Auth service can be exercised end to end locally.
//
//	go run ./cmd/seed
//
// It is idempotent: re-running updates the demo user's password hash.
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/siberindo/cti/packages/utils/config"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/services/auth-service/internal/service"
	"github.com/siberindo/cti/services/auth-service/internal/store"
)

const (
	demoTenantSlug = "demo"
	demoEmail      = "analyst@demo.siberindo.io"
	demoPassword   = "Demo!Passw0rd"
)

func main() {
	cfg := config.LoadBase("auth-service-seed")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer db.Close()

	// Ensure the identity schema exists.
	if err := store.New(db).Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	hash, err := service.HashPassword(demoPassword)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	err = db.WithoutTenant(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var tenantID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO core_platform.tenants (slug, display_name)
			 VALUES ($1, $2)
			 ON CONFLICT (slug) DO UPDATE SET display_name = EXCLUDED.display_name
			 RETURNING id`, demoTenantSlug, "Demo Tenant").Scan(&tenantID); err != nil {
			return err
		}

		// Tenant context is required for the RLS-protected identity tables.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.current_tenant_id', $1, true)", tenantID); err != nil {
			return err
		}

		var userID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO core_platform.users (tenant_id, email, display_name, password_hash, status)
			 VALUES ($1, $2, $3, $4, 'active')
			 ON CONFLICT (email, tenant_id) DO UPDATE SET password_hash = EXCLUDED.password_hash
			 RETURNING id`, tenantID, demoEmail, "Demo Analyst", hash).Scan(&userID); err != nil {
			return err
		}

		var roleID string
		if err := tx.QueryRow(ctx,
			`INSERT INTO core_platform.roles (tenant_id, name, role_type, description)
			 VALUES ($1, 'cti_analyst', 'tenant', 'Demo CTI analyst role')
			 ON CONFLICT (name, tenant_id) WHERE tenant_id IS NOT NULL DO UPDATE SET description = EXCLUDED.description
			 RETURNING id`, tenantID).Scan(&roleID); err != nil {
			return err
		}

		perms := [][2]string{
			{"finding", "read"}, {"finding", "create"}, {"finding", "update"},
			{"alert", "read"}, {"alert", "update"}, {"alert", "manage"},
			{"asset", "read"}, {"asset", "create"}, {"asset", "update"}, {"asset", "approve"},
			{"user", "read"}, {"user", "manage"},
			{"investigation", "read"}, {"investigation", "create"}, {"investigation", "update"},
			{"notification", "read"}, {"notification", "update"}, {"notification", "manage"},
			{"audit", "read"}, {"audit", "write"},
			{"indicator", "read"}, {"indicator", "create"}, {"indicator", "update"},
			{"takedown", "read"}, {"takedown", "create"}, {"takedown", "update"},
			{"report", "read"}, {"report", "create"},
			{"attack", "read"}, {"attack", "manage"},
			{"adapter", "read"}, {"adapter", "manage"},
			{"role", "read"}, {"role", "manage"},
		}
		for _, p := range perms {
			var permID string
			if err := tx.QueryRow(ctx,
				`INSERT INTO core_platform.permissions (resource, action)
				 VALUES ($1, $2)
				 ON CONFLICT (resource, action) DO UPDATE SET resource = EXCLUDED.resource
				 RETURNING id`, p[0], p[1]).Scan(&permID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO core_platform.role_permissions (role_id, permission_id)
				 VALUES ($1, $2) ON CONFLICT DO NOTHING`, roleID, permID); err != nil {
				return err
			}
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO core_platform.user_roles (user_id, role_id, tenant_id)
			 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, userID, roleID, tenantID); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		log.Fatalf("seed: %v", err)
	}

	log.Printf("seeded tenant=%q user=%q password=%q", demoTenantSlug, demoEmail, demoPassword)
	os.Exit(0)
}
