// Command server runs the ATT&CK Reference service HTTP API. It serves the global
// MITRE ATT&CK technique catalog (platform_services.attack_techniques) as a
// synchronous query + sync service. There is no Kafka producer or consumer: the
// frozen event catalog defines no events for this reference-data service.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/packages/utils/logging"
	"github.com/siberindo/cti/packages/utils/server"
	"github.com/siberindo/cti/services/attack-reference-service/internal/api"
	"github.com/siberindo/cti/services/attack-reference-service/internal/config"
	"github.com/siberindo/cti/services/attack-reference-service/internal/service"
	"github.com/siberindo/cti/services/attack-reference-service/internal/store"
)

func main() {
	cfg := config.Load()
	log := logging.New(cfg.ServiceName, cfg.LogLevel)

	if err := cfg.MustProductionSecrets(); err != nil {
		log.Error("insecure configuration", slog.String("error", err.Error()))
		os.Exit(1)
	}

	ctx := context.Background()
	db, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("connect database", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer db.Close()

	st := store.New(db)
	migCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.Migrate(migCtx); err != nil {
		log.Error("run migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}

	svc := service.New(st, log)

	// Seed the built-in technique set once at startup so the catalog is queryable
	// immediately. Best-effort: a failure here (e.g. transient DB issue) is logged
	// but does not prevent the service from starting and serving reads.
	seedCtx, seedCancel := context.WithTimeout(ctx, 30*time.Second)
	defer seedCancel()
	if n, err := svc.SeedDefaults(seedCtx); err != nil {
		log.Warn("seed default techniques failed", slog.String("error", err.Error()))
	} else {
		log.Info("seeded default techniques", slog.Int("count", n))
	}

	issuer := auth.NewIssuer(cfg.JWTSecret, time.Hour)
	handler := api.New(svc, issuer)

	srv := server.New(cfg.HTTPPort, log)
	srv.AddReadinessCheck(db.Health)
	handler.Register(srv.Mux())

	log.Info("attack-reference-service starting", slog.Int("port", cfg.HTTPPort), slog.String("env", cfg.Env))
	if err := srv.Run(); err != nil {
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
