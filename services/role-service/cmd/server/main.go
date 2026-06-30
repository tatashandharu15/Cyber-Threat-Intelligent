// Command server runs the Role service HTTP API. The Role service is a
// synchronous RBAC management API over the core_platform identity tables; it has
// no Kafka producer or consumer (correct per the frozen event catalog).
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
	"github.com/siberindo/cti/services/role-service/internal/api"
	"github.com/siberindo/cti/services/role-service/internal/config"
	"github.com/siberindo/cti/services/role-service/internal/service"
	"github.com/siberindo/cti/services/role-service/internal/store"
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
	issuer := auth.NewIssuer(cfg.JWTSecret, time.Hour)
	handler := api.New(svc, issuer)

	srv := server.New(cfg.HTTPPort, log)
	srv.AddReadinessCheck(db.Health)
	handler.Register(srv.Mux())

	log.Info("role-service starting", slog.Int("port", cfg.HTTPPort), slog.String("env", cfg.Env))
	if err := srv.Run(); err != nil {
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
