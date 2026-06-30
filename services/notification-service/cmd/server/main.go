// Command server runs the Notification Center: a REST API for notifications and
// preferences plus a Kafka consumer that turns alert.created events into in_app
// notifications.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	types "github.com/siberindo/cti/packages/shared-types"
	"github.com/siberindo/cti/packages/utils/auth"
	"github.com/siberindo/cti/packages/utils/database"
	"github.com/siberindo/cti/packages/utils/kafka"
	"github.com/siberindo/cti/packages/utils/logging"
	"github.com/siberindo/cti/packages/utils/server"
	"github.com/siberindo/cti/services/notification-service/internal/api"
	"github.com/siberindo/cti/services/notification-service/internal/config"
	"github.com/siberindo/cti/services/notification-service/internal/consumer"
	"github.com/siberindo/cti/services/notification-service/internal/service"
	"github.com/siberindo/cti/services/notification-service/internal/store"
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

	// Start the alert.created consumer.
	handler := consumer.New(svc, log)
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	defer stopConsumer()
	c := kafka.NewConsumer(cfg.KafkaBrokers, types.TopicAlertCreated, "notification-center", log)
	go func() {
		log.Info("consuming", slog.String("topic", types.TopicAlertCreated))
		if err := c.Run(consumerCtx, handler.Handle); err != nil {
			log.Error("consumer stopped", slog.String("topic", types.TopicAlertCreated), slog.String("error", err.Error()))
		}
	}()
	defer func() { _ = c.Close() }()

	issuer := auth.NewIssuer(cfg.JWTSecret, time.Hour)
	handlerAPI := api.New(svc, issuer)

	srv := server.New(cfg.HTTPPort, log)
	srv.AddReadinessCheck(db.Health)
	handlerAPI.Register(srv.Mux())

	log.Info("notification-service starting", slog.Int("port", cfg.HTTPPort), slog.String("env", cfg.Env))
	if err := srv.Run(); err != nil {
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	stopConsumer()
}
