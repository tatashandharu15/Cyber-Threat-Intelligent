// Command server runs the Collection Adapter Manager: a REST API for the
// per-module collection adapter registry plus two Kafka consumers that track
// adapter health from the collection.job.completed and collection.job.failed
// topics. It is a pure consumer (no producer): the Kafka Topic Catalog defines no
// collection-request topic, so the on-demand trigger records intent only.
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
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/api"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/config"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/consumer"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/service"
	"github.com/siberindo/cti/services/collection-adapter-manager/internal/store"
)

const consumerGroup = "collection-adapter-manager"

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

	st := store.New(db).WithLogger(log)
	migCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := st.Migrate(migCtx); err != nil {
		log.Error("run migrations", slog.String("error", err.Error()))
		os.Exit(1)
	}

	svc := service.New(st, log)

	// Start the two collection-job outcome consumers. Each runs in its own
	// goroutine on its own topic but feeds the same ingester.
	handler := consumer.New(svc, log)
	consumerCtx, stopConsumers := context.WithCancel(ctx)
	defer stopConsumers()

	type topicConsumer struct {
		topic   string
		handler kafka.Handler
	}
	wiring := []topicConsumer{
		{types.TopicCollectionCompleted, handler.HandleCompleted},
		{types.TopicCollectionFailed, handler.HandleFailed},
	}
	var consumers []*kafka.Consumer
	for _, tc := range wiring {
		c := kafka.NewConsumer(cfg.KafkaBrokers, tc.topic, consumerGroup, log)
		consumers = append(consumers, c)
		go func(tc topicConsumer, c *kafka.Consumer) {
			log.Info("consuming", slog.String("topic", tc.topic))
			if err := c.Run(consumerCtx, tc.handler); err != nil {
				log.Error("consumer stopped", slog.String("topic", tc.topic), slog.String("error", err.Error()))
			}
		}(tc, c)
	}
	defer func() {
		for _, c := range consumers {
			_ = c.Close()
		}
	}()

	issuer := auth.NewIssuer(cfg.JWTSecret, time.Hour)
	handlerAPI := api.New(svc, issuer)

	srv := server.New(cfg.HTTPPort, log)
	srv.AddReadinessCheck(db.Health)
	handlerAPI.Register(srv.Mux())

	log.Info("collection-adapter-manager starting", slog.Int("port", cfg.HTTPPort), slog.String("env", cfg.Env))
	if err := srv.Run(); err != nil {
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	stopConsumers()
}
