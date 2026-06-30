// Command server runs the Alert Engine: a REST API for alerts and rules plus a
// set of Kafka consumers that turn escalated findings into alerts.
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
	"github.com/siberindo/cti/services/alert-engine/internal/api"
	"github.com/siberindo/cti/services/alert-engine/internal/config"
	"github.com/siberindo/cti/services/alert-engine/internal/consumer"
	"github.com/siberindo/cti/services/alert-engine/internal/store"
)

// escalationTopics are the per-module finding.escalated topics the engine consumes.
var escalationTopics = []string{
	types.TopicFindingEscalatedDLM,
	types.TopicFindingEscalatedCLM,
	types.TopicFindingEscalatedDWM,
	types.TopicFindingEscalatedBRM,
	types.TopicFindingEscalatedPHM,
}

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

	producer := kafka.NewProducer(cfg.KafkaBrokers)
	defer producer.Close()

	// Start the escalated-finding consumers.
	handler := consumer.New(st, producer, log)
	consumerCtx, stopConsumers := context.WithCancel(ctx)
	defer stopConsumers()
	var consumers []*kafka.Consumer
	for _, topic := range escalationTopics {
		c := kafka.NewConsumer(cfg.KafkaBrokers, topic, "alert-engine", log)
		consumers = append(consumers, c)
		go func(topic string, c *kafka.Consumer) {
			log.Info("consuming", slog.String("topic", topic))
			if err := c.Run(consumerCtx, handler.Handle); err != nil {
				log.Error("consumer stopped", slog.String("topic", topic), slog.String("error", err.Error()))
			}
		}(topic, c)
	}
	defer func() {
		for _, c := range consumers {
			_ = c.Close()
		}
	}()

	issuer := auth.NewIssuer(cfg.JWTSecret, time.Hour)
	handlerAPI := api.New(st, issuer)

	srv := server.New(cfg.HTTPPort, log)
	srv.AddReadinessCheck(db.Health)
	handlerAPI.Register(srv.Mux())

	log.Info("alert-engine starting", slog.Int("port", cfg.HTTPPort), slog.String("env", cfg.Env))
	if err := srv.Run(); err != nil {
		log.Error("server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
	stopConsumers()
}
