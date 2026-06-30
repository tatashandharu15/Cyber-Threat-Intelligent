package kafka

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	kgo "github.com/segmentio/kafka-go"
)

// Handler processes a single message body. Returning an error causes the message
// to be retried (it is not committed) after a short backoff.
type Handler func(ctx context.Context, key, value []byte) error

// Consumer reads from a single topic as part of a consumer group and dispatches
// each message to a Handler. Offsets are committed only after successful handling.
type Consumer struct {
	r   *kgo.Reader
	log *slog.Logger
}

// NewConsumer creates a Consumer for topic within groupID.
func NewConsumer(brokers, topic, groupID string, log *slog.Logger) *Consumer {
	return &Consumer{
		r: kgo.NewReader(kgo.ReaderConfig{
			Brokers:        splitBrokers(brokers),
			Topic:          topic,
			GroupID:        groupID,
			MinBytes:       1,
			MaxBytes:       10e6,
			CommitInterval: 0, // commit synchronously after each handled message
			MaxWait:        500 * time.Millisecond,
		}),
		log: log,
	}
}

// Run consumes messages until ctx is cancelled. Handler errors are logged and the
// message is retried; the offset advances only on success.
func (c *Consumer) Run(ctx context.Context, h Handler) error {
	for {
		m, err := c.r.FetchMessage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			return fmt.Errorf("fetch message: %w", err)
		}
		if err := h(ctx, m.Key, m.Value); err != nil {
			c.log.ErrorContext(ctx, "message handler failed; will retry",
				slog.String("topic", m.Topic),
				slog.Int("partition", m.Partition),
				slog.Int64("offset", m.Offset),
				slog.String("error", err.Error()),
			)
			// Do not commit. Back off briefly before the next fetch so a poison
			// message does not spin the loop. A production deployment routes
			// repeated failures to the topic's .dlq (Architecture Blueprint 10.3).
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
			continue
		}
		if err := c.r.CommitMessages(ctx, m); err != nil {
			c.log.ErrorContext(ctx, "commit failed", slog.String("error", err.Error()))
		}
	}
}

// Close closes the underlying reader.
func (c *Consumer) Close() error {
	return c.r.Close()
}
