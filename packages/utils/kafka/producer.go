// Package kafka provides thin producer and consumer wrappers over
// segmentio/kafka-go, with JSON payload marshaling and tenant-keyed partitioning.
package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	kgo "github.com/segmentio/kafka-go"
)

// Producer publishes JSON events to Kafka topics.
type Producer struct {
	w *kgo.Writer
}

// NewProducer returns a Producer that connects to the given comma-separated
// brokers. Topic is selected per-message so a single Producer serves a service.
func NewProducer(brokers string) *Producer {
	return &Producer{
		w: &kgo.Writer{
			Addr:                   kgo.TCP(splitBrokers(brokers)...),
			Balancer:               &kgo.Hash{}, // hash on key => same tenant lands on same partition
			RequiredAcks:           kgo.RequireAll,
			Async:                  false,
			BatchTimeout:           50 * time.Millisecond,
			AllowAutoTopicCreation: true, // create the topic on first publish in dev/MVP
		},
	}
}

// Publish marshals value to JSON and writes it to topic, keyed by key (typically
// the tenant_id, so events for a tenant preserve per-partition ordering).
func (p *Producer) Publish(ctx context.Context, topic, key string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	msg := kgo.Message{
		Topic: topic,
		Key:   []byte(key),
		Value: body,
		Time:  time.Now(),
	}
	// Retry transient failures with bounded exponential backoff. The common case is
	// UNKNOWN_TOPIC_OR_PARTITION on the first publish to a topic that is still being
	// auto-created; the topic becomes available within a few hundred milliseconds, so
	// retrying makes first-use publishes reliable instead of silently dropping events.
	const maxAttempts = 6
	backoff := 150 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		lastErr = p.w.WriteMessages(ctx, msg)
		if lastErr == nil {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("write message to %s: %w", topic, ctx.Err())
		}
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return fmt.Errorf("write message to %s: %w", topic, ctx.Err())
			case <-time.After(backoff):
			}
			backoff *= 2
		}
	}
	return fmt.Errorf("write message to %s after %d attempts: %w", topic, maxAttempts, lastErr)
}

// Close flushes and closes the underlying writer.
func (p *Producer) Close() error {
	return p.w.Close()
}

func splitBrokers(brokers string) []string {
	parts := strings.Split(brokers, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
