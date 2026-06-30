// Package events defines the Publisher abstraction the Reporting service uses to
// emit Kafka events. kafka.Producer satisfies this interface; tests use a fake.
package events

import "context"

// Publisher publishes a JSON value to a topic, keyed for partitioning.
type Publisher interface {
	Publish(ctx context.Context, topic, key string, value any) error
}

// NopPublisher discards events. Useful when Kafka is not configured.
type NopPublisher struct{}

// Publish implements Publisher and does nothing.
func (NopPublisher) Publish(context.Context, string, string, any) error { return nil }
