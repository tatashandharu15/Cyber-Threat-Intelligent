// Package events defines the Publisher abstraction used to emit alert.created
// events. kafka.Producer satisfies it; tests use a fake.
package events

import "context"

// Publisher publishes a JSON value to a topic, keyed for partitioning.
type Publisher interface {
	Publish(ctx context.Context, topic, key string, value any) error
}
