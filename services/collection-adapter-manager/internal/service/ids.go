package service

import "github.com/google/uuid"

// newEventID returns a fresh event id. It is retained for symmetry with the other
// services; the Collection Adapter Manager is a pure consumer and does not publish
// events, so it is currently unused by the publish path.
func newEventID() string { return uuid.NewString() }
