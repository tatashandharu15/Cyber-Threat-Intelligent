package service

import "github.com/google/uuid"

// newEventID returns a fresh event id. Reserved for future event publication.
func newEventID() string { return uuid.NewString() }
