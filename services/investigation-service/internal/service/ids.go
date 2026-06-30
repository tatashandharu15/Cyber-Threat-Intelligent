package service

import "github.com/google/uuid"

// newEventID returns a fresh event id for published events.
func newEventID() string { return uuid.NewString() }
