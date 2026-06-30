// Package audit computes the tamper-evident HMAC signature applied to every audit
// event, as required by the Security Blueprint. The canonical string is a stable,
// ordered concatenation of the security-relevant fields so signatures can be
// recomputed and verified independently of JSON field ordering.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Event is the minimal set of fields covered by the HMAC signature.
type Event struct {
	TenantID     string
	ActorID      string
	ActorType    string
	EventType    string
	ResourceType string
	ResourceID   string
	Action       string
	Outcome      string
	CreatedAt    time.Time
}

// Signer produces and verifies HMAC-SHA256 signatures over audit events.
type Signer struct {
	key []byte
}

// NewSigner returns a Signer keyed with the given secret.
func NewSigner(key string) *Signer {
	return &Signer{key: []byte(key)}
}

// Canonical returns the deterministic string that is signed for e.
func Canonical(e Event) string {
	return strings.Join([]string{
		e.TenantID,
		e.ActorID,
		e.ActorType,
		e.EventType,
		e.ResourceType,
		e.ResourceID,
		e.Action,
		e.Outcome,
		e.CreatedAt.UTC().Format(time.RFC3339Nano),
	}, "|")
}

// Sign returns the hex-encoded HMAC-SHA256 signature for e.
func (s *Signer) Sign(e Event) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(Canonical(e)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether sig is a valid signature for e.
func (s *Signer) Verify(e Event, sig string) bool {
	expected, err := hex.DecodeString(sig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(Canonical(e)))
	return hmac.Equal(expected, mac.Sum(nil))
}
