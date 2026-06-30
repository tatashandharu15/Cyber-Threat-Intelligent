// Package domain holds the Audit Log service's core entity types.
package domain

import (
	"encoding/json"
	"time"
)

// AuditEvent is a single tamper-evident audit record. The HMACSignature is computed
// over the security-relevant fields (see packages/utils/audit) so a mutated record
// can be detected via the verify endpoint.
type AuditEvent struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	ActorID       string          `json:"actor_id"`
	ActorType     string          `json:"actor_type"`
	EventType     string          `json:"event_type"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    *string         `json:"resource_id,omitempty"`
	Action        string          `json:"action"`
	Outcome       string          `json:"outcome"`
	IPAddress     *string         `json:"ip_address,omitempty"`
	UserAgent     *string         `json:"user_agent,omitempty"`
	RequestID     *string         `json:"request_id,omitempty"`
	EventPayload  json.RawMessage `json:"event_payload,omitempty"`
	HMACSignature string          `json:"hmac_signature"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AuditFilter constrains an audit-event list query.
type AuditFilter struct {
	EventType    string
	ResourceType string
	ActorID      string
	Outcome      string
	Limit        int
	Offset       int
}
