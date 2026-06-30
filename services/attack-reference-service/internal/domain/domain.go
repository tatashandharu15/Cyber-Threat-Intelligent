// Package domain holds the ATT&CK Reference service's core entity types. The
// catalog is global reference data (MITRE ATT&CK techniques) and is not
// tenant-scoped, so the types carry no tenant_id.
package domain

import "time"

// Technique is a single MITRE ATT&CK (sub-)technique in the reference catalog.
// It mirrors platform_services.attack_techniques (Database Blueprint 8.10).
type Technique struct {
	ID                string    `json:"id"`
	TechniqueID       string    `json:"technique_id"`
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	TacticRefs        []string  `json:"tactic_refs"`
	PlatformRefs      []string  `json:"platform_refs"`
	IsSubtechnique    bool      `json:"is_subtechnique"`
	ParentTechniqueID *string   `json:"parent_technique_id,omitempty"`
	StixID            *string   `json:"stix_id,omitempty"`
	LastSyncedAt      time.Time `json:"last_synced_at"`
	CreatedAt         time.Time `json:"created_at"`
}

// TechniqueFilter constrains a technique list query. Tactic matches techniques
// whose tactic_refs contains the value; Search matches the name or technique_id.
type TechniqueFilter struct {
	Tactic string
	Search string
	Limit  int
	Offset int
}
