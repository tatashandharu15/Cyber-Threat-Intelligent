// Package domain holds the Asset service's core entity types, free of transport
// and storage concerns.
package domain

import "time"

// Asset is a monitored digital asset within a tenant's attack surface (a domain,
// IP range, brand keyword, executive profile, etc.). Brand-keyword assets are
// subject to an approval gate (BRM-BR-001) before they can be monitored.
type Asset struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	AssetType      string    `json:"asset_type"`
	Value          string    `json:"value"`
	DisplayName    *string   `json:"display_name,omitempty"`
	Criticality    string    `json:"criticality"`
	Status         string    `json:"status"`
	ApprovalStatus string    `json:"approval_status"`
	ApprovedBy     *string   `json:"approved_by,omitempty"`
	ApprovedAt     *time.Time `json:"approved_at,omitempty"`
	Visibility     string    `json:"visibility"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedBy      *string   `json:"created_by,omitempty"`
	UpdatedBy      *string   `json:"updated_by,omitempty"`
}

// DirectoryLinkage links an asset to an external identity/directory source so that
// asset ownership can be reconciled with the customer's directory of record.
type DirectoryLinkage struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	AssetID       string    `json:"asset_id"`
	DirectoryType string    `json:"directory_type"`
	DirectoryRef  string    `json:"directory_ref"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
