// Package types holds enums, event schemas, and error codes shared across all
// SiberIndo CTI platform services. It has no external dependencies so that it can
// be imported by every service and shared package without creating import cycles.
package types

// Severity is the normalized severity scale shared by every detection module,
// the Alert Engine, and reporting. See the Database Blueprint CHECK constraints.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// Valid reports whether s is one of the approved severity values.
func (s Severity) Valid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		return true
	}
	return false
}

// Rank returns a numeric ordering for severity, higher is more severe. It is used
// by the Alert Engine to compare against rule thresholds.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

// Module identifies a detection module that produces findings.
type Module string

const (
	ModuleDLM Module = "dlm"
	ModuleCLM Module = "clm"
	ModuleDWM Module = "dwm"
	ModuleBRM Module = "brm"
	ModulePHM Module = "phm"
)

// Valid reports whether m is one of the five detection modules.
func (m Module) Valid() bool {
	switch m {
	case ModuleDLM, ModuleCLM, ModuleDWM, ModuleBRM, ModulePHM:
		return true
	}
	return false
}

// Criticality is the asset criticality scale from the Asset Management registry.
type Criticality string

const (
	CriticalityCritical Criticality = "critical"
	CriticalityHigh     Criticality = "high"
	CriticalityMedium   Criticality = "medium"
	CriticalityLow      Criticality = "low"
)

// Valid reports whether c is one of the approved criticality values.
func (c Criticality) Valid() bool {
	switch c {
	case CriticalityCritical, CriticalityHigh, CriticalityMedium, CriticalityLow:
		return true
	}
	return false
}

// TLP is a Traffic Light Protocol marking applied to indicators and exports.
type TLP string

const (
	TLPWhite TLP = "TLP:WHITE"
	TLPGreen TLP = "TLP:GREEN"
	TLPAmber TLP = "TLP:AMBER"
	TLPRed   TLP = "TLP:RED"
)

// Valid reports whether t is one of the approved TLP markings.
func (t TLP) Valid() bool {
	switch t {
	case TLPWhite, TLPGreen, TLPAmber, TLPRed:
		return true
	}
	return false
}
