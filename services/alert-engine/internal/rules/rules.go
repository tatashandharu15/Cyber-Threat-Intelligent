// Package rules holds the pure alert-rule evaluation logic. It has no database or
// Kafka dependencies so it is trivially unit-testable, which matters because this
// is the heart of the Alert Engine.
package rules

import types "github.com/siberindo/cti/packages/shared-types"

// Conditions is the JSONB body of an alert rule. An empty list/zero value means
// "no constraint on this dimension".
type Conditions struct {
	Severity      []string `json:"severity"`             // event severity must be in this list
	FindingType   []string `json:"finding_type"`         // event finding_type must be in this list
	ConfidenceMin float64  `json:"confidence_score_min"` // event confidence must be >= this
}

// Rule is a tenant alert rule.
type Rule struct {
	ID           string     `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	SourceModule string     `json:"source_module"` // "", "any", or a module code
	Conditions   Conditions `json:"conditions"`
	Status       string     `json:"status"` // active | paused | archived
}

// Matches reports whether ev satisfies this rule.
func (r Rule) Matches(ev types.FindingEscalated) bool {
	if r.Status != "active" {
		return false
	}
	if r.SourceModule != "" && r.SourceModule != "any" && r.SourceModule != string(ev.SourceModule) {
		return false
	}
	if len(r.Conditions.Severity) > 0 && !contains(r.Conditions.Severity, string(ev.Severity)) {
		return false
	}
	if len(r.Conditions.FindingType) > 0 && !contains(r.Conditions.FindingType, ev.FindingType) {
		return false
	}
	if ev.ConfidenceScore < r.Conditions.ConfidenceMin {
		return false
	}
	return true
}

// Evaluate returns the subset of rules that match ev.
func Evaluate(rules []Rule, ev types.FindingEscalated) []Rule {
	var matched []Rule
	for _, r := range rules {
		if r.Matches(ev) {
			matched = append(matched, r)
		}
	}
	return matched
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
