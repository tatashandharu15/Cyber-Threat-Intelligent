package rules

import (
	"testing"

	types "github.com/siberindo/cti/packages/shared-types"
)

func ev(module types.Module, severity types.Severity, findingType string, conf float64) types.FindingEscalated {
	return types.FindingEscalated{
		SourceModule: module, Severity: severity, FindingType: findingType, ConfidenceScore: conf,
		FindingID: "f1", TenantID: "t1",
	}
}

func TestSeverityFilter(t *testing.T) {
	r := Rule{Status: "active", Conditions: Conditions{Severity: []string{"critical", "high"}}}
	if !r.Matches(ev(types.ModuleDLM, types.SeverityHigh, "x", 1)) {
		t.Fatal("high should match [critical,high]")
	}
	if r.Matches(ev(types.ModuleDLM, types.SeverityLow, "x", 1)) {
		t.Fatal("low should not match [critical,high]")
	}
}

func TestFindingTypeFilter(t *testing.T) {
	r := Rule{Status: "active", Conditions: Conditions{FindingType: []string{"credential_reference"}}}
	if !r.Matches(ev(types.ModuleDLM, types.SeverityHigh, "credential_reference", 1)) {
		t.Fatal("matching finding type should match")
	}
	if r.Matches(ev(types.ModuleDLM, types.SeverityHigh, "pii_exposure", 1)) {
		t.Fatal("non-matching finding type should not match")
	}
}

func TestConfidenceThreshold(t *testing.T) {
	r := Rule{Status: "active", Conditions: Conditions{ConfidenceMin: 0.8}}
	if !r.Matches(ev(types.ModuleDLM, types.SeverityHigh, "x", 0.8)) {
		t.Fatal("confidence at threshold should match")
	}
	if r.Matches(ev(types.ModuleDLM, types.SeverityHigh, "x", 0.79)) {
		t.Fatal("confidence below threshold should not match")
	}
}

func TestSourceModule(t *testing.T) {
	any := Rule{Status: "active", SourceModule: "any"}
	specific := Rule{Status: "active", SourceModule: "dlm"}
	other := Rule{Status: "active", SourceModule: "phm"}
	e := ev(types.ModuleDLM, types.SeverityHigh, "x", 1)
	if !any.Matches(e) {
		t.Fatal(`source_module "any" should match dlm`)
	}
	if !specific.Matches(e) {
		t.Fatal("source_module dlm should match dlm event")
	}
	if other.Matches(e) {
		t.Fatal("source_module phm should not match dlm event")
	}
}

func TestPausedExcluded(t *testing.T) {
	r := Rule{Status: "paused"}
	if r.Matches(ev(types.ModuleDLM, types.SeverityCritical, "x", 1)) {
		t.Fatal("paused rule must never match")
	}
}

func TestEmptyConditionsMatchAll(t *testing.T) {
	r := Rule{Status: "active"} // no constraints
	if !r.Matches(ev(types.ModuleDLM, types.SeverityInformational, "x", 0)) {
		t.Fatal("empty active rule should match any active event")
	}
}

func TestEvaluateMultiple(t *testing.T) {
	rules := []Rule{
		{ID: "r1", Status: "active", Conditions: Conditions{Severity: []string{"high"}}},
		{ID: "r2", Status: "active", SourceModule: "dlm"},
		{ID: "r3", Status: "paused"},
		{ID: "r4", Status: "active", Conditions: Conditions{Severity: []string{"critical"}}},
	}
	matched := Evaluate(rules, ev(types.ModuleDLM, types.SeverityHigh, "x", 1))
	if len(matched) != 2 {
		t.Fatalf("expected 2 matches (r1,r2), got %d: %+v", len(matched), matched)
	}
}
