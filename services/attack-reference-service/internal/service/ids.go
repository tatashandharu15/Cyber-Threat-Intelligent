package service

import "regexp"

// techniqueIDPattern matches a MITRE ATT&CK technique id ("T1566") or
// sub-technique id ("T1566.001"): the letter T, four digits, and an optional
// dot-separated three-digit sub-technique suffix.
var techniqueIDPattern = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// validTechniqueID reports whether id is a well-formed ATT&CK technique id.
func validTechniqueID(id string) bool {
	return techniqueIDPattern.MatchString(id)
}
