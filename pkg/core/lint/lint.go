// Package lint holds the capability lint domain types (spec 3, spec 5
// `smithmark lint`). This file defines only the Finding type, the single shape
// a lint result takes, so pkg/core/verify's VerificationReport can embed a
// Findings slice from M3 onward. The detection heuristics that populate these
// findings, and the declared versus detected gap engine, arrive in Phase 4
// (Task 4.1 onward); this package stays pure and never touches a filesystem,
// exactly like the rest of pkg/core.
package lint

// Finding is one capability lint result: a stable machine readable Code, a
// Severity, a human readable Detail, and the source Location it was found at.
// Its field set and JSON encoding are fixed here in M3 so a VerificationReport
// serialized today carries the same finding shape a Phase 4 build will emit.
type Finding struct {
	Code     string `json:"code"`     // stable, from pkg/core/codes
	Severity string `json:"severity"` // low | medium | high
	Detail   string `json:"detail"`
	Location string `json:"location"` // file:line
}
