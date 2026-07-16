package discover

// This file, unlike refmap.go, is allowed to import "regexp": the header
// comment on refmap.go keeps that one file's import list narrow by
// deliberate choice, not because the package as a whole is under the
// internal/arch import guard (that guard only scans ./pkg/core/..., per
// refmap.go's own comment). ValidOCITag needs a real grammar check rather
// than the hand written byte scans refmap.go uses, so it lives here instead.

import "regexp"

// ociTagGrammar is the OCI distribution spec tag grammar,
// [a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}. It is asserted here as a runtime check
// rather than only in a test, because ValidOCITag is meant for callers
// outside this package (pkg/compose's OCI push path, Task 2.7) that hand it a
// tag they did not necessarily obtain from AttestationRef.
var ociTagGrammar = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$`)

// ValidOCITag reports whether tag matches the OCI distribution spec tag
// grammar. AttestationRef is the normative producer of tags in this
// codebase: it builds every tag from a fixed constant prefix plus lowercase
// hex plus ".att", a shape that is provably safe by construction (decision
// recorded against Task 2.6), so AttestationRef itself never calls
// ValidOCITag. This function exists for callers a step removed from that
// guarantee, such as pkg/compose's push path, which validates a tag as a
// last line of defense before spending any I/O on it, even though
// pkg/discover remains the normative producer.
func ValidOCITag(tag string) bool {
	return ociTagGrammar.MatchString(tag)
}
