// Package verify is the pure verification core (spec 3 rules, spec 5 verify
// semantics, open item U3). It is the single place check outcomes are decided:
// spec 3's rule is that no downstream code reads an envelope back and trusts it,
// so every CheckResult in a VerificationReport is produced here and only here. The
// package is pure in the pkg/core sense: it imports no I/O, bundles arrive as
// bytes the caller already fetched, the verification clock is injected as
// in.Now, and all signature cryptography is delegated to an injected
// SignatureVerifier (implemented in pkg/compose behind the wasip1 build tag).
//
// npm provenance is parsed here directly from its bundle JSON with the standard
// library alone (encoding/json plus encoding/base64): extracting the enveloped
// statement's predicateType needs no protobuf types and no cryptography, so it
// stays inside the purity guard without an extra interface hop. Cryptographic
// verification of that provenance, which does need the Sigstore trust root,
// lands in M6; until then NPM_PROVENANCE_VERIFIED is informational and reports
// that it was not attempted.
package verify

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// CheckResult is one verification check outcome. Passed is the pass or fail
// bit the exit code contract keys off (D4), but only for failing class checks:
// Informational marks a check whose outcome never drives an exit code and is
// left for downstream policy (assayward) to weigh. Detail is a human readable
// explanation, present on failures and on notable passes and omitted otherwise.
type CheckResult struct {
	Code          string `json:"code"`
	Passed        bool   `json:"passed"`
	Informational bool   `json:"informational,omitempty"` // never drives exit codes; policy consumes it
	Detail        string `json:"detail,omitempty"`
}

// VerificationReport is the full result of verifying one artifact. Checks are
// sorted by Code for determinism. Findings is the capability lint result set,
// an empty non nil slice until Phase 4 populates it, so it always renders as
// [] rather than null. Evidence is the assayward compatible evidence block
// (spec 7, U5); Run always leaves it nil, so it renders as null until a
// caller builds one with EvidenceBlock and assigns it before serializing
// (Task 3.5 wires the CLI to do exactly that). VerifiedAt is the injected
// clock, never the wall clock.
type VerificationReport struct {
	Subject    manifest.ArtifactRef `json:"subject"`
	Checks     []CheckResult        `json:"checks"`
	Findings   []lint.Finding       `json:"findings"`
	Evidence   json.RawMessage      `json:"evidence"`
	VerifiedAt time.Time            `json:"verifiedAt"`
	// WinningBundle is the zero based index into Input.Bundles of the candidate
	// this report reflects when one passed every failing class cryptographic
	// stage, or -1 when none did (no bundle at all, or every candidate failed a
	// failing class check). The CLI reads it to hand EvidenceBlock exactly the
	// bytes whose outcomes the report records. It is json:"-" on purpose: the
	// wire report retains no bundle bytes, and excluding the index keeps the
	// serialized report byte identical to a build without this field.
	WinningBundle int `json:"-"`
}

// FailingChecksFailed reports whether any failing class check in r did not pass:
// a check that is not informational and whose Passed bit is false. It is the
// single authority for the exit code contract's "did verification fail" question
// (D4). A fully valid report contains informational checks with Passed false by
// design (REKOR_INCLUSION_VALID and the npm interop checks for a key based
// offline bundle), so a naive "any failed check" test would wrongly reject a
// valid artifact; every exit mapping keys off this helper instead so the rule
// lives in exactly one place.
func FailingChecksFailed(r *VerificationReport) bool {
	for _, c := range r.Checks {
		if !c.Informational && !c.Passed {
			return true
		}
	}
	return false
}

// Input is everything Run needs to verify one artifact. Ref is the identity and
// digest the caller expects, resolved by discovery. Bundles are the candidate
// attestation bundles, already fetched, evaluated in order. NPMProvenance is an
// optional npm provenance bundle for the interop checks. TrustMaterial is a PEM
// public key for the key based bundles of v0.1; the Sigstore TUF root lands in
// M6. Now is the injected verification clock.
type Input struct {
	Ref           manifest.ArtifactRef
	Bundles       [][]byte
	NPMProvenance []byte
	TrustMaterial []byte
	Now           time.Time
}

// SignatureVerifier abstracts the sigstore stack so the pure core stays
// buildable everywhere. pkg/compose provides the native implementation
// everywhere except wasip1 (behind the !wasip1 build tag) and a fail closed
// stub under wasip1, where the sigstore stack does not compile (spec 2.1). Run
// never imports pkg/compose; the CLI wires an implementation in.
type SignatureVerifier interface {
	// VerifyBundle checks the bundle signature against trust material and
	// returns the DSSE payload statement bytes plus whether a transparency
	// log inclusion was cryptographically verified.
	VerifyBundle(bundle, trustMaterial []byte, now time.Time) (statement []byte, rekorIncluded bool, err error)
}

// Run verifies one artifact and returns its report. It returns a non nil error
// only when verification could not be attempted at all, meaning the injected
// verifier reported a configuration or platform failure that applies to every
// candidate equally (empty or unsupported trust material, or an unavailable
// platform). Every ordinary outcome, including a bad signature, a wrong
// subject, or no attestation at all, is recorded as a failed check in a
// completed report with a nil error, so the CLI derives its exit code from the
// report rather than from an error.
//
// When multiple candidate bundles are supplied, Run evaluates them in order and
// reports the first candidate that passes every failing class cryptographic
// stage (signature, predicate version, subject digest, manifest schema). If no
// candidate passes them all, the report reflects the first candidate's
// outcomes. Either way the multi candidate summary lands in the
// ATTESTATION_MISSING detail rather than in an extra check line.
func Run(in Input, sv SignatureVerifier) (*VerificationReport, error) {
	report := &VerificationReport{
		Subject:    in.Ref,
		Findings:   []lint.Finding{},
		Evidence:   nil,
		VerifiedAt: in.Now,
	}

	n := len(in.Bundles)
	if n == 0 {
		// Presence stage, U3: no bundle fails ATTESTATION_MISSING and short
		// circuits, marking every bundle derived check not evaluated. No candidate
		// is reflected, so there is no winning bundle. The two npm provenance
		// checks are the exception: provenance is a separate, input driven signal
		// from any primary attestation bundle, so PROVENANCE_PRESENT and
		// NPM_PROVENANCE_VERIFIED are still evaluated against in.NPMProvenance
		// here (both informational, so neither drives an exit code either way).
		checks := missingAttestationChecks()
		set := func(code string, passed, informational bool, detail string) {
			checks[code] = CheckResult{Code: code, Passed: passed, Informational: informational, Detail: detail}
		}
		evalProvenance(in, set)
		report.Checks = sortChecks(checks)
		report.WinningBundle = -1
		return report, nil
	}

	var firstChecks map[string]CheckResult
	selected := map[string]CheckResult(nil)
	selectedIdx := 0
	passedFound := false
	for i, b := range in.Bundles {
		checks, passedFailing, cfgErr := evaluateCandidate(in, b, sv)
		if cfgErr != nil {
			// A configuration or platform failure applies to every candidate, so
			// verification as a whole could not be attempted.
			return nil, cfgErr
		}
		if i == 0 {
			firstChecks = checks
		}
		if passedFailing {
			selected = checks
			selectedIdx = i
			passedFound = true
			break
		}
	}
	if selected == nil {
		selected = firstChecks
		selectedIdx = 0
	}

	// The presence check passes when at least one bundle is present; its detail
	// carries the multi candidate summary.
	selected[codes.AttestationMissing] = attestationPresentResult(n, selectedIdx, passedFound)
	report.Checks = sortChecks(selected)
	// The winning bundle is the passing candidate the report reflects; when no
	// candidate passed every failing class stage the report reflects the first
	// candidate's outcomes but there is no winner to build evidence from.
	if passedFound {
		report.WinningBundle = selectedIdx
	} else {
		report.WinningBundle = -1
	}
	return report, nil
}

// evidenceArtifact mirrors assayward's pkg/core.ArtifactRef (U5): a kind
// tagged name and an algorithm keyed digest set, pinned by contract_test.go
// against the real assayward module.
type evidenceArtifact struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
	Source string            `json:"source,omitempty"`
}

// evidenceAttestation mirrors assayward's pkg/core.Attestation (U5). Envelope
// is []byte, the same field type assayward uses, so encoding/json's standard
// base64 handling of byte slices is what makes the two sides round trip
// without either repo agreeing on an encoding by hand.
type evidenceAttestation struct {
	PredicateType string `json:"predicateType"`
	Envelope      []byte `json:"envelope"`
	Verified      bool   `json:"verified"`
	SignatureNote string `json:"signatureNote,omitempty"`
}

// evidenceBlock mirrors assayward's pkg/core.Evidence (U5). Identity is
// omitted entirely rather than marshaled as null: smithmark carries no
// workload identity, and assayward's field is optional (omitempty).
type evidenceBlock struct {
	Artifact      evidenceArtifact      `json:"artifact"`
	Attestations  []evidenceAttestation `json:"attestations"`
	SchemaVersion string                `json:"schemaVersion"`
	FetchedAt     time.Time             `json:"fetchedAt"`
}

// evidenceSchemaVersion must equal assaywardcore.EvidenceSchemaVersion;
// pinned by contract_test.go. verify.go itself imports no assayward package
// (the pkg/core purity guard), so this constant is smithmark's own mirror of
// that value rather than a reference to it; the contract test is what proves
// the two stay equal.
const evidenceSchemaVersion = "0.2.0"

// EvidenceBlock builds the assayward compatible Evidence block for r (spec 7,
// U5). bundle is the winning candidate's raw bytes, the same bundle whose
// outcomes r.Checks already records: the report itself retains no bundle
// bytes, so the caller (the CLI, Task 3.5) passes them in.
//
// The block maps r.Subject into assayward's kind tagged ArtifactRef{Kind,
// Name, Digest, Source} directly: Kind carries r.Subject.Kind (no more prose
// shim in SignatureNote), and Digest carries every algorithm the subject's
// DigestSet declares (see artifactDigest), since ArtifactRef supports more
// than one. SchemaVersion is evidenceSchemaVersion, pinned equal to
// assayward's EvidenceSchemaVersion by contract_test.go. Attestations always
// has exactly one entry: PredicateType is the smithmark agent capability v1
// constant, Envelope is the DSSE envelope JSON extracted from bundle's
// protojson dsseEnvelope field, and Verified is the SIGNATURE_VALID outcome
// Run already decided, never reevaluated here. FetchedAt is r.VerifiedAt, the
// injected clock, never the wall clock.
//
// assayward's SLSA subject matching is algorithm aware, so a
// "smithmark-bundle-v1:" keyed digest round trips through Digest without any
// prefix stripping or other mangling.
func (r *VerificationReport) EvidenceBlock(bundle []byte) (json.RawMessage, error) {
	digest, err := artifactDigest(r.Subject.Digest)
	if err != nil {
		return nil, err
	}
	parts, err := extractDSSEParts(bundle)
	if err != nil {
		return nil, err
	}

	verified := false
	for _, c := range r.Checks {
		if c.Code == codes.SignatureValid {
			verified = c.Passed
			break
		}
	}
	note := fmt.Sprintf("smithmark agent capability attestation; signature %s", validityWord(verified))

	block := evidenceBlock{
		Artifact: evidenceArtifact{
			Kind:   string(r.Subject.Kind),
			Name:   manifest.SubjectName(r.Subject),
			Digest: digest,
		},
		Attestations: []evidenceAttestation{{
			PredicateType: manifest.PredicateType,
			Envelope:      []byte(parts.envelope),
			Verified:      verified,
			SignatureNote: note,
		}},
		SchemaVersion: evidenceSchemaVersion,
		FetchedAt:     r.VerifiedAt,
	}
	return json.Marshal(block)
}

// artifactDigest copies a DigestSet into the map[string]string shape
// assayward's ArtifactRef.Digest expects (U5). ArtifactRef is not limited to
// one algorithm the way ImageRef.Digest was, so any non empty set is valid;
// only a subject with zero digests is the subject's own shape being wrong for
// this purpose, not an internal failure, so it is coded
// STATEMENT_SUBJECT_INVALID rather than InternalError.
func artifactDigest(d manifest.DigestSet) (map[string]string, error) {
	if len(d) == 0 {
		return nil, codes.E(codes.StatementSubjectInvalid,
			"assayward Evidence requires at least one subject digest, got 0")
	}
	out := make(map[string]string, len(d))
	for alg, hex := range d {
		out[alg] = hex
	}
	return out, nil
}

// validityWord renders a boolean as the "valid" or "invalid" word
// SignatureNote's prose carries.
func validityWord(verified bool) string {
	if verified {
		return "valid"
	}
	return "invalid"
}

// dsseParts holds the two projections of a protojson sigstore bundle's
// dsseEnvelope that this package needs: the raw envelope object (EvidenceBlock
// carries it verbatim into the Evidence block) and its decoded DSSE payload
// bytes (provenancePredicateType reads the enveloped statement's
// predicateType). payload is nil when the envelope carries no payload field.
type dsseParts struct {
	envelope json.RawMessage
	payload  []byte
}

// extractDSSEParts performs the single lenient field walk both EvidenceBlock and
// provenancePredicateType rely on: it locates the dsseEnvelope object embedded
// in a bundle's own JSON and, when a payload field is present, base64 decodes
// it. This needs no protobuf types and no cryptography, so it stays inside the
// pkg/core purity guard without an extra interface hop through
// SignatureVerifier. The gen kit's tamperSignature (testdata/gen/gen.go) does
// the same untyped walk over the signatures array for a different purpose; this
// is its typed twin here.
func extractDSSEParts(bundleBytes []byte) (dsseParts, error) {
	var doc struct {
		DSSEEnvelope json.RawMessage `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleBytes, &doc); err != nil {
		return dsseParts{}, fmt.Errorf("decoding bundle JSON: %w", err)
	}
	if len(doc.DSSEEnvelope) == 0 {
		return dsseParts{}, errors.New("bundle carries no dsseEnvelope object")
	}
	var inner struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(doc.DSSEEnvelope, &inner); err != nil {
		return dsseParts{}, fmt.Errorf("decoding DSSE envelope: %w", err)
	}
	parts := dsseParts{envelope: doc.DSSEEnvelope}
	if inner.Payload != "" {
		payload, err := base64.StdEncoding.DecodeString(inner.Payload)
		if err != nil {
			return dsseParts{}, fmt.Errorf("decoding DSSE payload as base64: %w", err)
		}
		parts.payload = payload
	}
	return parts, nil
}

// evaluateCandidate runs the full stage pipeline for a single bundle and
// returns the eight non presence checks, whether the candidate passed every
// failing class cryptographic stage, and a non nil configuration error when the
// verifier could not be used at all. The presence check is added by Run.
func evaluateCandidate(in Input, bundleBytes []byte, sv SignatureVerifier) (map[string]CheckResult, bool, error) {
	checks := map[string]CheckResult{}
	set := func(code string, passed, informational bool, detail string) {
		checks[code] = CheckResult{Code: code, Passed: passed, Informational: informational, Detail: detail}
	}

	// Signature stage. The verifier owns all cryptography; a config or platform
	// error is propagated to Run rather than recorded as a check failure.
	stmtBytes, rekorIncluded, err := sv.VerifyBundle(bundleBytes, in.TrustMaterial, in.Now)
	if err != nil {
		if isConfigError(err) {
			return nil, false, err
		}
		set(codes.SignatureValid, false, false,
			fmt.Sprintf("the attestation signature did not verify: %v", err))
		const notEval = "not evaluated because the attestation signature did not verify"
		set(codes.RekorInclusionValid, false, true, notEval)
		set(codes.PredicateVersionUnsupported, false, false, notEval)
		set(codes.SubjectDigestMatch, false, false, notEval)
		set(codes.ManifestSchemaValid, false, false, notEval)
		// Provenance is a separate input from the primary statement, so it is
		// still evaluated even when the primary signature fails.
		evalProvenance(in, set)
		set(codes.DependencySBOMMissing, false, true, notEval)
		return checks, false, nil
	}
	set(codes.SignatureValid, true, false, "")

	// Transparency log inclusion, informational: key based offline bundles carry
	// no entry, and an inclusion proof cannot be checked offline without the log
	// key from the Sigstore trust root (M6).
	if rekorIncluded {
		set(codes.RekorInclusionValid, true, true, "")
	} else {
		set(codes.RekorInclusionValid, false, true, rekorAbsentDetail)
	}

	// Strict parse and predicate version. An unknown predicateType, or a
	// predicate whose schemaVersion implies a structure the strict parser
	// rejects, fails here; a parseable v1 predicate whose schemaVersion is merely
	// unsupported parses cleanly and is caught by MANIFEST_SCHEMA_VALID instead.
	stmt, perr := manifest.ParseStatement(stmtBytes)
	if perr != nil {
		set(codes.PredicateVersionUnsupported, false, false, predicateParseDetail(perr))
		const notEval = "not evaluated because the attestation statement did not parse"
		set(codes.SubjectDigestMatch, false, false, notEval)
		set(codes.ManifestSchemaValid, false, false, notEval)
		evalProvenance(in, set)
		set(codes.DependencySBOMMissing, false, true, notEval)
		return checks, false, nil
	}
	set(codes.PredicateVersionUnsupported, true, false, "")

	// Subject digest match against the caller's expected reference.
	if detail, ok := digestMatch(in.Ref.Digest, stmt.Subject[0].Digest); ok {
		set(codes.SubjectDigestMatch, true, false, "")
	} else {
		set(codes.SubjectDigestMatch, false, false, detail)
	}

	// Manifest semantic validation. Every issue is aggregated into the detail,
	// the same way attest reports a manifest it refuses to sign.
	if issues := stmt.Predicate.Validate(); len(issues) == 0 {
		set(codes.ManifestSchemaValid, true, false, "")
	} else {
		set(codes.ManifestSchemaValid, false, false, aggregateIssues(issues))
	}

	// npm provenance interop, both informational.
	evalProvenance(in, set)

	// Dependency SBOM reference presence, informational.
	if stmt.Predicate.Dependencies != nil {
		set(codes.DependencySBOMMissing, true, true, "")
	} else {
		set(codes.DependencySBOMMissing, false, true,
			"the capability manifest declares no dependency SBOM reference")
	}

	passedFailing := checks[codes.SignatureValid].Passed &&
		checks[codes.PredicateVersionUnsupported].Passed &&
		checks[codes.SubjectDigestMatch].Passed &&
		checks[codes.ManifestSchemaValid].Passed
	return checks, passedFailing, nil
}

// evalProvenance sets the two npm provenance checks. PROVENANCE_PRESENT passes
// when a provenance bundle is supplied and its enveloped statement declares a
// SLSA provenance predicate. NPM_PROVENANCE_VERIFIED is always failed in v0.1:
// full cryptographic verification needs the Sigstore trust root, and the key
// based trust material of v0.1 does not suit it, so the check reports that it
// was not attempted rather than claiming a verification it did not perform.
func evalProvenance(in Input, set func(code string, passed, informational bool, detail string)) {
	switch {
	case len(in.NPMProvenance) == 0:
		set(codes.ProvenancePresent, false, true, "no npm provenance attestation was provided")
	default:
		pt, err := provenancePredicateType(in.NPMProvenance)
		switch {
		case err != nil:
			set(codes.ProvenancePresent, false, true,
				fmt.Sprintf("npm provenance did not parse as a sigstore bundle: %v", err))
		case !isSLSAProvenance(pt):
			set(codes.ProvenancePresent, false, true,
				fmt.Sprintf("npm provenance predicate type %q is not a SLSA provenance predicate", pt))
		default:
			set(codes.ProvenancePresent, true, true, "")
		}
	}
	set(codes.NPMProvenanceVerified, false, true,
		"full verification requires the Sigstore trust root, a later addition not performed in v0.1")
}

// rekorAbsentDetail explains a false REKOR_INCLUSION_VALID for a key based
// offline bundle. It is a legitimate absence, not a failure that should worry a
// caller, which is why the check is informational.
const rekorAbsentDetail = "no transparency log inclusion entry; key based offline bundles carry none, and verifying an inclusion proof offline needs the log key from the Sigstore trust root, a later addition"

// missingAttestationChecks builds the check set for the no bundle case: the
// presence check fails and every other check is present but not evaluated, so a
// consumer sees the full check surface with a single clear cause.
func missingAttestationChecks() map[string]CheckResult {
	const notEval = "not evaluated because no attestation bundle was found"
	m := map[string]CheckResult{
		codes.AttestationMissing:          {Code: codes.AttestationMissing, Passed: false, Detail: "no attestation bundle was found for the artifact"},
		codes.SignatureValid:              {Code: codes.SignatureValid, Passed: false, Detail: notEval},
		codes.RekorInclusionValid:         {Code: codes.RekorInclusionValid, Passed: false, Informational: true, Detail: notEval},
		codes.PredicateVersionUnsupported: {Code: codes.PredicateVersionUnsupported, Passed: false, Detail: notEval},
		codes.SubjectDigestMatch:          {Code: codes.SubjectDigestMatch, Passed: false, Detail: notEval},
		codes.ManifestSchemaValid:         {Code: codes.ManifestSchemaValid, Passed: false, Detail: notEval},
		codes.ProvenancePresent:           {Code: codes.ProvenancePresent, Passed: false, Informational: true, Detail: notEval},
		codes.NPMProvenanceVerified:       {Code: codes.NPMProvenanceVerified, Passed: false, Informational: true, Detail: notEval},
		codes.DependencySBOMMissing:       {Code: codes.DependencySBOMMissing, Passed: false, Informational: true, Detail: notEval},
	}
	return m
}

// attestationPresentResult builds the passing presence check and folds the
// multi candidate summary into its detail. For a single bundle the detail stays
// empty; the summary only appears when more than one candidate was supplied,
// naming whether the reported candidate passed and how many were considered.
func attestationPresentResult(n, selectedIdx int, passed bool) CheckResult {
	r := CheckResult{Code: codes.AttestationMissing, Passed: true}
	if n > 1 {
		if passed {
			r.Detail = fmt.Sprintf("selected attestation candidate %d of %d that satisfied every cryptographic check", selectedIdx+1, n)
		} else {
			r.Detail = fmt.Sprintf("evaluated %d attestation candidates; none satisfied every cryptographic check, reporting the first", n)
		}
	}
	return r
}

// digestMatch reports whether the caller's expected digest set matches the
// attested subject digest set. Both the algorithm keys and their hex values
// must match; a differing key set or a differing value is a failure whose
// detail names both sets in full, so a caller sees exactly what was expected
// against what was attested.
//
// The check is deliberately exact today. Should it ever be relaxed, the only
// safe direction is to require the expected set to be a subset of the attested
// set: every algorithm the caller expects must be attested with a matching
// value. Accepting mere overlap (a single matching algorithm among several
// expected, or among several attested) must never be the rule, since an
// attacker who controls one weak or colliding algorithm could satisfy the
// check while the strong digest the caller cares about disagrees.
func digestMatch(expected, attested manifest.DigestSet) (string, bool) {
	if sameKeys(expected, attested) {
		mismatch := false
		for k, v := range expected {
			if attested[k] != v {
				mismatch = true
				break
			}
		}
		if !mismatch {
			return "", true
		}
	}
	return fmt.Sprintf("attested subject digest does not match the artifact: expected %s, attested %s",
		formatDigestSet(expected), formatDigestSet(attested)), false
}

// sameKeys reports whether two digest sets carry exactly the same algorithm
// keys.
func sameKeys(a, b manifest.DigestSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

// formatDigestSet renders a digest set deterministically as {alg:hex, ...} with
// keys in sorted order, so a mismatch detail is stable across runs.
func formatDigestSet(d manifest.DigestSet) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ":" + d[k]
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// aggregateIssues folds every semantic validation issue into one detail as
// "CODE at path", joined by semicolons, matching how attest surfaces a manifest
// it refuses to sign so a maker sees all of them at once.
func aggregateIssues(issues []manifest.Issue) string {
	parts := make([]string, len(issues))
	for i, is := range issues {
		parts[i] = fmt.Sprintf("%s at %s", is.Code, is.Path)
	}
	return "the capability manifest is invalid: " + strings.Join(parts, "; ")
}

// RegistryChecks builds the two check results `smithmark registry check`
// always reports for one MCP Registry entry (spec 5, decision D5). Both are
// informational: neither ever drives an exit code (the D4 contract), and the
// cmd/smithmark registry command merges them straight into a report's Checks
// rather than constructing CheckResult literals itself, keeping spec 3's
// single authority rule intact (TestCheckOutcomesSetOnlyInVerifyPackage).
//
// REGISTRY_ATTESTATION_REF_PRESENT passes when hasAttRef is true: the entry
// carries the MCP Registry provenance RFC's proposed attestation reference
// field. No real registry entry carries that field today (the RFC, Task 6.4,
// is what would add it), so this fails for every real entry `registry check`
// fetches; that failure is the RFC gap the command demonstrates.
//
// HOSTED_ENDPOINT_UNSUPPORTED passes when hasNPM is true: the entry carries
// an npm package, so verification continues into that pipeline and no
// hosted endpoint blocks anything, regardless of what packageTypes or
// remotes also happen to be present. Otherwise it fails with one of two
// distinct details, so a caller is never told about a remote endpoint that
// does not exist: when the entry carries no packages at all and at least
// one remote (the true "remote only" shape D5 names), the detail lists
// every entry in remotes; when the entry carries some other, non npm
// distribution instead (another package ecosystem, or nothing at all), the
// detail instead reports that this build carries no distribution it can
// verify, naming whatever packageTypes were seen.
func RegistryChecks(hasAttRef bool, hasNPM bool, packageTypes []string, remotes []string) []CheckResult {
	attDetail := ""
	if !hasAttRef {
		attDetail = "this MCP Registry entry carries no attestation reference field; that field does not exist in the registry schema today, which is the gap the MCP Registry provenance RFC proposes to close"
	}

	hostedPassed := true
	hostedDetail := ""
	remoteOnly := len(packageTypes) == 0 && len(remotes) > 0
	switch {
	case hasNPM:
		// Passes; no detail needed.
	case remoteOnly:
		hostedPassed = false
		hostedDetail = fmt.Sprintf(
			"this build verifies artifact distributed (npm) servers only; this registry entry points only at remote endpoint(s): %s",
			strings.Join(remotes, ", "))
	default:
		hostedPassed = false
		hostedDetail = unsupportedDistributionDetail(packageTypes)
	}

	return []CheckResult{
		{Code: codes.RegistryAttestationRefPresent, Passed: hasAttRef, Informational: true, Detail: attDetail},
		{Code: codes.HostedEndpointUnsupported, Passed: hostedPassed, Informational: true, Detail: hostedDetail},
	}
}

// unsupportedDistributionDetail explains a failing HOSTED_ENDPOINT_UNSUPPORTED
// for a registry entry that carries no npm package and is not remote only
// either: some other package ecosystem entirely (pypi, oci, and so on), or no
// distribution at all. Naming packageTypes (or their absence) keeps this
// detail distinct from the remote only case, whose own detail names
// endpoints instead of package types.
func unsupportedDistributionDetail(packageTypes []string) string {
	if len(packageTypes) == 0 {
		return "this build verifies artifact distributed (npm) servers only; this registry entry carries no packages and no remote endpoints at all"
	}
	return fmt.Sprintf(
		"this build verifies artifact distributed (npm) servers only; this registry entry carries no npm package, only: %s",
		strings.Join(packageTypes, ", "))
}

// predicateParseDetail distinguishes the causes PREDICATE_VERSION_UNSUPPORTED
// covers: a statement missing exactly one valid subject (framed as a subject
// problem, keyed on the wrapped STATEMENT_SUBJECT_INVALID code rather than on
// message text so the framing never drifts with wording), an unknown
// predicateType, which ParseStatement names explicitly, and any other strict
// parse failure of the predicate, which stands in for a predicate schema this
// build cannot structurally understand.
func predicateParseDetail(err error) string {
	var coded *codes.Error
	if errors.As(err, &coded) && coded.Code == codes.StatementSubjectInvalid {
		return fmt.Sprintf("the attestation statement does not carry exactly one valid subject: %v", err)
	}
	if strings.Contains(err.Error(), "predicateType") {
		return fmt.Sprintf("the attestation predicate type is not one this build understands: %v", err)
	}
	return fmt.Sprintf("the attestation predicate could not be parsed as a supported predicate schema: %v", err)
}

// provenancePredicateType extracts the predicateType of an npm provenance
// bundle's enveloped in-toto statement using only the standard library: it
// reuses extractDSSEParts to reach the decoded DSSE payload, then reads the
// statement's predicateType. This needs no protobuf types and no cryptography,
// so provenance presence detection stays inside the pkg/core purity guard
// without an extra interface hop through the SignatureVerifier.
func provenancePredicateType(raw []byte) (string, error) {
	parts, err := extractDSSEParts(raw)
	if err != nil {
		return "", err
	}
	if len(parts.payload) == 0 {
		return "", errors.New("bundle carries no DSSE envelope payload")
	}
	var statement struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(parts.payload, &statement); err != nil {
		return "", fmt.Errorf("decoding enveloped in-toto statement: %w", err)
	}
	if statement.PredicateType == "" {
		return "", errors.New("enveloped statement carries no predicateType")
	}
	return statement.PredicateType, nil
}

// SLSAProvenancePrefix is the URI prefix that identifies the SLSA provenance
// predicate family (for example .../provenance/v1). PROVENANCE_PRESENT accepts
// any version within it. It is exported so pkg/discover's fetchNPMProvenance
// selects npm's provenance among the attestations npm returns by this exact
// same prefix, which means the presence check decided here and discovery's own
// selection can never drift onto different predicate families.
const SLSAProvenancePrefix = "https://slsa.dev/provenance/"

// isSLSAProvenance reports whether a predicate type is in the SLSA provenance
// family.
func isSLSAProvenance(predicateType string) bool {
	return strings.HasPrefix(predicateType, SLSAProvenancePrefix)
}

// isConfigError reports whether err is a coded configuration or platform
// failure that means verification could not be attempted at all, as opposed to
// an ordinary signature verification failure. Run propagates the former and
// records the latter as a failed SIGNATURE_VALID check.
func isConfigError(err error) bool {
	var coded *codes.Error
	if !errors.As(err, &coded) {
		return false
	}
	return coded.Code == codes.SigningConfigInvalid || coded.Code == codes.SigningUnavailablePlatform
}

// sortChecks flattens a check map into a slice ordered by Code, the stable
// order every consumer and the golden snapshot rely on.
func sortChecks(m map[string]CheckResult) []CheckResult {
	out := make([]CheckResult, 0, len(m))
	for _, c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}
