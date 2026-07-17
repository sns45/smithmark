package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sns45/smithmark/internal/golden"
	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
	"github.com/sns45/smithmark/pkg/discover"
)

// Fixture layout, relative to this test package (pkg/core/verify). The signed
// bundles and the throwaway public key are the Task 3.1 committed fixtures; the
// npm attestations response is the Task 3.2 discovery fixture. The tests read
// them and pass bytes into Run, so the core itself stays pure.
const (
	fixtureRoot         = "../../../testdata"
	signatureDir        = fixtureRoot + "/signature"
	pubKeyPath          = signatureDir + "/test-signing-key-pub.pem"
	skillRoot           = fixtureRoot + "/skills/hello-skill"
	npmAttestationsPath = fixtureRoot + "/npm/attestations.json"
)

// The fabricated npm subject digest the valid npm fixtures attest, matching the
// constant the generation kit signs in. The digest-mismatch fixture carries a
// different one; the mismatch is what SUBJECT_DIGEST_MATCH must catch.
const fakeNPMDigestHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// slsaProvenancePredicate is the predicate type of the SLSA provenance entry
// inside the npm attestations fixture; it is the one PROVENANCE_PRESENT accepts.
const slsaProvenancePredicate = "https://slsa.dev/provenance/v1"

// fixedNow is the injected verification clock every deterministic assertion
// uses (2026-07-16T00:00:00Z), matching the fixed generatedAt the fixtures
// were signed with.
var fixedNow = time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)

// loadTrust reads the committed throwaway public key PEM the fixtures were
// signed against; it is the trust material Run passes to the verifier.
func loadTrust(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(pubKeyPath)
	if err != nil {
		t.Fatalf("reading committed public key (run `go run ./testdata/gen` to generate fixtures): %v", err)
	}
	return raw
}

// loadBundle reads one committed signed bundle fixture as raw bytes.
func loadBundle(t *testing.T, subject, variant string) []byte {
	t.Helper()
	path := filepath.Join(signatureDir, subject, variant+".sigstore.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s (run `go run ./testdata/gen`): %v", path, err)
	}
	return raw
}

// skillRef reconstructs the hello-skill artifact reference through the real
// discovery and bundle path, so the expected subject digest tracks the skill's
// on disk content exactly as attest and the fixture kit compute it. Its digest
// is the true digest the valid skill fixture attests, so SUBJECT_DIGEST_MATCH
// passes for the valid variant and fails for digest-mismatch.
func skillRef(t *testing.T) manifest.ArtifactRef {
	t.Helper()
	decl, err := discover.LoadDeclared(filepath.Join(skillRoot, "smithmark.yaml"))
	if err != nil {
		t.Fatalf("loading hello-skill declaration: %v", err)
	}
	files, _, info, err := discover.WalkSkill(skillRoot, decl.Executables)
	if err != nil {
		t.Fatalf("walking hello-skill: %v", err)
	}
	dg, err := bundle.Digest(files)
	if err != nil {
		t.Fatalf("digesting hello-skill bundle: %v", err)
	}
	ds, err := manifest.SubjectDigestFromBundle(dg)
	if err != nil {
		t.Fatalf("converting hello-skill bundle digest: %v", err)
	}
	return manifest.ArtifactRef{
		Kind:    manifest.KindSkill,
		Name:    "hello-skill",
		Version: info.Version,
		Digest:  ds,
		Source:  manifest.SourceLocal,
	}
}

// npmRef is the synthetic fake-caller npm reference the npm fixtures attest.
func npmRef() manifest.ArtifactRef {
	return manifest.ArtifactRef{
		Kind:    manifest.KindMCPServer,
		Name:    "fake-caller",
		Version: "1.0.0",
		Digest:  manifest.DigestSet{"sha512": fakeNPMDigestHex},
		Source:  manifest.SourceNPM,
	}
}

// slsaProvenanceBundle extracts the SLSA provenance entry's bundle bytes from
// the npm attestations fixture, exactly the bytes discovery hands to Run as
// NPMProvenance.
func slsaProvenanceBundle(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(npmAttestationsPath)
	if err != nil {
		t.Fatalf("reading npm attestations fixture: %v", err)
	}
	var parsed struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decoding npm attestations fixture: %v", err)
	}
	for _, a := range parsed.Attestations {
		if a.PredicateType == slsaProvenancePredicate {
			return []byte(a.Bundle)
		}
	}
	t.Fatalf("npm attestations fixture carries no SLSA provenance entry")
	return nil
}

// checkFor returns the CheckResult with the given code, failing the test when
// it is absent so a missing check is never mistaken for a passing one.
func checkFor(t *testing.T, report *verify.VerificationReport, code string) verify.CheckResult {
	t.Helper()
	for _, c := range report.Checks {
		if c.Code == code {
			return c
		}
	}
	t.Fatalf("report carries no check %s; checks present: %v", code, checkCodes(report))
	return verify.CheckResult{}
}

func checkCodes(report *verify.VerificationReport) []string {
	out := make([]string, len(report.Checks))
	for i, c := range report.Checks {
		out[i] = c.Code
	}
	return out
}

// assertPassed and assertFailed keep the matrix assertions terse.
func assertPassed(t *testing.T, report *verify.VerificationReport, code string) {
	t.Helper()
	if c := checkFor(t, report, code); !c.Passed {
		t.Errorf("check %s = failed, want passed; detail: %s", code, c.Detail)
	}
}

func assertFailed(t *testing.T, report *verify.VerificationReport, code string) verify.CheckResult {
	t.Helper()
	c := checkFor(t, report, code)
	if c.Passed {
		t.Errorf("check %s = passed, want failed", code)
	}
	return c
}

// failingClassCodes are the checks that drive exit 1 in the CLI; none of them
// may be marked informational.
var failingClassCodes = []string{
	codes.AttestationMissing,
	codes.SignatureValid,
	codes.SubjectDigestMatch,
	codes.ManifestSchemaValid,
	codes.PredicateVersionUnsupported,
}

// informationalCodes are the checks that never drive an exit code.
var informationalCodes = []string{
	codes.RekorInclusionValid,
	codes.ProvenancePresent,
	codes.NPMProvenanceVerified,
	codes.DependencySBOMMissing,
}

func TestValidAttestationPassesEveryFailingCheck(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "valid")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, code := range failingClassCodes {
		assertPassed(t, report, code)
	}
	// The classification is part of the contract: failing class checks are not
	// informational, informational checks are.
	for _, code := range failingClassCodes {
		if checkFor(t, report, code).Informational {
			t.Errorf("failing class check %s must not be informational", code)
		}
	}
	for _, code := range informationalCodes {
		if !checkFor(t, report, code).Informational {
			t.Errorf("check %s must be informational", code)
		}
	}
	// The report always completes with a clock stamped from the injected Now.
	if !report.VerifiedAt.Equal(fixedNow) {
		t.Errorf("VerifiedAt = %s, want %s", report.VerifiedAt, fixedNow)
	}
	// Findings is empty but non nil so it serializes as [], not null.
	if report.Findings == nil {
		t.Error("Findings must be a non nil empty slice")
	}
}

func TestTamperedSignatureFailsSignatureValid(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "tampered")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	assertFailed(t, report, codes.SignatureValid)
	// A failed signature stops trusting the payload derived checks: they must
	// not be reported as passed.
	for _, code := range []string{codes.SubjectDigestMatch, codes.ManifestSchemaValid, codes.PredicateVersionUnsupported} {
		if checkFor(t, report, code).Passed {
			t.Errorf("check %s passed after a signature failure; payload derived checks must not be trusted", code)
		}
	}
}

func TestSubjectDigestMismatchFailsAndNamesBothSets(t *testing.T) {
	ref := skillRef(t)
	report, err := verify.Run(verify.Input{
		Ref:           ref,
		Bundles:       [][]byte{loadBundle(t, "skill", "digest-mismatch")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The bundle is validly signed over a wrong subject, so the signature and
	// parse pass while the digest match fails.
	assertPassed(t, report, codes.SignatureValid)
	assertPassed(t, report, codes.PredicateVersionUnsupported)
	c := assertFailed(t, report, codes.SubjectDigestMatch)

	trueHex := ref.Digest["smithmark-bundle-v1"]
	const wrongHex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if !strings.Contains(c.Detail, trueHex) {
		t.Errorf("SUBJECT_DIGEST_MATCH detail does not name the expected digest %s: %s", trueHex, c.Detail)
	}
	if !strings.Contains(c.Detail, wrongHex) {
		t.Errorf("SUBJECT_DIGEST_MATCH detail does not name the attested digest %s: %s", wrongHex, c.Detail)
	}
}

func TestSchemaInvalidFailsManifestSchemaValid(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "schema-invalid")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The predicate type is v1, so the parse stage passes; only the semantic
	// validation catches the unsupported schemaVersion.
	assertPassed(t, report, codes.PredicateVersionUnsupported)
	c := assertFailed(t, report, codes.ManifestSchemaValid)
	if !strings.Contains(c.Detail, codes.ManifestSchemaVersionUnsupported) {
		t.Errorf("MANIFEST_SCHEMA_VALID detail does not name %s: %s", codes.ManifestSchemaVersionUnsupported, c.Detail)
	}
}

func TestUnknownPredicateFailsPredicateVersionUnsupported(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "unknown-predicate")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The signature verifies but the strict parse rejects the v2 predicate type.
	assertPassed(t, report, codes.SignatureValid)
	assertFailed(t, report, codes.PredicateVersionUnsupported)
	// The payload cannot be trusted once the parse fails.
	if checkFor(t, report, codes.SubjectDigestMatch).Passed {
		t.Error("SUBJECT_DIGEST_MATCH passed after a parse failure; it must not be evaluated")
	}
}

func TestMissingAttestationFailsAndMarksRestNotEvaluated(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       nil,
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run must complete the report even with no attestation: %v", err)
	}
	assertFailed(t, report, codes.AttestationMissing)
	// Everything else is present but not evaluated: none may be passed.
	for _, c := range report.Checks {
		if c.Code == codes.AttestationMissing {
			continue
		}
		if c.Passed {
			t.Errorf("check %s passed with no attestation; everything but ATTESTATION_MISSING must be not evaluated", c.Code)
		}
	}
}

func TestMissingNPMProvenanceIsInformationalAndReportCompletes(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "valid")},
		NPMProvenance: nil,
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := assertFailed(t, report, codes.ProvenancePresent)
	if !c.Informational {
		t.Error("PROVENANCE_PRESENT must be informational")
	}
	// The failing class checks still pass, so the report as a whole succeeds.
	for _, code := range failingClassCodes {
		assertPassed(t, report, code)
	}
}

func TestNPMProvenancePresentPasses(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           npmRef(),
		Bundles:       [][]byte{loadBundle(t, "npm", "valid")},
		NPMProvenance: slsaProvenanceBundle(t),
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	c := checkFor(t, report, codes.ProvenancePresent)
	if !c.Passed {
		t.Errorf("PROVENANCE_PRESENT = failed, want passed with a real SLSA provenance bundle; detail: %s", c.Detail)
	}
	if !c.Informational {
		t.Error("PROVENANCE_PRESENT must be informational even when it passes")
	}
	// npm subject digest still matches, so the crypto checks pass end to end.
	assertPassed(t, report, codes.SubjectDigestMatch)
}

// TestCertExpiryNotConstructibleOffline records why there is no expired or
// revoked certificate row in this offline matrix. The Task 3.1 fixtures are key
// based bundles: they carry a bare public key and no Fulcio issued certificate,
// so there is no certificate validity window to move an injected Now past. A
// cert expiry row needs a keyless bundle and the Sigstore trust root, which are
// exercised live only in M6. This test asserts nothing on purpose; it is the
// documented placeholder for that future row.
func TestCertExpiryNotConstructibleOffline(t *testing.T) {
	t.Log("cert expiry is not constructible offline for key based bundles; the row lands live in M6")
}

func TestGoldenValidReport(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "valid")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshaling report: %v", err)
	}
	got = append(got, '\n')
	golden.Assert(t, got, filepath.Join("testdata", "golden", "report_valid.json"))
}

func TestRunIsDeterministic(t *testing.T) {
	in := verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "valid")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}
	first, err := verify.Run(in, compose.NewVerifier())
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	second, err := verify.Run(in, compose.NewVerifier())
	if err != nil {
		t.Fatalf("second Run: %v", err)
	}
	fb, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshaling first report: %v", err)
	}
	sb, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshaling second report: %v", err)
	}
	if string(fb) != string(sb) {
		t.Errorf("two Run calls produced different reports:\nfirst:  %s\nsecond: %s", fb, sb)
	}
}

// TestChecksAreSortedByCode asserts the report's checks are in Code order, the
// determinism guarantee the golden and every consumer relies on.
func TestChecksAreSortedByCode(t *testing.T) {
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{loadBundle(t, "skill", "valid")},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for i := 1; i < len(report.Checks); i++ {
		if report.Checks[i-1].Code > report.Checks[i].Code {
			t.Errorf("checks are not sorted by code: %s came before %s", report.Checks[i-1].Code, report.Checks[i].Code)
		}
	}
}

// TestCheckOutcomesSetOnlyInVerifyPackage enforces spec 3's rule that check
// outcomes are decided in exactly one place. No package other than
// pkg/core/verify may construct a CheckResult, so nothing downstream can mint a
// passing check by re-reading an envelope it trusts on its own authority. The
// guard is a source scan, the same lightweight technique the purity and clock
// guards use.
func TestCheckOutcomesSetOnlyInVerifyPackage(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(self), "..", "..", "..")
	verifyDir := filepath.Join(root, "pkg", "core", "verify")

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip the verify package itself, which legitimately builds checks.
			if path == verifyDir {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "verify.CheckResult{") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning source tree: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("CheckResult is constructed outside pkg/core/verify, which would let a check outcome be set elsewhere: %v", offenders)
	}
}
