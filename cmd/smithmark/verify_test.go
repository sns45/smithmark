package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/sns45/smithmark/internal/golden"
	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/verify"
)

// Fixture paths, relative to this package (cmd/smithmark). The signed bundles
// and the throwaway public key are the Task 3.1 committed fixtures; the npm
// packument is the Task 3.2 discovery fixture. Every test reads them and injects
// bytes or fixture transports, so no test touches a real socket.
const (
	skillValidBundlePath    = "../../testdata/signature/skill/valid.sigstore.json"
	skillTamperedBundlePath = "../../testdata/signature/skill/tampered.sigstore.json"
	skillMismatchBundlePath = "../../testdata/signature/skill/digest-mismatch.sigstore.json"
	trustRootPath           = "../../testdata/signature/test-signing-key-pub.pem"
	verifyPackumentPath     = "../../testdata/npm/packument.json"
	verifyFixtureNPMName    = "@modelcontextprotocol/server-filesystem"
	verifyFixtureNPMVersion = "2026.7.10"
	verifyTestAttestBase    = "registry.example.com/attest"
)

// verifyFixtureTransport is a canned http.RoundTripper serving responses keyed
// by "METHOD path", failing the test loudly on any request it was not told to
// expect. It is a deliberate twin of pkg/discover's discover_test
// fixtureTransport (resolve_test.go): that one lives in an external test package
// and cannot be imported here without a cycle, so the tiny round tripper is
// duplicated with this comment naming its twin.
type verifyFixtureTransport struct {
	t     *testing.T
	byKey map[string][]byte
	code  map[string]int
}

func newVerifyTransport(t *testing.T) *verifyFixtureTransport {
	t.Helper()
	return &verifyFixtureTransport{t: t, byKey: map[string][]byte{}, code: map[string]int{}}
}

func (f *verifyFixtureTransport) serve(method, path string, status int, body []byte) *verifyFixtureTransport {
	key := method + " " + path
	f.byKey[key] = body
	f.code[key] = status
	return f
}

func (f *verifyFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	status, ok := f.code[key]
	if !ok {
		f.t.Fatalf("verifyFixtureTransport: unexpected request %s %s; no real network is permitted in this test", req.Method, req.URL.String())
		return nil, fmt.Errorf("unreachable")
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Body:       io.NopCloser(bytes.NewReader(f.byKey[key])),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// npmMissingTransport serves the packument (so identity resolves) and a 404 for
// the npm attestations endpoint (so provenance is tolerated absent), the shape
// the missing attestation case needs.
func npmMissingTransport(t *testing.T) *verifyFixtureTransport {
	t.Helper()
	body, err := os.ReadFile(verifyPackumentPath)
	if err != nil {
		t.Fatalf("reading packument fixture: %v", err)
	}
	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/"+verifyFixtureNPMName, http.StatusOK, body)
	tr.serve(http.MethodGet, fmt.Sprintf("/-/npm/v1/attestations/%s@%s", verifyFixtureNPMName, verifyFixtureNPMVersion), http.StatusNotFound, nil)
	return tr
}

// verifyDeps builds a deps value with a real signature verifier and the fixed
// clock, writing to the supplied buffers. Discovery seams (Transport, Registry,
// ReadTarget) default to nil and are set by the tests that need them.
func verifyDeps(t *testing.T, stdout, stderr *bytes.Buffer) *deps {
	t.Helper()
	return &deps{
		Signer:    fakeSigner{},
		NewTarget: failingTarget(t),
		Verifier:  compose.NewVerifier(),
		Now:       func() time.Time { return fixedNow },
		Stdout:    stdout,
		Stderr:    stderr,
	}
}

// findCheck returns a pointer to the report check with the given code, failing
// the test when it is absent. It returns a pointer into the report's own slice
// rather than a copy so it never constructs a verify.CheckResult literal, which
// the spec 3 single authority guard (TestCheckOutcomesSetOnlyInVerifyPackage)
// forbids outside pkg/core/verify.
func findCheck(t *testing.T, report *verify.VerificationReport, code string) *verify.CheckResult {
	t.Helper()
	for i := range report.Checks {
		if report.Checks[i].Code == code {
			return &report.Checks[i]
		}
	}
	t.Fatalf("report carries no check %s", code)
	return nil
}

func decodeReport(t *testing.T, stdout []byte) *verify.VerificationReport {
	t.Helper()
	var report verify.VerificationReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		t.Fatalf("stdout is not a verification report: %v\n%s", err, stdout)
	}
	return &report
}

// TestVerifyValidSkillBundleGolden drives the whole verify pipeline over the
// committed valid skill fixture in --bundle mode: identity is resolved from the
// local skill directory, the bundle bytes come from the flag, the injected
// verifier checks the real signature, and the JSON report (evidence populated)
// is pinned as a golden. It exits 0 because every failing class check passes.
func TestVerifyValidSkillBundleGolden(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillValidBundlePath,
		"--trust-root", trustRootPath,
		"--output", "json",
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	golden.Assert(t, stdout.Bytes(), filepath.Join("testdata", "golden", "verify_valid_skill.json"))
}

// TestVerifyTamperedExitsOne proves a bundle whose signature does not verify
// exits 1 with SIGNATURE_VALID failed and no evidence block.
func TestVerifyTamperedExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillTamperedBundlePath,
		"--trust-root", trustRootPath,
		"--output", "json",
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	report := decodeReport(t, stdout.Bytes())
	if findCheck(t, report, codes.SignatureValid).Passed {
		t.Error("SIGNATURE_VALID passed for a tampered bundle")
	}
	// A json null round trips into a json.RawMessage as the literal bytes
	// "null", so the marker of an absent evidence block is that value, not a nil
	// slice.
	if s := strings.TrimSpace(string(report.Evidence)); s != "null" && s != "" {
		t.Errorf("evidence must be null when no candidate wins, got: %s", report.Evidence)
	}
}

// TestVerifyDigestMismatchExitsOne proves a validly signed bundle over the wrong
// subject exits 1 with SUBJECT_DIGEST_MATCH failed while the signature passes.
func TestVerifyDigestMismatchExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillMismatchBundlePath,
		"--trust-root", trustRootPath,
		"--output", "json",
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	report := decodeReport(t, stdout.Bytes())
	if !findCheck(t, report, codes.SignatureValid).Passed {
		t.Error("SIGNATURE_VALID should pass; the mismatch bundle is validly signed")
	}
	if findCheck(t, report, codes.SubjectDigestMatch).Passed {
		t.Error("SUBJECT_DIGEST_MATCH passed for a wrong subject bundle")
	}
}

// TestVerifyMissingAttestationExitsOne resolves an npm package whose attestation
// tag is absent from an empty memory store: discovery yields zero bundles, so
// verification fails ATTESTATION_MISSING and the command exits 1. No trust root
// is required because no bundle was discovered.
func TestVerifyMissingAttestationExitsOne(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	d.Transport = npmMissingTransport(t)
	store := memory.New()
	d.ReadTarget = func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) { return store, nil }

	code := runMain(d, []string{
		"verify", verifyFixtureNPMName + "@" + verifyFixtureNPMVersion,
		"--attestation-base", verifyTestAttestBase,
		"--output", "json",
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	report := decodeReport(t, stdout.Bytes())
	if findCheck(t, report, codes.AttestationMissing).Passed {
		t.Error("ATTESTATION_MISSING passed with an empty store; it must fail")
	}
}

// TestVerifyDiscoveryFailedExitsThree proves an operational discovery failure (a
// malformed attestation base whose path segment violates the OCI grammar) exits
// 3 with the single DISCOVERY_FAILED stderr line.
func TestVerifyDiscoveryFailedExitsThree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	d.Transport = npmMissingTransport(t)
	store := memory.New()
	d.ReadTarget = func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) { return store, nil }

	code := runMain(d, []string{
		"verify", verifyFixtureNPMName + "@" + verifyFixtureNPMVersion,
		"--attestation-base", verifyTestAttestBase + "/BadSegment",
		"--output", "json",
	})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	if line := decodeErrLine(t, stderr.Bytes()); line.Code != codes.DiscoveryFailed {
		t.Errorf("code = %q, want %q", line.Code, codes.DiscoveryFailed)
	}
}

// TestVerifyCertificateIdentityRejected proves keyless verification is accepted
// but fails closed in v0.1: setting --certificate-identity exits 3 with
// SIGNING_CONFIG_INVALID naming M6, never a silent ignore.
func TestVerifyCertificateIdentityRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--certificate-identity", "ci@example.com",
		"--bundle", skillValidBundlePath,
	})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.SigningConfigInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.SigningConfigInvalid)
	}
	if !strings.Contains(line.Detail, "M6") {
		t.Errorf("detail %q should name M6 as where keyless verification lands", line.Detail)
	}
}

// TestVerifyBundleWithoutTrustRootRejected proves a discovered bundle with no
// --trust-root fails closed with SIGNING_CONFIG_INVALID naming the flag, rather
// than silently skipping signature verification.
func TestVerifyBundleWithoutTrustRootRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillValidBundlePath,
	})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.SigningConfigInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.SigningConfigInvalid)
	}
	if !strings.Contains(line.Detail, "--trust-root") {
		t.Errorf("detail %q should name the --trust-root flag", line.Detail)
	}
}

// TestVerifyStrictZeroFindingsExitsZero pins the reserved exit 2 placeholder: in
// --strict mode a valid artifact with zero lint findings (findings land in M4)
// still exits 0, proving the strict gate keys off findings, not off passing.
func TestVerifyStrictZeroFindingsExitsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillValidBundlePath,
		"--trust-root", trustRootPath,
		"--strict",
		"--output", "json",
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
}

// TestVerifySummaryMode smoke tests the human summary surface: it prints one
// line per check carrying the check codes and ends with a verdict line. Asserted
// loosely (contains codes and verdict), not goldened.
func TestVerifySummaryMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillValidBundlePath,
		"--trust-root", trustRootPath,
		"--output", "summary",
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{codes.SignatureValid, codes.SubjectDigestMatch, "VERIFIED"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary output does not contain %q:\n%s", want, out)
		}
	}
}
