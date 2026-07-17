package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// poisonRoundTripper fails the test on any HTTP request. verifyDeps installs it
// as the default Transport so a test that reaches the npm or MCP Registry
// network without deliberately injecting a fixture transport fails loudly at the
// request rather than possibly touching a real socket. It mirrors
// pkg/discover's own poisonTransport. A test that needs a real fixture
// transport overrides d.Transport, replacing this guard.
type poisonRoundTripper struct{ t *testing.T }

func (p poisonRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	p.t.Fatalf("poisonRoundTripper: unexpected request %s %s; inject a fixture transport for this test", req.Method, req.URL.String())
	return nil, fmt.Errorf("unreachable")
}

// verifyDeps builds a deps value with a real signature verifier and the fixed
// clock, writing to the supplied buffers. Transport defaults to a poison round
// tripper that fails the test on any request; Registry and ReadTarget default to
// nil. Tests that discover over the network override these.
func verifyDeps(t *testing.T, stdout, stderr *bytes.Buffer) *deps {
	t.Helper()
	return &deps{
		Signer:    fakeSigner{},
		NewTarget: failingTarget(t),
		Verifier:  compose.NewVerifier(),
		Transport: poisonRoundTripper{t: t},
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
//
// This golden embeds the winning bundle's DSSE envelope bytes, so it is coupled
// to the committed skill/valid.sigstore.json fixture: regenerating the signed
// fixtures (go run ./testdata/gen) reshuffles the randomized ECDSA signature and
// therefore the envelope this golden pins, so on any real fixture payload change
// this golden must be regenerated in the same commit with
// `go test -update ./cmd/smithmark`.
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

// TestVerifyMissingAttestationSummarySurfacesNote proves summary mode surfaces
// discovery notes on stderr: the same missing attestation case as
// TestVerifyMissingAttestationExitsOne, run in summary mode, carries the probed
// attestation tag note as a "note:" line on stderr while stdout stays the
// report. json mode surfaces nothing there (that path is pinned by the golden).
func TestVerifyMissingAttestationSummarySurfacesNote(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)
	d.Transport = npmMissingTransport(t)
	store := memory.New()
	d.ReadTarget = func(_ context.Context, _ string) (oras.ReadOnlyGraphTarget, error) { return store, nil }

	code := runMain(d, []string{
		"verify", verifyFixtureNPMName + "@" + verifyFixtureNPMVersion,
		"--attestation-base", verifyTestAttestBase,
		"--output", "summary",
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "note:") {
		t.Errorf("stderr carries no note line:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "no attestation tag") {
		t.Errorf("stderr does not carry the probed attestation tag note:\n%s", stderr.String())
	}
}

// TestVerifyInvalidOutputExitsThree proves an unrecognized --output value fails
// closed with exit 3 and the OUTPUT_FORMAT_INVALID code naming the valid values,
// rather than silently defaulting to the human summary.
func TestVerifyInvalidOutputExitsThree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := verifyDeps(t, &stdout, &stderr)

	code := runMain(d, []string{
		"verify", skillFixturePath,
		"--bundle", skillValidBundlePath,
		"--trust-root", trustRootPath,
		"--output", "yaml",
	})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.OutputFormatInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.OutputFormatInvalid)
	}
	if !strings.Contains(line.Detail, "summary") || !strings.Contains(line.Detail, "json") {
		t.Errorf("detail %q should name both valid values", line.Detail)
	}
}

// TestProductionReadTargetEmptyRepoFailsClosed proves the production ReadTarget
// factory fails closed with a coded DISCOVERY_FAILED when the resolved
// repository is empty, rather than handing remote.NewRepository an empty string
// and surfacing an uncoded INTERNAL_ERROR. The live per artifact scoping this
// stands in for is tracked in sns45/smithmark#4 and lands with M6; no memory
// store test can catch this because it exercises the production factory itself.
func TestProductionReadTargetEmptyRepoFailsClosed(t *testing.T) {
	_, err := productionDeps().ReadTarget(context.Background(), "")
	if err == nil {
		t.Fatal("ReadTarget returned no error for an empty repository")
	}
	var coded *codes.Error
	if !errors.As(err, &coded) || coded.Code != codes.DiscoveryFailed {
		t.Errorf("err = %v, want a %s coded error", err, codes.DiscoveryFailed)
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

// TestTruncateDetailRuneSafety proves truncateDetail counts runes, not bytes: a
// multi byte string truncated at the boundary stays valid UTF-8 and never splits
// a rune, matching the doc comment's "at most max runes" promise.
func TestTruncateDetailRuneSafety(t *testing.T) {
	// Ten 3 byte runes (30 bytes). Truncating to 8 runes must yield 5 runes plus
	// the "..." ellipsis, all valid UTF-8, never a byte split mid rune.
	s := strings.Repeat("あ", 10)
	got := truncateDetail(s, 8)
	if !utf8.ValidString(got) {
		t.Errorf("truncateDetail produced invalid UTF-8: %q", got)
	}
	if n := utf8.RuneCountInString(got); n > 8 {
		t.Errorf("truncateDetail returned %d runes, want at most 8", n)
	}
	if want := strings.Repeat("あ", 5) + "..."; got != want {
		t.Errorf("truncateDetail = %q, want %q", got, want)
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
