package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/sns45/smithmark/internal/golden"
	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// skillFixturePath points at the committed fixture skill, two directories up
// from this package, the same fixture pkg/discover walks.
const skillFixturePath = "../../testdata/skills/hello-skill"

// fixedNow is the injected clock every test uses, so a signed or printed
// statement's generatedAt is deterministic and the golden never drifts.
var fixedNow = time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

// fakeSBOM is an injectable SBOMGenerator: it returns a fixed result, or a
// fixed error, without ever shelling out to forgeseal. A test that must prove
// the SBOM step was skipped injects an err that would fail the test if
// Generate were ever called.
type fakeSBOM struct {
	result *compose.SBOMResult
	err    error
}

func (f fakeSBOM) Generate(_ context.Context, _ string) (*compose.SBOMResult, error) {
	return f.result, f.err
}

// goldenSBOMResult is a deterministic SBOM reference the golden dry run wires
// into the manifest's dependencies block. The digest and format are fixed so
// the golden statement is stable; the exact bytes are irrelevant to a dry run,
// which never publishes the BOM itself.
func goldenSBOMResult() *compose.SBOMResult {
	return &compose.SBOMResult{
		Ref: &manifest.SBOMRef{
			SBOMDigest: manifest.DigestSet{"sha256": strings.Repeat("ab", 32)},
			SBOMFormat: "application/vnd.cyclonedx+json;version=1.6",
		},
		BOM: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`),
	}
}

// fakeSigner builds a DSSE style bundle by hand, no sigstore-go and no crypto,
// so the CLI's sign, output, and push paths run on every platform. It mirrors
// the contract fake in pkg/compose: the statement becomes the base64 payload
// under the in-toto payloadType.
type fakeSigner struct{}

func (fakeSigner) SignStatement(_ context.Context, statement []byte, _ compose.SignOptions) (*compose.SignedBundle, error) {
	env := map[string]any{
		"payloadType": compose.DSSEPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"sig": base64.StdEncoding.EncodeToString([]byte("fake-signature"))}},
	}
	raw, err := json.Marshal(map[string]any{"dsseEnvelope": env})
	if err != nil {
		return nil, err
	}
	return &compose.SignedBundle{Bundle: raw, MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"}, nil
}

// capturingSigner records the SignOptions the CLI hands it and returns a fake
// bundle, so a test can assert the keyless wiring built the right SignOptions
// without any real crypto or network.
type capturingSigner struct{ opts *compose.SignOptions }

func (c capturingSigner) SignStatement(_ context.Context, statement []byte, opts compose.SignOptions) (*compose.SignedBundle, error) {
	*c.opts = opts
	env := map[string]any{
		"payloadType": compose.DSSEPayloadType,
		"payload":     base64.StdEncoding.EncodeToString(statement),
		"signatures":  []map[string]string{{"sig": base64.StdEncoding.EncodeToString([]byte("fake-signature"))}},
	}
	raw, err := json.Marshal(map[string]any{"dsseEnvelope": env})
	if err != nil {
		return nil, err
	}
	return &compose.SignedBundle{Bundle: raw, MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"}, nil
}

// TestAttestKeyAndKeylessMutuallyExclusive proves --key and --keyless cannot be
// combined: the request fails closed with SIGNING_CONFIG_INVALID before any
// pipeline work, never silently preferring one mode.
func TestAttestKeyAndKeylessMutuallyExclusive(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--key", "k.pem", "--keyless", skillFixturePath})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.SigningConfigInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.SigningConfigInvalid)
	}
	if !strings.Contains(line.Detail, "mutually exclusive") {
		t.Errorf("detail %q should name the two modes as mutually exclusive", line.Detail)
	}
}

// TestAttestKeylessWithoutOIDCContextFailsClosed proves --keyless outside a
// permitted GitHub Actions OIDC job fails closed with SIGNING_CONFIG_INVALID
// naming the missing OIDC request env vars, never falling back to an interactive
// flow CI cannot drive.
func TestAttestKeylessWithoutOIDCContextFailsClosed(t *testing.T) {
	// Ensure the ambient OIDC env is absent for this test regardless of the host.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--keyless", "--skip-sbom", skillFixturePath})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.SigningConfigInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.SigningConfigInvalid)
	}
	if !strings.Contains(line.Detail, "ACTIONS_ID_TOKEN_REQUEST_URL") {
		t.Errorf("detail %q should name the missing GitHub Actions OIDC context", line.Detail)
	}
}

// TestAttestKeylessBuildsSignOptions proves the keyless wiring obtains the
// ambient GitHub Actions OIDC token and builds a complete keyless SignOptions:
// the Fulcio and Rekor endpoints, the GitHub OIDC issuer, and the fetched
// identity token. A fixture transport serves the OIDC token endpoint, so no real
// network is touched, and a capturing signer records the SignOptions the CLI
// built rather than performing any real keyless signing.
func TestAttestKeylessBuildsSignOptions(t *testing.T) {
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/oidc")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "request-token")

	tr := newVerifyTransport(t)
	tr.serve(http.MethodGet, "/oidc", http.StatusOK, []byte(`{"value":"minted-identity-token"}`))

	var stdout, stderr bytes.Buffer
	var captured compose.SignOptions
	store := memory.New()
	d := &deps{
		SBOM:      fakeSBOM{result: goldenSBOMResult()},
		Signer:    capturingSigner{opts: &captured},
		NewTarget: func(_ context.Context, _ string) (oras.Target, error) { return store, nil },
		Transport: tr,
		Now:       func() time.Time { return fixedNow },
		Stdout:    &stdout,
		Stderr:    &stderr,
	}

	code := runMain(d, []string{
		"attest", "--keyless", "--skip-sbom",
		"--attestation-base", "registry.example.com/attest",
		skillFixturePath,
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	if captured.KeyPath != "" {
		t.Errorf("keyless SignOptions carried a KeyPath %q, want empty", captured.KeyPath)
	}
	if captured.IdentityToken != "minted-identity-token" {
		t.Errorf("IdentityToken = %q, want the fetched token", captured.IdentityToken)
	}
	if captured.OIDCIssuerURL != githubOIDCIssuer {
		t.Errorf("OIDCIssuerURL = %q, want %q", captured.OIDCIssuerURL, githubOIDCIssuer)
	}
	if captured.FulcioURL != defaultFulcioURL || captured.RekorURL != defaultRekorURL {
		t.Errorf("Fulcio/Rekor = %q/%q, want the public good defaults %q/%q",
			captured.FulcioURL, captured.RekorURL, defaultFulcioURL, defaultRekorURL)
	}
}

// failingTarget is a NewTarget factory that fails the test if called, for the
// dry-run and error path cases that must never reach publishing.
func failingTarget(t *testing.T) func(context.Context, string) (oras.Target, error) {
	t.Helper()
	return func(_ context.Context, repo string) (oras.Target, error) {
		t.Fatalf("NewTarget must not be called (repo %q)", repo)
		return nil, nil
	}
}

// newDeps builds a deps value with fakes for every collaborator and the fixed
// clock, writing to the supplied buffers.
func newDeps(t *testing.T, stdout, stderr *bytes.Buffer, sbom fakeSBOM) *deps {
	t.Helper()
	return &deps{
		SBOM:      sbom,
		Signer:    fakeSigner{},
		NewTarget: failingTarget(t),
		Now:       func() time.Time { return fixedNow },
		Stdout:    stdout,
		Stderr:    stderr,
	}
}

// decodeErrLine parses the single machine readable JSON line the failure
// contract writes to stderr, failing the test unless stderr is exactly one
// such line (decision D4).
func decodeErrLine(t *testing.T, stderr []byte) errLine {
	t.Helper()
	trimmed := bytes.TrimRight(stderr, "\n")
	if bytes.Contains(trimmed, []byte("\n")) {
		t.Fatalf("stderr must be exactly one line, got:\n%s", stderr)
	}
	var line errLine
	if err := json.Unmarshal(trimmed, &line); err != nil {
		t.Fatalf("stderr is not a JSON error line: %q (%v)", stderr, err)
	}
	return line
}

// TestAttestDryRunGolden pins the canonical statement a dry run of the fixture
// skill produces. The SBOM is a fixed fake, so the dependencies block is
// stable; the clock is injected; nothing is signed or pushed.
func TestAttestDryRunGolden(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	if code := runMain(d, []string{"attest", "--dry-run", skillFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	golden.Assert(t, stdout.Bytes(), filepath.Join("testdata", "attest_dryrun_hello_skill.golden.json"))
}

// TestAttestOutputWritesSBOMSidecar proves that in --output mode attest writes
// the raw SBOM as an <output>.sbom.json sidecar and points the signed
// statement's dependencies locator at that filename, whereas the push path
// leaves the locator empty.
func TestAttestOutputWritesSBOMSidecar(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.json")
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	if code := runMain(d, []string{"attest", "--key", "unused-by-fake-signer.pem", "--output", out, skillFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}

	// Both files exist: the signed bundle and its SBOM sidecar.
	bundleBytes, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading bundle: %v", err)
	}
	sbomBytes, err := os.ReadFile(out + ".sbom.json")
	if err != nil {
		t.Fatalf("reading SBOM sidecar: %v", err)
	}
	if !bytes.Equal(sbomBytes, goldenSBOMResult().BOM) {
		t.Errorf("sidecar bytes = %q, want the raw BOM %q", sbomBytes, goldenSBOMResult().BOM)
	}

	// The statement inside the signed bundle carries the sidecar filename as
	// its dependencies locator.
	stmt := statementFromFakeBundle(t, bundleBytes)
	if stmt.Predicate.Dependencies == nil {
		t.Fatal("dependencies block missing from the signed statement")
	}
	if got, want := stmt.Predicate.Dependencies.Locator, "bundle.json.sbom.json"; got != want {
		t.Errorf("locator = %q, want %q", got, want)
	}
}

// statementFromFakeBundle extracts the in-toto statement out of a bundle
// produced by fakeSigner: the DSSE payload is base64 of the canonical
// statement bytes.
func statementFromFakeBundle(t *testing.T, bundleBytes []byte) *manifest.Statement {
	t.Helper()
	var outer struct {
		DSSEEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleBytes, &outer); err != nil {
		t.Fatalf("bundle is not JSON: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(outer.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("payload not base64: %v", err)
	}
	stmt, err := manifest.ParseStatement(payload)
	if err != nil {
		t.Fatalf("ParseStatement on bundle payload: %v", err)
	}
	return stmt
}

// TestAttestDryRunOutputWritesNothing proves a dry run never touches disk even
// when --output is also passed: no sidecar (and no bundle) is written.
func TestAttestDryRunOutputWritesNothing(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "bundle.json")
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	if code := runMain(d, []string{"attest", "--dry-run", "--output", out, skillFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	for _, p := range []string{out, out + ".sbom.json"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("dry run wrote %s (stat err = %v); it must leave no files on disk", p, err)
		}
	}
}

// TestAttestDryRunIdempotent proves the dry run is deterministic: two runs
// with identical deps produce byte identical stdout, the property the golden
// snapshot rests on.
func TestAttestDryRunIdempotent(t *testing.T) {
	run := func() []byte {
		var stdout, stderr bytes.Buffer
		d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})
		if code := runMain(d, []string{"attest", "--dry-run", skillFixturePath}); code != 0 {
			t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
		}
		return append([]byte(nil), stdout.Bytes()...)
	}
	first, second := run(), run()
	if !bytes.Equal(first, second) {
		t.Errorf("dry run is not byte identical across two runs\n first: %s\nsecond: %s", first, second)
	}
}

// TestAttestPushTerminus exercises the publish terminus with no --dry-run and
// no --output: a memory store injected through NewTarget receives the signed
// bundle, and the deterministic attestation tag resolves in that store
// afterward.
func TestAttestPushTerminus(t *testing.T) {
	// The hello-skill fixture's pinned bundle digest, guarded by the walker's
	// own golden test; the push tag is derived from it.
	const bundleHex = "a4bdaaa7fd43eeca9269a369f0be3c87a9dedc8e052872064ad19ed26e27edda"
	store := memory.New()
	var stdout, stderr bytes.Buffer
	d := &deps{
		SBOM:      fakeSBOM{result: goldenSBOMResult()},
		Signer:    fakeSigner{},
		NewTarget: func(_ context.Context, _ string) (oras.Target, error) { return store, nil },
		Now:       func() time.Time { return fixedNow },
		Stdout:    &stdout,
		Stderr:    &stderr,
	}

	code := runMain(d, []string{"attest", "--key", "unused-by-fake-signer.pem", "--attestation-base", "registry.example.com/attest", skillFixturePath})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}

	ref := manifest.ArtifactRef{
		Kind:   manifest.KindSkill,
		Name:   "hello-skill",
		Source: manifest.SourceLocal,
		Digest: manifest.DigestSet{"smithmark-bundle-v1": bundleHex},
	}
	_, tag, err := discover.AttestationRef("registry.example.com/attest", ref)
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	if _, err := store.Resolve(context.Background(), tag); err != nil {
		t.Errorf("pushed tag %q does not resolve in the store: %v", tag, err)
	}
}

// TestAttestSkipSBOMNoDependencies proves --skip-sbom omits the dependencies
// block entirely and never calls the SBOM generator: the injected fake would
// error if it ran.
func TestAttestSkipSBOMNoDependencies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{err: errors.New("SBOM must not run under --skip-sbom")})

	if code := runMain(d, []string{"attest", "--dry-run", "--skip-sbom", skillFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	stmt, err := manifest.ParseStatement(stdout.Bytes())
	if err != nil {
		t.Fatalf("ParseStatement on dry run output: %v", err)
	}
	if stmt.Predicate.Dependencies != nil {
		t.Errorf("dependencies present under --skip-sbom: %+v", stmt.Predicate.Dependencies)
	}
}

// TestAttestMissingForgeseal proves the exit code contract end to end: an SBOM
// generator returning SBOM_FORGESEAL_MISSING makes the command exit 3 and
// write exactly that code on the single stderr JSON line.
func TestAttestMissingForgeseal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{err: codes.E(codes.SBOMForgesealMissing, "forgeseal not found on PATH")})

	code := runMain(d, []string{"attest", skillFixturePath})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.SBOMForgesealMissing {
		t.Errorf("code = %q, want %q", line.Code, codes.SBOMForgesealMissing)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout must be empty on failure, got: %s", stdout.String())
	}
}

// TestAttestUncodedErrorMapsToInternal proves an error that carries no registry
// code is surfaced under INTERNAL_ERROR rather than an empty code: a plain
// SBOM error stands in for any uncoded failure reaching the boundary.
func TestAttestUncodedErrorMapsToInternal(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{err: errors.New("some uncoded failure")})

	if code := runMain(d, []string{"attest", skillFixturePath}); code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	if line := decodeErrLine(t, stderr.Bytes()); line.Code != codes.InternalError {
		t.Errorf("code = %q, want %q", line.Code, codes.InternalError)
	}
}

// TestAttestMCPDryRun exercises the mcp-server branch without exec or network:
// the tool listing comes from --tools-from and the subject tarball is
// autodetected as the sole *.tgz in the artifact root. It asserts the subject
// is the npm purl with a sha512 digest and that resources and prompts are
// present but empty.
func TestAttestMCPDryRun(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, `kind: mcp-server
name: fake-caller
version: 1.0.0
source: npm
mcp:
  transports: [stdio]
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`)
	writeTestFile(t, dir, "tools.json", `{"tools":[{"name":"place_call","description":"place a call","inputSchema":{"type":"object","properties":{"to":{"type":"string"}}}}]}`)
	writeNPMTarball(t, dir, "fake-caller-1.0.0.tgz", "fake-caller", "1.0.0")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	stmt, err := manifest.ParseStatement(stdout.Bytes())
	if err != nil {
		t.Fatalf("ParseStatement: %v", err)
	}
	if got, want := stmt.Subject[0].Name, "pkg:npm/fake-caller@1.0.0"; got != want {
		t.Errorf("subject name = %q, want %q", got, want)
	}
	if _, ok := stmt.Subject[0].Digest["sha512"]; !ok {
		t.Errorf("subject digest missing sha512: %+v", stmt.Subject[0].Digest)
	}
	mcp := stmt.Predicate.MCP
	if mcp == nil {
		t.Fatal("predicate mcp surface is nil")
	}
	if len(mcp.Tools) != 1 || mcp.Tools[0].Name != "place_call" {
		t.Errorf("tools = %+v, want one place_call tool", mcp.Tools)
	}
	if mcp.Resources == nil || len(mcp.Resources) != 0 || mcp.Prompts == nil || len(mcp.Prompts) != 0 {
		t.Errorf("resources/prompts must be empty non nil, got resources=%v prompts=%v", mcp.Resources, mcp.Prompts)
	}
}

// TestAttestMCPSubjectUnresolved proves the ambiguous subject case: with no
// --tarball and two candidate tarballs in the root, attest fails closed with
// ATTEST_SUBJECT_UNRESOLVED rather than guessing.
func TestAttestMCPSubjectUnresolved(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, `kind: mcp-server
name: fake-caller
version: 1.0.0
source: npm
mcp:
  transports: [stdio]
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`)
	writeTestFile(t, dir, "tools.json", `{"tools":[]}`)
	writeTestFile(t, dir, "one-1.0.0.tgz", "a")
	writeTestFile(t, dir, "two-1.0.0.tgz", "b")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	if line := decodeErrLine(t, stderr.Bytes()); line.Code != codes.AttestSubjectUnresolved {
		t.Errorf("code = %q, want %q", line.Code, codes.AttestSubjectUnresolved)
	}
}

// mcpDeclFixture is the minimal fake-caller mcp-server declaration the tarball
// identity cases reuse, matching name fake-caller and version 1.0.0.
const mcpDeclFixture = `kind: mcp-server
name: fake-caller
version: 1.0.0
source: npm
mcp:
  transports: [stdio]
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`

// TestAttestMCPTarballIdentityMismatch proves the tarball's own package.json
// identity is cross checked against the declaration: a tarball naming a
// different package fails closed with STATEMENT_SUBJECT_MISMATCH rather than
// attesting the declaration over the wrong subject.
func TestAttestMCPTarballIdentityMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, mcpDeclFixture)
	writeTestFile(t, dir, "tools.json", `{"tools":[]}`)
	writeNPMTarball(t, dir, "fake-caller-1.0.0.tgz", "some-other-package", "1.0.0")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.StatementSubjectMismatch {
		t.Errorf("code = %q, want %q", line.Code, codes.StatementSubjectMismatch)
	}
	for _, want := range []string{"some-other-package", "fake-caller"} {
		if !strings.Contains(line.Detail, want) {
			t.Errorf("detail %q must name both sides of the mismatch (%s)", line.Detail, want)
		}
	}
}

// TestAttestMCPTarballMissingPackageJSON proves a tarball with no readable
// package/package.json is treated as not an npm package tarball at all and
// fails closed with ATTEST_SUBJECT_UNRESOLVED.
func TestAttestMCPTarballMissingPackageJSON(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, mcpDeclFixture)
	writeTestFile(t, dir, "tools.json", `{"tools":[]}`)

	// A valid gzip tar that carries a file other than package/package.json.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := "not a package manifest"
	if err := tw.WriteHeader(&tar.Header{Name: "package/README.md", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fake-caller-1.0.0.tgz"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	if line := decodeErrLine(t, stderr.Bytes()); line.Code != codes.AttestSubjectUnresolved {
		t.Errorf("code = %q, want %q", line.Code, codes.AttestSubjectUnresolved)
	}
}

// fakemcpDeclWithCommand is a fake-mcp declaration that carries BOTH a launch
// command (the committed fakemcp fixture, reached by a path relative to this
// package's working directory) and is used alongside --tools-from, so attest
// cross checks the static listing against the live server (U2 addendum). The
// name and version match the tarball the agreeing case digests.
const fakemcpDeclWithCommand = `kind: mcp-server
name: fakemcp
version: 0.1.0
source: npm
mcp:
  transports: [stdio]
  command: [go, run, ../../testdata/fakemcp]
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`

// agreeingToolsFile matches the fakemcp fixture's two tools and their exact
// input schemas, so a live extraction and this file digest identically (U2).
const agreeingToolsFile = `{
  "tools": [
    {"name": "hello_world", "description": "Say hello to someone by name.", "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"loud":{"type":"boolean"}},"required":["name"]}},
    {"name": "add_numbers", "description": "Add two numbers together.", "inputSchema": {"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}}
  ]
}`

// TestAttestToolListingMismatch proves the U2 addendum: with both --tools-from
// and a declared command, a static listing that disagrees with the live server
// fails closed with TOOL_LISTING_MISMATCH rather than signing the mismatch. The
// live fakemcp fixture lists hello_world and add_numbers; the file below names a
// different tool, so extraction and the file disagree.
func TestAttestToolListingMismatch(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, fakemcpDeclWithCommand)
	writeTestFile(t, dir, "tools.json", `{"tools":[{"name":"totally_different_tool","inputSchema":{"type":"object"}}]}`)

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.ToolListingMismatch {
		t.Errorf("code = %q, want %q", line.Code, codes.ToolListingMismatch)
	}
	if !strings.Contains(line.Detail, "totally_different_tool") {
		t.Errorf("detail %q should name the disagreeing tool", line.Detail)
	}
}

// TestAttestToolListingAgrees proves the happy path of the same cross check:
// when --tools-from matches the live server exactly, attest proceeds and signs
// (here a dry run), so the cross check adds a guard without blocking an honest
// maker.
func TestAttestToolListingAgrees(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, fakemcpDeclWithCommand)
	writeTestFile(t, dir, "tools.json", agreeingToolsFile)
	writeNPMTarball(t, dir, "fakemcp-0.1.0.tgz", "fakemcp", "0.1.0")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	stmt, err := manifest.ParseStatement(stdout.Bytes())
	if err != nil {
		t.Fatalf("ParseStatement: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range stmt.Predicate.MCP.Tools {
		names[tool.Name] = true
	}
	if !names["hello_world"] || !names["add_numbers"] {
		t.Errorf("signed tools = %+v, want hello_world and add_numbers", stmt.Predicate.MCP.Tools)
	}
}

// writeTestFile writes name under dir with content, failing the test on error.
func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeNPMTarball writes a minimal valid gzipped tar under dir, shaped like an
// npm pack output: a single package/package.json entry carrying the given name
// and version. This is exactly what the attest mcp path digests and cross
// checks the declaration against.
func writeNPMTarball(t *testing.T, dir, filename, pkgName, pkgVersion string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := fmt.Sprintf(`{"name":%q,"version":%q,"description":"fixture"}`, pkgName, pkgVersion)
	if err := tw.WriteHeader(&tar.Header{
		Name: "package/package.json",
		Mode: 0o644,
		Size: int64(len(body)),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// duplicateToolsFile is agreeingToolsFile with hello_world listed a second
// time: its two distinct tools match the live fakemcp server exactly, yet the
// repeated name makes it a malformed listing. Before the M4 fix the duplicate
// collapsed (last wins) and attest signed the listing; after it, the duplicate
// is itself a TOOL_LISTING_MISMATCH.
const duplicateToolsFile = `{
  "tools": [
    {"name": "hello_world", "description": "Say hello to someone by name.", "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"loud":{"type":"boolean"}},"required":["name"]}},
    {"name": "add_numbers", "description": "Add two numbers together.", "inputSchema": {"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}},
    {"name": "hello_world", "description": "Say hello to someone by name.", "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"loud":{"type":"boolean"}},"required":["name"]}}
  ]
}`

// TestToolListingDisagreementDuplicateFailsClosed proves the M4 fix directly on
// the comparison: a duplicate tool name on EITHER side is itself a disagreement
// naming the duplicate, rather than collapsing last wins. A well formed MCP
// tools list has unique names, so a duplicate is a disagreement worth failing
// on, not a detail to paper over.
func TestToolListingDisagreementDuplicateFailsClosed(t *testing.T) {
	sha := manifest.DigestSet{"sha256": "1111111111111111111111111111111111111111111111111111111111111111"}
	unique := []manifest.ToolDecl{{Name: "dup", InputSchemaDigest: sha}}
	duplicated := []manifest.ToolDecl{
		{Name: "dup", InputSchemaDigest: sha},
		{Name: "dup", InputSchemaDigest: sha},
	}

	if got := toolListingDisagreement(duplicated, unique); got == "" || !strings.Contains(got, "dup") {
		t.Errorf("duplicate on the --tools-from side must disagree naming the tool; got %q", got)
	}
	if got := toolListingDisagreement(unique, duplicated); got == "" || !strings.Contains(got, "dup") {
		t.Errorf("duplicate on the live side must disagree naming the tool; got %q", got)
	}
}

// TestAttestToolListingDuplicateFailsClosed proves the same fix end to end: a
// --tools-from file whose two distinct tools match the live server exactly, but
// which repeats one name, is refused with TOOL_LISTING_MISMATCH naming the
// duplicate rather than signed. Before M4 the duplicate collapsed and attest
// signed the listing.
func TestAttestToolListingDuplicateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, fakemcpDeclWithCommand)
	writeTestFile(t, dir, "tools.json", duplicateToolsFile)
	writeNPMTarball(t, dir, "fakemcp-0.1.0.tgz", "fakemcp", "0.1.0")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{result: goldenSBOMResult()})

	code := runMain(d, []string{"attest", "--dry-run", "--tools-from", filepath.Join(dir, "tools.json"), dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	if line.Code != codes.ToolListingMismatch {
		t.Errorf("code = %q, want %q", line.Code, codes.ToolListingMismatch)
	}
	if !strings.Contains(line.Detail, "hello_world") {
		t.Errorf("detail %q should name the duplicated tool", line.Detail)
	}
}

// TestToolListingDisagreementBranches is a pure unit table over
// toolListingDisagreement, exercising the live extra tool branch and the schema
// digest disagreement branch (M13) directly, with no fakemcp exec: the digest
// branch is the U2 cross check's core value, so it is worth pinning on its own.
// Identical listings in different orders agree, proving the comparison is order
// independent.
func TestToolListingDisagreementBranches(t *testing.T) {
	digX := manifest.DigestSet{"sha256": strings.Repeat("a", 64)}
	digY := manifest.DigestSet{"sha256": strings.Repeat("b", 64)}
	toolA := manifest.ToolDecl{Name: "alpha", InputSchemaDigest: digX}
	toolB := manifest.ToolDecl{Name: "bravo", InputSchemaDigest: digX}

	cases := []struct {
		name      string
		file      []manifest.ToolDecl
		live      []manifest.ToolDecl
		wantEmpty bool
		wantSub   string
	}{
		{
			name:    "live lists an extra tool",
			file:    []manifest.ToolDecl{toolA},
			live:    []manifest.ToolDecl{toolA, toolB},
			wantSub: "bravo",
		},
		{
			name:    "file declares an extra tool",
			file:    []manifest.ToolDecl{toolA, toolB},
			live:    []manifest.ToolDecl{toolA},
			wantSub: "bravo",
		},
		{
			name:    "schema digest disagrees for a shared name",
			file:    []manifest.ToolDecl{toolA},
			live:    []manifest.ToolDecl{{Name: "alpha", InputSchemaDigest: digY}},
			wantSub: "input schema digest",
		},
		{
			name:      "identical listings agree regardless of order",
			file:      []manifest.ToolDecl{toolA, toolB},
			live:      []manifest.ToolDecl{toolB, toolA},
			wantEmpty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := toolListingDisagreement(tc.file, tc.live)
			if tc.wantEmpty {
				if got != "" {
					t.Errorf("want agreement, got disagreement %q", got)
				}
				return
			}
			if got == "" || !strings.Contains(got, tc.wantSub) {
				t.Errorf("disagreement = %q, want one containing %q", got, tc.wantSub)
			}
		})
	}
}

// TestManifestInitRoundTrip writes a full mcp-server declaration through init
// and reads it back with LoadDeclared, asserting the round tripped manifest
// carries exactly what the flags described.
func TestManifestInitRoundTrip(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, declFileName)
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	code := runMain(d, []string{
		"manifest", "init",
		"--kind", "mcp-server",
		"--name", "fake-caller",
		"--version", "1.0.0",
		"--source", "npm",
		"--transport", "stdio",
		"--egress", "api.example.com:443",
		"--fs", "${home}/.fake-caller/**:readwrite",
		"--exec", "ffmpeg",
		"--env", "API_TOKEN",
		"--secret", "api-key:example",
		"--out", out,
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}

	decl, err := discover.LoadDeclared(out)
	if err != nil {
		t.Fatalf("LoadDeclared on init output: %v", err)
	}
	m := decl.Manifest
	wantArtifact := manifest.PredicateArtifact{
		Kind:    manifest.KindMCPServer,
		Name:    "fake-caller",
		Version: "1.0.0",
		Source:  manifest.SourceNPM,
	}
	if m.Artifact != wantArtifact {
		t.Errorf("artifact = %+v, want %+v", m.Artifact, wantArtifact)
	}
	if m.MCP == nil || !reflect.DeepEqual(m.MCP.Transports, []string{"stdio"}) {
		t.Errorf("transports = %+v, want [stdio]", m.MCP)
	}
	wantCaps := manifest.CapabilitySet{
		NetworkEgress: []manifest.EgressRule{{Host: "api.example.com", Ports: []int{443}}},
		Filesystem:    []manifest.FSRule{{Path: "${home}/.fake-caller/**", Access: "readwrite"}},
		Exec:          []manifest.ExecRule{{Binary: "ffmpeg"}},
		Env:           []string{"API_TOKEN"},
		Secrets:       []string{"api-key:example"},
	}
	if !reflect.DeepEqual(m.Capabilities, wantCaps) {
		t.Errorf("capabilities = %+v, want %+v", m.Capabilities, wantCaps)
	}
}

// TestManifestInitSkillRoundTrip pins that a skill declaration with no version
// and an empty capability surface round trips: the empty capability lists must
// survive as non nil so LoadDeclared accepts them.
func TestManifestInitSkillRoundTrip(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, declFileName)
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	code := runMain(d, []string{
		"manifest", "init",
		"--kind", "skill",
		"--name", "hello-skill",
		"--source", "local",
		"--invokes-tool", "some-server:some_tool",
		"--out", out,
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	decl, err := discover.LoadDeclared(out)
	if err != nil {
		t.Fatalf("LoadDeclared on init output: %v", err)
	}
	m := decl.Manifest
	if m.Artifact.Kind != manifest.KindSkill || m.Artifact.Version != "" {
		t.Errorf("artifact = %+v, want skill with no version", m.Artifact)
	}
	if m.Skill == nil || !reflect.DeepEqual(m.Skill.InvokesTools, []string{"some-server:some_tool"}) {
		t.Errorf("invokesTools = %+v, want [some-server:some_tool]", m.Skill)
	}
}

// TestManifestInitMissingFlags proves every missing required flag is reported
// at once, not one at a time.
func TestManifestInitMissingFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"manifest", "init", "--kind", "mcp-server"}); code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	for _, flag := range []string{"--name", "--source", "--version"} {
		if !strings.Contains(line.Detail, flag) {
			t.Errorf("missing flags detail %q does not mention %s", line.Detail, flag)
		}
	}
}

// TestManifestInitRefusesOverwrite proves init will not clobber an existing
// file without --force, and does overwrite with it.
func TestManifestInitRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, declFileName)
	if err := os.WriteFile(out, []byte("existing content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"manifest", "init", "--kind", "skill", "--name", "x", "--source", "local", "--out", out}

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})
	if code := runMain(d, base); code != 3 {
		t.Fatalf("exit = %d, want 3 when refusing overwrite; stderr: %s", code, stderr.String())
	}
	if data, _ := os.ReadFile(out); string(data) != "existing content\n" {
		t.Errorf("file was overwritten without --force: %q", data)
	}

	stdout.Reset()
	stderr.Reset()
	if code := runMain(d, append(base, "--force")); code != 0 {
		t.Fatalf("exit = %d, want 0 with --force; stderr: %s", code, stderr.String())
	}
	if _, err := discover.LoadDeclared(out); err != nil {
		t.Errorf("forced init did not write a loadable declaration: %v", err)
	}
}

// TestAttestAggregatesValidationIssues proves that when the completed
// manifest trips more than one Validate issue, the error detail lists every
// issue as code at path joined by semicolons, while the error code is the
// first issue's code under Validate's stable sort. The declaration below loads
// cleanly (the loader does not grammar check capability values) but fails
// Validate on both a malformed egress host and a malformed env name.
func TestAttestAggregatesValidationIssues(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, declFileName, `kind: skill
name: hello
source: local
skill:
  invokesTools: []
capabilities:
  networkEgress:
    - host: BAD
  filesystem: []
  exec: []
  env:
    - lower
  secrets: []
`)
	writeTestFile(t, dir, "SKILL.md", "---\nname: hello\n---\nbody\n")

	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{err: errors.New("SBOM must not run under --skip-sbom")})

	code := runMain(d, []string{"attest", "--dry-run", "--skip-sbom", dir})
	if code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	line := decodeErrLine(t, stderr.Bytes())
	// EGRESS_HOST_INVALID sorts before ENV_NAME_INVALID, so it is the code.
	if line.Code != codes.EgressHostInvalid {
		t.Errorf("code = %q, want %q (first issue under the stable sort)", line.Code, codes.EgressHostInvalid)
	}
	for _, want := range []string{codes.EgressHostInvalid, codes.EnvNameInvalid} {
		if !strings.Contains(line.Detail, want) {
			t.Errorf("detail %q does not list %s; every issue must be aggregated", line.Detail, want)
		}
	}
}

// TestParseEgress pins the host[:port] split, including the IPv6 cases the
// naive last colon split gets wrong: a bare IPv6 literal has many colons and
// must be preserved whole, while a bracketed literal carries its port after
// the closing bracket.
func TestParseEgress(t *testing.T) {
	cases := []struct {
		in        string
		wantHost  string
		wantPorts []int
	}{
		{"example.com:443", "example.com", []int{443}},
		{"example.com", "example.com", nil},
		{"::1", "::1", nil},
		{"fe80::1", "fe80::1", nil},
		{"[::1]:443", "::1", []int{443}},
		{"[fe80::1]", "fe80::1", nil},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			host, ports := parseEgress(tc.in)
			if host != tc.wantHost {
				t.Errorf("host = %q, want %q", host, tc.wantHost)
			}
			if !reflect.DeepEqual(ports, tc.wantPorts) {
				t.Errorf("ports = %v, want %v", ports, tc.wantPorts)
			}
		})
	}
}

// TestVersionCommand proves the version subcommand prints the version var and
// exits 0.
func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})
	if code := runMain(d, []string{"version"}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != version {
		t.Errorf("version output = %q, want %q", got, version)
	}
}
