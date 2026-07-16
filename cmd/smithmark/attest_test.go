package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"oras.land/oras-go/v2"

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
	writeTestFile(t, dir, "fake-caller-1.0.0.tgz", "pretend npm tarball bytes")

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

// writeTestFile writes name under dir with content, failing the test on error.
func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
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
