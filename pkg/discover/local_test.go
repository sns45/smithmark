package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// fixturePath points at the committed repo root fixture: a realistic
// declaration for the fake-caller MCP server.
const fixturePath = "../../testdata/declared/smithmark.yaml"

// validMCPDecl is a minimal valid mcp-server declaration used as the base
// document for the mutation tables below.
const validMCPDecl = `kind: mcp-server
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

// validSkillDecl is a minimal valid skill declaration: no version (optional
// for skills per U4) and an empty invokesTools list, which is allowed.
const validSkillDecl = `kind: skill
name: hello-skill
source: local
skill:
  invokesTools: []
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`

// writeDecl writes doc to a temp file and returns its path, for tests that
// need a declaration other than the committed fixture.
func writeDecl(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "smithmark.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// without removes one exact line from doc, failing the test if the line is
// not present, so a fixture edit cannot silently defuse a mutation case.
func without(t *testing.T, doc, line string) string {
	t.Helper()
	out := strings.Replace(doc, line+"\n", "", 1)
	if out == doc {
		t.Fatalf("line %q not found in base document", line)
	}
	return out
}

// replace swaps one exact line in doc, failing the test if the line is not
// present.
func replace(t *testing.T, doc, line, with string) string {
	t.Helper()
	out := strings.Replace(doc, line+"\n", with+"\n", 1)
	if out == doc {
		t.Fatalf("line %q not found in base document", line)
	}
	return out
}

func TestLoadDeclaredValidFixture(t *testing.T) {
	decl, err := discover.LoadDeclared(fixturePath)
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	// LoadDeclared now returns a Declaration wrapping the manifest alongside
	// the skill only executables list (Task 2.2's sanctioned API change).
	m := decl.Manifest
	if decl.Executables != nil {
		t.Errorf("Executables = %v, want nil for an mcp-server declaration", decl.Executables)
	}

	// The loader returns a partial manifest by design: it never reads the
	// clock, never stamps a generator, and never composes an SBOM.
	if !m.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt = %v, want zero; attest stamps the clock", m.GeneratedAt)
	}
	if m.Generator != (manifest.GeneratorInfo{}) {
		t.Errorf("Generator = %+v, want zero; attest stamps the generator", m.Generator)
	}
	if m.Dependencies != nil {
		t.Errorf("Dependencies = %+v, want nil; SBOMs are composed later", m.Dependencies)
	}

	if m.SchemaVersion != "1.0.0" {
		t.Errorf("SchemaVersion = %q, want 1.0.0", m.SchemaVersion)
	}
	wantArtifact := manifest.PredicateArtifact{
		Kind:    manifest.KindMCPServer,
		Name:    "fake-caller",
		Version: "1.0.0",
		Source:  manifest.SourceNPM,
	}
	if m.Artifact != wantArtifact {
		t.Errorf("Artifact = %+v, want %+v", m.Artifact, wantArtifact)
	}

	if m.Skill != nil {
		t.Errorf("Skill = %+v, want nil for an mcp-server declaration", m.Skill)
	}
	if m.MCP == nil {
		t.Fatal("MCP surface is nil; the declared transports must be mapped")
	}
	if !reflect.DeepEqual(m.MCP.Transports, []string{"stdio"}) {
		t.Errorf("Transports = %v, want [stdio]", m.MCP.Transports)
	}
	// Tools, resources, and prompts are extraction owned: the loader must
	// leave them nil for attest to fill in.
	if m.MCP.Tools != nil || m.MCP.Resources != nil || m.MCP.Prompts != nil {
		t.Errorf("extraction owned mcp fields must stay nil, got tools=%v resources=%v prompts=%v",
			m.MCP.Tools, m.MCP.Resources, m.MCP.Prompts)
	}

	wantCaps := manifest.CapabilitySet{
		NetworkEgress: []manifest.EgressRule{
			{Host: "api.example.com", Ports: []int{443}, Reason: "Calls the example telephony API"},
		},
		Filesystem: []manifest.FSRule{
			{Path: "${home}/.fake-caller/**", Access: "readwrite", Reason: "Stores call recordings and session cache"},
		},
		Exec: []manifest.ExecRule{
			{Binary: "ffmpeg", Reason: "Transcodes recorded audio"},
		},
		Env:     []string{"API_TOKEN"},
		Secrets: []string{"api-key:example"},
	}
	if !reflect.DeepEqual(m.Capabilities, wantCaps) {
		t.Errorf("Capabilities = %+v, want %+v", m.Capabilities, wantCaps)
	}

	// Validate requires a complete manifest: a non zero UTC GeneratedAt, a
	// generator block, and all surface arrays non nil. The loader returns a
	// partial manifest by design, so this test completes it minimally the
	// way attest will: stamp the clock and generator, and fill the
	// extraction owned mcp arrays with empty non nil slices. Transports are
	// left alone because they are declared in the YAML, not extracted.
	m.GeneratedAt = time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)
	m.Generator = manifest.GeneratorInfo{Name: "smithmark", Version: "test"}
	m.MCP.Tools = []manifest.ToolDecl{}
	m.MCP.Resources = []string{}
	m.MCP.Prompts = []string{}
	if issues := m.Validate(); len(issues) != 0 {
		t.Errorf("completed fixture manifest is invalid: %+v", issues)
	}
}

func TestLoadDeclaredSkill(t *testing.T) {
	decl, err := discover.LoadDeclared(writeDecl(t, validSkillDecl))
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	m := decl.Manifest
	if decl.Executables != nil {
		t.Errorf("Executables = %v, want nil when smithmark.yaml declares no executables key", decl.Executables)
	}
	if m.Artifact.Kind != manifest.KindSkill || m.Artifact.Version != "" {
		t.Errorf("Artifact = %+v, want kind skill with no version", m.Artifact)
	}
	if m.MCP != nil {
		t.Errorf("MCP = %+v, want nil for a skill declaration", m.MCP)
	}
	if m.Skill == nil {
		t.Fatal("Skill surface is nil; invokesTools must be mapped")
	}
	// An empty invokesTools list is allowed and must survive as a non nil
	// empty slice: the key was declared, as distinct from absent.
	if m.Skill.InvokesTools == nil || len(m.Skill.InvokesTools) != 0 {
		t.Errorf("InvokesTools = %v, want a non nil empty slice", m.Skill.InvokesTools)
	}
	// EntryDigest and scripts are extraction owned: the walker fills them.
	if m.Skill.EntryDigest != nil || m.Skill.Scripts != nil {
		t.Errorf("extraction owned skill fields must stay nil, got entryDigest=%v scripts=%v",
			m.Skill.EntryDigest, m.Skill.Scripts)
	}
}

// Unknown keys are errors at every nesting level via KnownFields(true):
// yaml.v3 applies the known fields check recursively wherever it decodes
// into a struct, including structs reached through pointers and sequence
// elements (proven by the nested cases below). Documents beyond the first
// and empty documents are rejected too.
func TestLoadDeclaredRejectsMalformedDocuments(t *testing.T) {
	egressUnknown := replace(t, validMCPDecl, "  networkEgress: []",
		"  networkEgress:\n    - host: api.example.com\n      protocol: https")
	cases := []struct {
		name string
		doc  string
	}{
		{"top level unknown key", validMCPDecl + "publisher: acme\n"},
		{"unknown key in capabilities block", replace(t, validMCPDecl, "  secrets: []", "  secrets: []\n  tokens: []")},
		// Declaring tools is an unknown field by construction: the mcp
		// block accepts only transports, because tool listings are
		// extracted from the running server (U2), never declared.
		{"tools declared in mcp block", replace(t, validMCPDecl, "  transports: [stdio]", "  transports: [stdio]\n  tools: []")},
		{"unknown key in an egress rule", egressUnknown},
		{"second yaml document", validMCPDecl + "---\nkind: skill\n"},
		{"empty document", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := discover.LoadDeclared(writeDecl(t, tc.doc)); err == nil {
				t.Error("malformed document accepted; strict loading required (U1, D6)")
			}
		})
	}
}

func TestLoadDeclaredMissingFile(t *testing.T) {
	_, err := discover.LoadDeclared(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("missing file accepted; LoadDeclared must return an error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a wrapped os.ErrNotExist", err)
	}
}

// Required keys at the authoring surface, mirroring D6: kind, name, source,
// and all five capability keys must be present; version is required for kind
// mcp-server (U4); an mcp declaration must list its transports and a skill
// declaration must carry invokesTools. Each absence is a typed coded error.
func TestLoadDeclaredRequiredKeys(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want string
	}{
		{"missing kind", without(t, validMCPDecl, "kind: mcp-server"), codes.ManifestFieldRequired},
		{"unknown kind", replace(t, validMCPDecl, "kind: mcp-server", "kind: container"), codes.ManifestEnumInvalid},
		{"missing name", without(t, validMCPDecl, "name: fake-caller"), codes.ManifestFieldRequired},
		{"missing source", without(t, validMCPDecl, "source: npm"), codes.ManifestFieldRequired},
		{"missing version for mcp server", without(t, validMCPDecl, "version: 1.0.0"), codes.ManifestVersionRequired},
		{"missing networkEgress", without(t, validMCPDecl, "  networkEgress: []"), codes.ManifestCapabilitiesKeyMissing},
		{"missing filesystem", without(t, validMCPDecl, "  filesystem: []"), codes.ManifestCapabilitiesKeyMissing},
		{"missing exec", without(t, validMCPDecl, "  exec: []"), codes.ManifestCapabilitiesKeyMissing},
		{"missing env", without(t, validMCPDecl, "  env: []"), codes.ManifestCapabilitiesKeyMissing},
		{"missing secrets", without(t, validMCPDecl, "  secrets: []"), codes.ManifestCapabilitiesKeyMissing},
		// A null value is absence, not an empty declaration: "env:" with no
		// value decodes to a nil slice, exactly like a missing key.
		{"null capability key", replace(t, validMCPDecl, "  env: []", "  env:"), codes.ManifestCapabilitiesKeyMissing},
		{"missing capabilities block", "kind: mcp-server\nname: x\nversion: 1.0.0\nsource: npm\nmcp:\n  transports: [stdio]\n", codes.ManifestCapabilitiesKeyMissing},
		{"missing transports", without(t, validMCPDecl, "  transports: [stdio]"), codes.ManifestSurfaceKeyMissing},
		{"missing mcp block", without(t, without(t, validMCPDecl, "  transports: [stdio]"), "mcp:"), codes.ManifestSurfaceKeyMissing},
		{"missing invokesTools", without(t, validSkillDecl, "  invokesTools: []"), codes.ManifestSurfaceKeyMissing},
		{"skill block on mcp kind", validMCPDecl + "skill:\n  invokesTools: []\n", codes.ManifestKindSurfaceMismatch},
		{"mcp block on skill kind", validSkillDecl + "mcp:\n  transports: [stdio]\n", codes.ManifestKindSurfaceMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := discover.LoadDeclared(writeDecl(t, tc.doc))
			var cerr *codes.Error
			if !errors.As(err, &cerr) {
				t.Fatalf("err = %v, want a *codes.Error carrying %s", err, tc.want)
			}
			if cerr.Code != tc.want {
				t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, tc.want, err)
			}
		})
	}
}

// validSkillDeclWithExecutables extends validSkillDecl with the optional
// executables key (Task 2.2): the walker's platform independent mode rule
// reads this list from the declaration rather than trusting a filesystem
// bit that Windows does not have.
const validSkillDeclWithExecutables = `kind: skill
name: hello-skill
source: local
skill:
  invokesTools: []
  executables:
    - scripts/greet.sh
    - bin/tool
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`

func TestLoadDeclaredSkillExecutablesRoundTrip(t *testing.T) {
	decl, err := discover.LoadDeclared(writeDecl(t, validSkillDeclWithExecutables))
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	want := []string{"scripts/greet.sh", "bin/tool"}
	if !reflect.DeepEqual(decl.Executables, want) {
		t.Errorf("Executables = %v, want %v", decl.Executables, want)
	}
}

// The executables key lives inside the skill block, so declaring it on an
// mcp-server document hits the same kind versus surface mismatch check that
// any skill block on an mcp kind already triggers; this test pins that the
// specific combination (executables present) is rejected too, per the
// controller resolution.
func TestLoadDeclaredExecutablesRejectedOnMCPKind(t *testing.T) {
	doc := validMCPDecl + "skill:\n  invokesTools: []\n  executables: [scripts/greet.sh]\n"
	_, err := discover.LoadDeclared(writeDecl(t, doc))
	var cerr *codes.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.ManifestKindSurfaceMismatch)
	}
	if cerr.Code != codes.ManifestKindSurfaceMismatch {
		t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, codes.ManifestKindSurfaceMismatch, err)
	}
}

// TestLoadDeclaredMCPCommand pins the optional launch command an mcp-server
// declaration may carry under its mcp block. attest hands this to ExtractTools
// when no --tools-from escape hatch is supplied (controller resolution 3), so
// it must survive strict parsing and travel out on Declaration.Command.
func TestLoadDeclaredMCPCommand(t *testing.T) {
	doc := replace(t, validMCPDecl, "  transports: [stdio]",
		"  transports: [stdio]\n  command: [npx, fake-caller, --stdio]")
	decl, err := discover.LoadDeclared(writeDecl(t, doc))
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	want := []string{"npx", "fake-caller", "--stdio"}
	if !reflect.DeepEqual(decl.Command, want) {
		t.Errorf("Command = %v, want %v", decl.Command, want)
	}
}

// TestLoadDeclaredCommandAbsent pins that Command is nil when no command key
// is declared, for both an mcp-server without the key and a skill declaration
// (where the mcp block that would hold a command is forbidden outright).
func TestLoadDeclaredCommandAbsent(t *testing.T) {
	mcp, err := discover.LoadDeclared(writeDecl(t, validMCPDecl))
	if err != nil {
		t.Fatalf("LoadDeclared mcp: %v", err)
	}
	if mcp.Command != nil {
		t.Errorf("Command = %v, want nil when the mcp block omits command", mcp.Command)
	}
	skill, err := discover.LoadDeclared(writeDecl(t, validSkillDecl))
	if err != nil {
		t.Fatalf("LoadDeclared skill: %v", err)
	}
	if skill.Command != nil {
		t.Errorf("Command = %v, want nil for a skill declaration", skill.Command)
	}
}

// TestLoadDeclaredCommandRejectedForSkill pins that command stays an mcp only
// key: a skill cannot smuggle one in. Inside an mcp block it trips the kind
// versus surface mismatch (a skill may not declare mcp at all); at the top
// level or inside the skill block it is an unknown field. Either way the
// declaration is rejected, never silently accepted.
func TestLoadDeclaredCommandRejectedForSkill(t *testing.T) {
	cases := map[string]string{
		"inside an mcp block": validSkillDecl + "mcp:\n  transports: [stdio]\n  command: [npx, x]\n",
		"at the top level":    "command: [npx, x]\n" + validSkillDecl,
		"inside the skill block": replace(t, validSkillDecl, "  invokesTools: []",
			"  invokesTools: []\n  command: [npx, x]"),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := discover.LoadDeclared(writeDecl(t, doc)); err == nil {
				t.Fatalf("declaration with a command key %s was accepted; it must be rejected", name)
			}
		})
	}
}

// skillFixturePath points at the committed repo root fixture skill, used to
// pin the canonical bundle digest end to end through the walker.
const skillFixturePath = "../../testdata/skills/hello-skill"

// pinnedHelloSkillDigest is computed once from the fixture at implementation
// time and then frozen, mirroring pkg/core/bundle's own golden vector rule:
// recompute only if the algorithm is believed wrong, never to make a failing
// test pass.
const pinnedHelloSkillDigest = "smithmark-bundle-v1:a4bdaaa7fd43eeca9269a369f0be3c87a9dedc8e052872064ad19ed26e27edda"

func TestWalkSkillGoldenDigest(t *testing.T) {
	files, _, _, err := discover.WalkSkill(skillFixturePath, []string{"scripts/greet.sh"})
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}
	got, err := bundle.Digest(files)
	if err != nil {
		t.Fatalf("bundle.Digest: %v", err)
	}
	if got != pinnedHelloSkillDigest {
		t.Errorf("digest drifted from the pinned fixture vector\n got: %s\nwant: %s", got, pinnedHelloSkillDigest)
	}
}

func TestWalkSkillSurfaceAndFrontmatter(t *testing.T) {
	files, surface, info, err := discover.WalkSkill(skillFixturePath, []string{"scripts/greet.sh"})
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}

	if info.Name != "hello-skill" || info.Version != "0.1.0" {
		t.Errorf("SkillInfo = %+v, want name hello-skill version 0.1.0", info)
	}

	// smithmark.yaml and SKILL.md are files under the root, so they are part
	// of the walked file set and thus the digest: the declaration ships
	// inside the bundle by design.
	wantModes := map[string]bundle.Mode{
		"SKILL.md":            bundle.ModeRegular,
		"scripts/greet.sh":    bundle.ModeExecutable,
		"references/notes.md": bundle.ModeRegular,
		"smithmark.yaml":      bundle.ModeRegular,
	}
	if len(files) != len(wantModes) {
		t.Fatalf("files = %+v, want %d entries", files, len(wantModes))
	}
	for _, f := range files {
		want, ok := wantModes[f.Path]
		if !ok {
			t.Errorf("unexpected path %q in walked file set", f.Path)
			continue
		}
		if f.Mode != want {
			t.Errorf("path %q mode = %s, want %s", f.Path, f.Mode, want)
		}
		if f.SHA256 == "" {
			t.Errorf("path %q has an empty sha256", f.Path)
		}
	}

	if surface.InvokesTools != nil {
		t.Errorf("InvokesTools = %v, want nil; the declaration owns this key, not the walker", surface.InvokesTools)
	}
	if len(surface.Scripts) != 3 {
		t.Fatalf("Scripts = %+v, want 3 entries (every file except SKILL.md)", surface.Scripts)
	}
	for i := 1; i < len(surface.Scripts); i++ {
		if surface.Scripts[i-1].Path >= surface.Scripts[i].Path {
			t.Errorf("Scripts not sorted by path: %+v", surface.Scripts)
		}
	}
	for _, s := range surface.Scripts {
		if s.Path == "SKILL.md" {
			t.Error("SKILL.md must not appear in Scripts; it is the entry point")
		}
	}
	if surface.EntryDigest["sha256"] == "" {
		t.Error("EntryDigest is empty")
	}
}

func TestWalkSkillMissingSKILLMD(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := discover.WalkSkill(dir, nil)
	var cerr *codes.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.ManifestFieldRequired)
	}
	if cerr.Code != codes.ManifestFieldRequired {
		t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, codes.ManifestFieldRequired, err)
	}
	if !strings.Contains(cerr.Detail, "SKILL.md") {
		t.Errorf("error detail %q does not name SKILL.md", cerr.Detail)
	}
}

func TestWalkSkillRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "SKILL.md")
	if err := os.WriteFile(target, []byte("---\nname: x\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "sneaky")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink on this platform: %v", err)
	}
	_, _, _, err := discover.WalkSkill(dir, nil)
	var cerr *codes.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.BundleSymlinkRejected)
	}
	if cerr.Code != codes.BundleSymlinkRejected {
		t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, codes.BundleSymlinkRejected, err)
	}
	if !strings.Contains(cerr.Detail, "sneaky") {
		t.Errorf("error detail %q does not name the offending path", cerr.Detail)
	}
}

func TestWalkSkillFrontmatterExtraction(t *testing.T) {
	dir := t.TempDir()
	doc := "---\nname: sample\nversion: 2.3.4\n---\n\nBody paragraph.\n"
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, info, err := discover.WalkSkill(dir, nil)
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}
	if info.Name != "sample" || info.Version != "2.3.4" {
		t.Errorf("SkillInfo = %+v, want name sample version 2.3.4", info)
	}
}

// A declared executable must get ModeExecutable even when the file has no
// executable bit on disk: the declaration list is what makes the digest
// platform independent, so it must win regardless of what git or the local
// filesystem happen to report.
func TestWalkSkillDeclaredExecutableForcesModeWithoutDiskBit(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: x\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, _, _, err := discover.WalkSkill(dir, []string{"run.sh"})
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}
	found := false
	for _, f := range files {
		if f.Path == "run.sh" {
			found = true
			if f.Mode != bundle.ModeExecutable {
				t.Errorf("declared executable run.sh has mode %s, want %s", f.Mode, bundle.ModeExecutable)
			}
		}
	}
	if !found {
		t.Fatal("run.sh not found in walked file set")
	}
}

// An undeclared file with the unix executable bit set falls back to
// ModeExecutable; this fallback only makes sense on unix, since Windows has
// no such bit to report.
func TestWalkSkillUndeclaredExecBitOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix executable bit fallback does not apply on windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: x\n---\nbody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	files, _, _, err := discover.WalkSkill(dir, nil)
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}
	found := false
	for _, f := range files {
		if f.Path == "run.sh" {
			found = true
			if f.Mode != bundle.ModeExecutable {
				t.Errorf("undeclared exec bit file run.sh has mode %s, want %s", f.Mode, bundle.ModeExecutable)
			}
		}
	}
	if !found {
		t.Fatal("run.sh not found in walked file set")
	}
}
