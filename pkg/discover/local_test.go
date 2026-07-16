package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

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
	m, err := discover.LoadDeclared(fixturePath)
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
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
	m, err := discover.LoadDeclared(writeDecl(t, validSkillDecl))
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
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
