package manifest

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// validManifest returns the struct literal equivalent of the validMCP JSON
// fixture in manifest_test.go: schemaVersion 1.0.0, an mcp-server artifact
// from npm, one tool, stdio transport, and all five capability keys present
// but declared empty.
func validManifest() *CapabilityManifest {
	return &CapabilityManifest{
		SchemaVersion: "1.0.0",
		Artifact: PredicateArtifact{
			Kind:    KindMCPServer,
			Name:    "better-call-claude",
			Version: "1.4.2",
			Source:  SourceNPM,
		},
		MCP: &MCPSurface{
			Transports: []string{"stdio"},
			Tools: []ToolDecl{
				{Name: "initiate_call", InputSchemaDigest: DigestSet{"sha256": "ab"}},
			},
			Resources: []string{},
			Prompts:   []string{},
		},
		Capabilities: CapabilitySet{
			NetworkEgress: []EgressRule{},
			Filesystem:    []FSRule{},
			Exec:          []ExecRule{},
			Env:           []string{},
			Secrets:       []string{},
		},
		GeneratedAt: time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC),
		Generator: GeneratorInfo{
			Name:    "smithmark",
			Version: "0.1.0",
		},
	}
}

func TestValidateTable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *CapabilityManifest)
		want   string // expected code, empty means valid
	}{
		{"valid", func(m *CapabilityManifest) {}, ""},
		{"bad schema version", func(m *CapabilityManifest) { m.SchemaVersion = "2.0.0" }, codes.ManifestSchemaVersionUnsupported},
		{"skill surface on mcp kind", func(m *CapabilityManifest) { m.Skill = &SkillSurface{} }, codes.ManifestKindSurfaceMismatch},
		{"missing capabilities key", func(m *CapabilityManifest) { m.Capabilities.Env = nil }, codes.ManifestCapabilitiesKeyMissing},
		{"wildcard host ok", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "*.googleapis.com"}}
		}, ""},
		{"double wildcard host", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "*.*.googleapis.com"}}
		}, codes.EgressHostInvalid},
		{"port out of range", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "example.com", Ports: []int{70000}}}
		}, codes.EgressPortInvalid},
		{"absolute fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "/etc/passwd", Access: "read"}}
		}, codes.FSPathInvalid},
		{"token fs path ok", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "${home}/.config/x/**", Access: "readwrite"}}
		}, ""},
		{"malformed token fs path", func(m *CapabilityManifest) {
			// "${home}x" has no separator after the token: the token form
			// requires the rest of the path to be empty or start with "/".
			m.Capabilities.Filesystem = []FSRule{{Path: "${home}x", Access: "read"}}
		}, codes.FSPathInvalid},
		{"bad access", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "data/**", Access: "execute"}}
		}, codes.FSAccessInvalid},
		{"env prefix ok", func(m *CapabilityManifest) { m.Capabilities.Env = []string{"AWS_*"} }, ""},
		{"env lowercase", func(m *CapabilityManifest) { m.Capabilities.Env = []string{"aws_key"} }, codes.EnvNameInvalid},
		{"secret format", func(m *CapabilityManifest) { m.Capabilities.Secrets = []string{"google oauth"} }, codes.SecretFormatInvalid},
		{"secret ok", func(m *CapabilityManifest) { m.Capabilities.Secrets = []string{"oauth:google"} }, ""},
		{"bad transport", func(m *CapabilityManifest) { m.MCP.Transports = []string{"websocket"} }, codes.TransportInvalid},
		{"version optional for skill", func(m *CapabilityManifest) {
			m.Artifact = PredicateArtifact{Kind: KindSkill, Name: "dear-claude-notes", Source: SourceLocal}
			m.MCP = nil
			m.Skill = &SkillSurface{EntryDigest: DigestSet{"sha256": strings.Repeat("ab", 32)}, Scripts: []FileRef{}, InvokesTools: []string{}}
		}, ""},
		{"version required for mcp", func(m *CapabilityManifest) { m.Artifact.Version = "" }, codes.ManifestVersionRequired},
		{"uppercase digest hex", func(m *CapabilityManifest) {
			m.MCP.Tools[0].InputSchemaDigest = DigestSet{"sha256": "AB"}
		}, codes.DigestInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mutate(m)
			issues := m.Validate()
			if tc.want == "" && len(issues) != 0 {
				t.Fatalf("expected valid, got %+v", issues)
			}
			if tc.want != "" {
				found := false
				for _, is := range issues {
					if is.Code == tc.want {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected code %s, got %+v", tc.want, issues)
				}
			}
		})
	}
}

func TestValidateIsDeterministicallySorted(t *testing.T) {
	m := validManifest()
	m.SchemaVersion = "9"
	m.Capabilities.Env = []string{"bad", "also bad"}
	a := m.Validate()
	b := m.Validate()
	if !reflect.DeepEqual(a, b) {
		t.Error("Validate output is not deterministic")
	}
	if !sort.SliceIsSorted(a, func(i, j int) bool {
		if a[i].Code != a[j].Code {
			return a[i].Code < a[j].Code
		}
		return a[i].Path < a[j].Path
	}) {
		t.Errorf("issues not sorted by (Code, Path): %+v", a)
	}
}
