package manifest

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// assertCode fails unless issues contains want; an empty want asserts the
// manifest is valid with no issues at all.
func assertCode(t *testing.T, issues []Issue, want string) {
	t.Helper()
	if want == "" {
		if len(issues) != 0 {
			t.Fatalf("expected valid, got %+v", issues)
		}
		return
	}
	for _, is := range issues {
		if is.Code == want {
			return
		}
	}
	t.Fatalf("expected code %s, got %+v", want, issues)
}

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

		// F2: exec binary is a basename pattern with no slash or backslash.
		{"empty exec binary", func(m *CapabilityManifest) { m.Capabilities.Exec = []ExecRule{{Binary: ""}} }, codes.ExecBinaryInvalid},
		{"exec binary with slash", func(m *CapabilityManifest) { m.Capabilities.Exec = []ExecRule{{Binary: "/usr/bin/x"}} }, codes.ExecBinaryInvalid},
		{"exec basename ok", func(m *CapabilityManifest) { m.Capabilities.Exec = []ExecRule{{Binary: "ffmpeg"}} }, ""},
		{"exec bare star ok", func(m *CapabilityManifest) { m.Capabilities.Exec = []ExecRule{{Binary: "*"}} }, ""},
		{"exec trailing star ok", func(m *CapabilityManifest) { m.Capabilities.Exec = []ExecRule{{Binary: "python*"}} }, ""},

		// F3: required surface array keys must be present (non nil).
		{"mcp resources key missing", func(m *CapabilityManifest) { m.MCP.Resources = nil }, codes.ManifestSurfaceKeyMissing},
		{"skill invokesTools key missing", func(m *CapabilityManifest) {
			m.Artifact = PredicateArtifact{Kind: KindSkill, Name: "s", Source: SourceLocal}
			m.MCP = nil
			m.Skill = &SkillSurface{EntryDigest: DigestSet{"sha256": strings.Repeat("ab", 32)}, Scripts: []FileRef{}, InvokesTools: nil}
		}, codes.ManifestSurfaceKeyMissing},

		// F4: filesystem paths reject dotdot segments and backslashes.
		{"token dotdot fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "${home}/../x", Access: "read"}}
		}, codes.FSPathInvalid},
		{"relative dotdot fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "../x", Access: "read"}}
		}, codes.FSPathInvalid},
		{"backslash dotdot fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: `..\x`, Access: "read"}}
		}, codes.FSPathInvalid},
		{"interior dotdot fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "a/../b", Access: "read"}}
		}, codes.FSPathInvalid},
		{"relative fs path ok", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "a/b", Access: "read"}}
		}, ""},

		// F6: required identity strings.
		{"artifact name required", func(m *CapabilityManifest) { m.Artifact.Name = "" }, codes.ManifestFieldRequired},
		{"tool name required", func(m *CapabilityManifest) { m.MCP.Tools[0].Name = "" }, codes.ManifestFieldRequired},

		// F13 and F19: host grammar pins, including the IPv6 zone rejection.
		{"ipv6 zone literal host", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "fe80::1%eth0"}}
		}, codes.EgressHostInvalid},
		{"ipv6 literal host ok", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "fe80::1"}}
		}, ""},
		{"ipv4 literal host ok", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "192.168.0.1"}}
		}, ""},
		{"bare wildcard host ok", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "*"}}
		}, ""},

		// F19: enum and filesystem path pins.
		{"unknown kind enum", func(m *CapabilityManifest) { m.Artifact.Kind = "docker-image" }, codes.ManifestEnumInvalid},
		{"unknown source enum", func(m *CapabilityManifest) { m.Artifact.Source = "cargo" }, codes.ManifestEnumInvalid},
		{"tmp token fs path ok", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "${tmp}/x", Access: "read"}}
		}, ""},
		{"cwd token fs path ok", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "${cwd}/x", Access: "read"}}
		}, ""},
		{"drive letter fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "C:/x", Access: "read"}}
		}, codes.FSPathInvalid},
		{"backslash drive fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: `C:\x`, Access: "read"}}
		}, codes.FSPathInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mutate(m)
			assertCode(t, m.Validate(), tc.want)
		})
	}
}

// F5: generatedAt must be a non zero UTC timestamp with no sub second
// precision.
func TestValidateGeneratedAt(t *testing.T) {
	cases := []struct {
		name string
		when time.Time
		want string
	}{
		{"zero time", time.Time{}, codes.GeneratedAtInvalid},
		{"non utc offset", time.Date(2026, 7, 16, 0, 0, 0, 0, time.FixedZone("+0530", 5*3600+30*60)), codes.GeneratedAtInvalid},
		{"sub second precision", time.Date(2026, 7, 16, 0, 0, 0, 1, time.UTC), codes.GeneratedAtInvalid},
		{"fixture utc time", time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			m.GeneratedAt = tc.when
			assertCode(t, m.Validate(), tc.want)
		})
	}
}

// The parse path of an RFC 3339 Z timestamp still validates: it lands in UTC
// with a zero zone offset and no sub second precision.
func TestValidateGeneratedAtParsePathValid(t *testing.T) {
	m, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatal(err)
	}
	for _, is := range m.Validate() {
		if is.Code == codes.GeneratedAtInvalid {
			t.Errorf("parsed RFC 3339 Z timestamp rejected: %+v", is)
		}
	}
}

// F7 and F19: skill script paths are clean, unique relative paths; mode is
// regular or executable.
func TestValidateSkillScriptPaths(t *testing.T) {
	d := DigestSet{"sha256": strings.Repeat("ab", 32)}
	skill := func(scripts []FileRef) *CapabilityManifest {
		m := validManifest()
		m.Artifact = PredicateArtifact{Kind: KindSkill, Name: "s", Source: SourceLocal}
		m.MCP = nil
		m.Skill = &SkillSurface{EntryDigest: d, Scripts: scripts, InvokesTools: []string{}}
		return m
	}
	cases := []struct {
		name    string
		scripts []FileRef
		want    string
	}{
		{"absolute path", []FileRef{{Path: "/etc/x", Mode: "regular", Digest: d}}, codes.SkillScriptPathInvalid},
		{"dotdot path", []FileRef{{Path: "a/../b", Mode: "regular", Digest: d}}, codes.SkillScriptPathInvalid},
		{"duplicate path", []FileRef{
			{Path: "scripts/x.py", Mode: "regular", Digest: d},
			{Path: "scripts/x.py", Mode: "regular", Digest: d},
		}, codes.SkillScriptPathInvalid},
		{"setuid mode", []FileRef{{Path: "scripts/x.py", Mode: "setuid", Digest: d}}, codes.ModeInvalid},
		{"clean path ok", []FileRef{{Path: "scripts/x.py", Mode: "regular", Digest: d}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertCode(t, skill(tc.scripts).Validate(), tc.want)
		})
	}
}

// F19: an unknown artifact kind reports the enum code and must not also report
// a surface mismatch, even when a skill surface is set.
func TestUnknownKindSkipsSurfaceMismatch(t *testing.T) {
	m := validManifest()
	m.Artifact.Kind = "docker-image"
	m.MCP = nil
	m.Skill = &SkillSurface{
		EntryDigest:  DigestSet{"sha256": strings.Repeat("ab", 32)},
		Scripts:      []FileRef{},
		InvokesTools: []string{},
	}
	var hasEnum, hasMismatch bool
	for _, is := range m.Validate() {
		switch is.Code {
		case codes.ManifestEnumInvalid:
			hasEnum = true
		case codes.ManifestKindSurfaceMismatch:
			hasMismatch = true
		}
	}
	if !hasEnum {
		t.Error("unknown kind must report MANIFEST_ENUM_INVALID")
	}
	if hasMismatch {
		t.Error("unknown kind must not also report MANIFEST_KIND_SURFACE_MISMATCH")
	}
}

// F20: a valid manifest yields a non nil empty slice so JSON renders [] not
// null.
func TestValidateEmptyResultIsNonNilEmpty(t *testing.T) {
	issues := validManifest().Validate()
	if issues == nil {
		t.Fatal("Validate returned nil for a valid manifest; want a non nil empty slice")
	}
	if len(issues) != 0 {
		t.Fatalf("expected no issues, got %+v", issues)
	}
	b, err := json.Marshal(issues)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[]" {
		t.Errorf("marshaled empty issues = %s, want []", b)
	}
}

// F19: the struct literal fixture must decode to exactly the JSON fixture. The
// JSON in manifest_test.go is the source of truth. DeepEqual on the
// GeneratedAt time.Time holds because stdlib parses the RFC 3339 Z timestamp
// back to the time.UTC singleton.
func TestFixtureEquivalence(t *testing.T) {
	parsed, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, validManifest()) {
		t.Errorf("struct fixture drifted from the JSON fixture\n got: %+v\nwant: %+v", parsed, validManifest())
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
