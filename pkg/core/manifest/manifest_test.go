package manifest

import (
	"strings"
	"testing"
)

const validMCP = `{
  "schemaVersion": "1.0.0",
  "artifact": {"kind": "mcp-server", "name": "better-call-claude", "version": "1.4.2", "source": "npm"},
  "mcp": {"transports": ["stdio"], "tools": [{"name": "initiate_call", "inputSchemaDigest": {"sha256": "ab"}}], "resources": [], "prompts": []},
  "capabilities": {"networkEgress": [], "filesystem": [], "exec": [], "env": [], "secrets": []},
  "generatedAt": "2026-07-16T00:00:00Z",
  "generator": {"name": "smithmark", "version": "0.1.0"}
}`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Artifact.Kind != KindMCPServer || m.MCP == nil || m.Skill != nil {
		t.Errorf("unexpected parse result: %+v", m)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	for name, doc := range map[string]string{
		"top level": strings.Replace(validMCP, `"schemaVersion"`, `"extra": 1, "schemaVersion"`, 1),
		"nested":    strings.Replace(validMCP, `"env": []`, `"env": [], "sneaky": true`, 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: unknown field accepted; strict parsing required (spec 2.2)", name)
		}
	}
}

func TestCanonicalIsDeterministicAndSorted(t *testing.T) {
	m, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Canonical()
	if string(a) != string(b) {
		t.Error("Canonical is not deterministic")
	}
	if strings.Contains(string(a), "\n") || strings.Contains(string(a), ": ") {
		t.Error("Canonical output contains insignificant whitespace")
	}
}
