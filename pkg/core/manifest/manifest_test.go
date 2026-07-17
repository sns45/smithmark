package manifest

import (
	"encoding/json"
	"reflect"
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

func TestParseRejectsTrailingData(t *testing.T) {
	if _, err := Parse([]byte(validMCP + "{}")); err == nil {
		t.Error("trailing data after the JSON document accepted; Parse must reject it")
	}
}

func TestParseRejectsEmptyInput(t *testing.T) {
	if _, err := Parse(nil); err == nil {
		t.Error("empty input accepted; Parse must return an error")
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
	// Key ORDER is the observable that distinguishes RFC 8785 output from
	// plain json.Marshal: the struct declares schemaVersion first, so an
	// implementation that skipped the canonicalizer would emit it first.
	// Each key below appears exactly once in this document, all at the top
	// level, so index comparison checks alphabetical ordering directly.
	keys := []string{`"artifact"`, `"capabilities"`, `"generatedAt"`, `"generator"`, `"mcp"`, `"schemaVersion"`}
	prev := -1
	for _, k := range keys {
		i := strings.Index(string(a), k)
		if i < 0 {
			t.Fatalf("Canonical output missing key %s", k)
		}
		if i <= prev {
			t.Errorf("Canonical output keys not in alphabetical order: %s at %d does not follow previous key at %d", k, i, prev)
		}
		prev = i
	}
}

// addNumbersSchema is the same fixed schema string pkg/discover's fakemcp
// fixture and mcptools_test.go both use for the add_numbers tool (Task 2.3):
// one pinned vector here proves the algorithm, and pkg/discover reuses it
// end to end through ExtractTools and ToolsFromFile.
const addNumbersSchema = `{"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}`

// pinnedAddNumbersSchemaDigest is computed once from addNumbersSchema at
// implementation time and then frozen, mirroring pkg/core/bundle's own
// golden vector rule: recompute only if the algorithm is believed wrong,
// never to make a failing test pass.
const pinnedAddNumbersSchemaDigest = "710001a478edca4fcc7ed6cf35253c1dc872c3bf5e691a091b35f3c4fde52779"

func TestSchemaDigestPinnedVector(t *testing.T) {
	digest, err := SchemaDigest(json.RawMessage(addNumbersSchema))
	if err != nil {
		t.Fatalf("SchemaDigest: %v", err)
	}
	want := DigestSet{"sha256": pinnedAddNumbersSchemaDigest}
	if !reflect.DeepEqual(digest, want) {
		t.Errorf("SchemaDigest = %+v, want %+v", digest, want)
	}
}

// TestSchemaDigestKeyOrderIndependent proves canonicalization, not raw byte
// hashing: two JSON objects with the same keys and values in different
// orders must digest identically.
func TestSchemaDigestKeyOrderIndependent(t *testing.T) {
	a, err := SchemaDigest(json.RawMessage(`{"a":1,"b":2}`))
	if err != nil {
		t.Fatalf("SchemaDigest: %v", err)
	}
	b, err := SchemaDigest(json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("SchemaDigest: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("SchemaDigest differs by key order: %+v vs %+v", a, b)
	}
}

func TestSchemaDigestRejectsEmptySchema(t *testing.T) {
	if _, err := SchemaDigest(nil); err == nil {
		t.Error("empty schema accepted; SchemaDigest must return an error")
	}
	if _, err := SchemaDigest(json.RawMessage{}); err == nil {
		t.Error("empty schema accepted; SchemaDigest must return an error")
	}
}
