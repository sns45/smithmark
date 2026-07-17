package discover_test

import (
	"context"
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

// fakemcpPath points at the committed fixture: a tiny Go program speaking
// just enough of the MCP stdio transport to answer initialize and tools/list
// with two tools of fixed shape (Task 2.3). "go run" accepts this explicit
// directory path even though it lives under testdata, which a package
// pattern like ./... would otherwise skip.
const fakemcpPath = "../../testdata/fakemcp"

// pinnedHelloWorldDigest and pinnedAddNumbersDigest are computed once from
// the fixture's fixed schema strings and then frozen, mirroring
// pkg/core/bundle's own golden vector rule: recompute only if the algorithm
// is believed wrong, never to make a failing test pass. addNumbersSchema in
// pkg/core/manifest's own test pins the same schema string, so the two
// packages cross check one another's use of SchemaDigest.
const (
	pinnedHelloWorldDigest = "9b0a69543e7ea39241d0b33f56a707ed57252f637e756b68c873733dd2e24e88"
	pinnedAddNumbersDigest = "710001a478edca4fcc7ed6cf35253c1dc872c3bf5e691a091b35f3c4fde52779"
)

func fakemcpCommand(extra ...string) []string {
	return append([]string{"go", "run", fakemcpPath}, extra...)
}

func wantFixtureTools() []manifest.ToolDecl {
	return []manifest.ToolDecl{
		{
			Name:              "hello_world",
			Description:       "Say hello to someone by name.",
			InputSchemaDigest: manifest.DigestSet{"sha256": pinnedHelloWorldDigest},
		},
		{
			Name:              "add_numbers",
			Description:       "Add two numbers together.",
			InputSchemaDigest: manifest.DigestSet{"sha256": pinnedAddNumbersDigest},
		},
	}
}

// TestExtractToolsFakeServer also warms the go build cache for the fixture
// binary, which keeps TestExtractToolsHangTimesOut's short context deadline
// from being eaten by compilation rather than the protocol hang it exists to
// exercise.
func TestExtractToolsFakeServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tools, transports, err := discover.ExtractTools(ctx, fakemcpCommand())
	if err != nil {
		t.Fatalf("ExtractTools: %v", err)
	}
	if !reflect.DeepEqual(transports, []string{"stdio"}) {
		t.Errorf("transports = %v, want [stdio]", transports)
	}
	if want := wantFixtureTools(); !reflect.DeepEqual(tools, want) {
		t.Errorf("tools = %+v, want %+v", tools, want)
	}
}

func TestExtractToolsHangTimesOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	start := time.Now()
	_, _, err := discover.ExtractTools(ctx, fakemcpCommand("-hang"))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ExtractTools succeeded against a hung server; want a context timeout error")
	}
	var cerr *codes.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.ToolExtractionFailed)
	}
	if cerr.Code != codes.ToolExtractionFailed {
		t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, codes.ToolExtractionFailed, err)
	}
	// The context deadline is 2s; this asserts prompt cancellation rather
	// than some unrelated much longer failure mode, with slack for a slow
	// CI runner and process teardown.
	if elapsed > 10*time.Second {
		t.Errorf("ExtractTools took %s to return after a 2s context timeout; want prompt cancellation", elapsed)
	}
}

func TestExtractToolsRejectsEmptyCommand(t *testing.T) {
	_, _, err := discover.ExtractTools(context.Background(), nil)
	var cerr *codes.Error
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.ToolExtractionFailed)
	}
	if cerr.Code != codes.ToolExtractionFailed {
		t.Fatalf("code = %s, want %s (err: %v)", cerr.Code, codes.ToolExtractionFailed, err)
	}
}

// validToolsFromFile reuses the exact same fixed schema strings as the
// fakemcp fixture, so pinnedHelloWorldDigest and pinnedAddNumbersDigest
// apply here too: --tools-from and a live extraction must map identically
// (U2).
const validToolsFromFile = `{
  "tools": [
    {"name": "hello_world", "description": "Say hello to someone by name.", "inputSchema": {"type":"object","properties":{"name":{"type":"string"},"loud":{"type":"boolean"}},"required":["name"]}},
    {"name": "add_numbers", "description": "Add two numbers together.", "inputSchema": {"type":"object","properties":{"a":{"type":"number"},"b":{"type":"number"}},"required":["a","b"]}}
  ]
}`

func writeToolsFile(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tools.json")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestToolsFromFileValid(t *testing.T) {
	tools, err := discover.ToolsFromFile(writeToolsFile(t, validToolsFromFile))
	if err != nil {
		t.Fatalf("ToolsFromFile: %v", err)
	}
	if want := wantFixtureTools(); !reflect.DeepEqual(tools, want) {
		t.Errorf("tools = %+v, want %+v", tools, want)
	}
}

func TestToolsFromFileRejectsUnknownFields(t *testing.T) {
	doc := strings.Replace(validToolsFromFile, `"name": "hello_world"`, `"name": "hello_world", "extra": true`, 1)
	if _, err := discover.ToolsFromFile(writeToolsFile(t, doc)); err == nil {
		t.Error("unknown field accepted; ToolsFromFile must reject it (strict parsing, U2)")
	}
}

func TestToolsFromFileRejectsUnknownTopLevelField(t *testing.T) {
	doc := strings.Replace(validToolsFromFile, `"tools":`, `"transports": ["stdio"], "tools":`, 1)
	if _, err := discover.ToolsFromFile(writeToolsFile(t, doc)); err == nil {
		t.Error("unknown top level field accepted; ToolsFromFile must reject it (strict parsing, U2)")
	}
}

func TestToolsFromFileMissingFile(t *testing.T) {
	_, err := discover.ToolsFromFile(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("missing file accepted; ToolsFromFile must return an error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err = %v, want a wrapped os.ErrNotExist", err)
	}
}
