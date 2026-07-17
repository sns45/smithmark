package lint_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/lint"
)

// jsFixtureDir is the committed JS and TS fixture corpus for task 4.1,
// relative to this test package.
const jsFixtureDir = "../../../testdata/lint/js"

// loadJSFixture reads one committed fixture file and returns it as a
// lint.Source. Test file I/O is fine here; DetectJS itself never touches the
// filesystem, since sources arrive pre read (the pkg/core purity guard).
func loadJSFixture(t *testing.T, name string) lint.Source {
	t.Helper()
	path := filepath.Join(jsFixtureDir, name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return lint.Source{Path: path, Content: content}
}

// lineOf returns the 1 based line number of the first line in content that
// contains needle, failing the test if no line does. Tests use it to find
// the construct they care about inside a fixture instead of hardcoding a
// line number that would silently drift if the fixture is ever edited.
func lineOf(t *testing.T, content []byte, needle string) int {
	t.Helper()
	for i, line := range strings.Split(string(content), "\n") {
		if strings.Contains(line, needle) {
			return i + 1
		}
	}
	t.Fatalf("no line containing %q found in fixture", needle)
	return 0
}

// mustDetect asserts dets contains exactly one Detection at the line
// containing needle in src, with the given class and symbol.
func mustDetect(t *testing.T, dets []lint.Detection, src lint.Source, needle, class, symbol string) {
	t.Helper()
	line := lineOf(t, src.Content, needle)
	want := fmt.Sprintf("%s:%d", src.Path, line)
	for _, d := range dets {
		if d.Location == want {
			if d.Class != class || d.Symbol != symbol {
				t.Errorf("detection at %s = {%s %s}, want {%s %s}", want, d.Class, d.Symbol, class, symbol)
			}
			return
		}
	}
	t.Errorf("expected a %s/%s detection at %s, found none in %+v", class, symbol, want, dets)
}

// mustNotDetectLine asserts no Detection landed on the line containing
// needle in src.
func mustNotDetectLine(t *testing.T, dets []lint.Detection, src lint.Source, needle string) {
	t.Helper()
	line := lineOf(t, src.Content, needle)
	want := fmt.Sprintf("%s:%d", src.Path, line)
	for _, d := range dets {
		if d.Location == want {
			t.Errorf("expected no detection at %s (known false negative), got {%s %s}", want, d.Class, d.Symbol)
		}
	}
}

func TestDetectJSNetworkClass(t *testing.T) {
	src := loadJSFixture(t, "network.ts")
	dets := lint.DetectJS([]lint.Source{src})

	mustDetect(t, dets, src, `fetch(`, "network", "fetch")
	mustDetect(t, dets, src, `require("http")`, "network", "http")
	mustDetect(t, dets, src, `require("https")`, "network", "https")
	mustDetect(t, dets, src, `require("net")`, "network", "net")
	mustDetect(t, dets, src, `from "http"`, "network", "http")
	mustDetect(t, dets, src, `from "https"`, "network", "https")
	mustDetect(t, dets, src, `from "net"`, "network", "net")
	mustDetect(t, dets, src, `axios`, "network", "axios")
	mustDetect(t, dets, src, `undici`, "network", "undici")

	if len(dets) != 9 {
		t.Errorf("len(dets) = %d, want 9 (no detections beyond the network table)", len(dets))
	}
}

func TestDetectJSFilesystemClass(t *testing.T) {
	src := loadJSFixture(t, "filesystem.js")
	dets := lint.DetectJS([]lint.Source{src})

	mustDetect(t, dets, src, `require("fs")`, "filesystem", "fs")
	mustDetect(t, dets, src, `from "fs"`, "filesystem", "fs")
	mustDetect(t, dets, src, `fs/promises`, "filesystem", "fs/promises")

	if len(dets) != 3 {
		t.Errorf("len(dets) = %d, want 3 (no detections beyond the filesystem table)", len(dets))
	}
}

func TestDetectJSExecClass(t *testing.T) {
	src := loadJSFixture(t, "exec.ts")
	dets := lint.DetectJS([]lint.Source{src})

	mustDetect(t, dets, src, `child_process`, "exec", "child_process")
	mustDetect(t, dets, src, `execa`, "exec", "execa")
	mustDetect(t, dets, src, `Bun.spawn`, "exec", "Bun.spawn")

	if len(dets) != 3 {
		t.Errorf("len(dets) = %d, want 3 (no detections beyond the exec table)", len(dets))
	}
}

func TestDetectJSEnvClass(t *testing.T) {
	src := loadJSFixture(t, "env.mjs")
	dets := lint.DetectJS([]lint.Source{src})

	mustDetect(t, dets, src, `process.env.API_KEY`, "env", "process.env")
	mustDetect(t, dets, src, `process.env.NODE_ENV`, "env", "process.env")

	if len(dets) != 2 {
		t.Errorf("len(dets) = %d, want 2 (no detections beyond the env table)", len(dets))
	}
}

// TestKnownFalseNegativeDynamicImport pins the spec 1.3 honesty posture:
// lint is heuristic and advisory, not proof of absence. import(moduleName)
// carries a variable specifier, not a literal quoted module string, so
// DetectJS never follows it. Recording this as a passing test, not just a
// doc comment, is what keeps the false negative honest.
func TestKnownFalseNegativeDynamicImport(t *testing.T) {
	src := loadJSFixture(t, "falsenegatives.ts")
	dets := lint.DetectJS([]lint.Source{src})
	mustNotDetectLine(t, dets, src, `import(moduleName)`)
}

// TestKnownFalseNegativeEval pins the same honesty posture for eval: the
// string handed to eval is never scanned, so a capability reference hidden
// behind runtime evaluation (here, decoded from an opaque variable rather
// than a literal, so no literal require(...) text ever collides with the
// line pattern) is not detected.
func TestKnownFalseNegativeEval(t *testing.T) {
	src := loadJSFixture(t, "falsenegatives.ts")
	dets := lint.DetectJS([]lint.Source{src})
	mustNotDetectLine(t, dets, src, `eval(hexDecoded)`)
}

// TestKnownFalsePositiveCommentedRequire pins the flip side of the honesty
// posture: DetectJS does not parse comments out, so a commented out
// require("http") still matches the same line anchored pattern a live call
// would. This is an accepted, documented limitation (heuristic, advisory),
// not a defect, and is asserted here rather than only described in prose.
func TestKnownFalsePositiveCommentedRequire(t *testing.T) {
	src := loadJSFixture(t, "falsenegatives.ts")
	dets := lint.DetectJS([]lint.Source{src})
	mustDetect(t, dets, src, `// require("http")`, "network", "http")
}

// TestDetectJSOneDetectionPerLinePerClass proves the determinism rule: even
// when two patterns of the same class both match one line, only a single
// Detection is emitted for that line and class.
func TestDetectJSOneDetectionPerLinePerClass(t *testing.T) {
	src := lint.Source{
		Path:    "inline.ts",
		Content: []byte("const x = fetch(\"http://example.com\"); // also mentions axios and undici here\n"),
	}
	dets := lint.DetectJS([]lint.Source{src})
	if len(dets) != 1 {
		t.Fatalf("len(dets) = %d, want 1 (one detection per line per class); got %+v", len(dets), dets)
	}
	if dets[0].Class != "network" || dets[0].Symbol != "fetch" {
		t.Errorf("dets[0] = %+v, want {network fetch inline.ts:1}", dets[0])
	}
}

// TestDetectJSDistinctClassesSameLineEachDetect proves the other half of the
// same rule: distinct classes matching the same line each produce their own
// Detection.
func TestDetectJSDistinctClassesSameLineEachDetect(t *testing.T) {
	src := lint.Source{
		Path:    "inline.ts",
		Content: []byte(`fetch("http://x"); require("fs"); child_process.exec(); process.env.FOO;` + "\n"),
	}
	dets := lint.DetectJS([]lint.Source{src})
	wantClasses := map[string]bool{"network": true, "filesystem": true, "exec": true, "env": true}
	if len(dets) != 4 {
		t.Fatalf("len(dets) = %d, want 4; got %+v", len(dets), dets)
	}
	// Sorted by (Location, Class, Symbol); all four share one Location, so
	// Class must come out alphabetical: env, exec, filesystem, network.
	wantOrder := []string{"env", "exec", "filesystem", "network"}
	for i, want := range wantOrder {
		if dets[i].Class != want {
			t.Errorf("dets[%d].Class = %q, want %q (dets = %+v)", i, dets[i].Class, want, dets)
		}
		delete(wantClasses, dets[i].Class)
	}
	if len(wantClasses) != 0 {
		t.Errorf("missing classes: %v", wantClasses)
	}
}

// TestDetectJSSortsAcrossFiles proves Location ordering holds across
// multiple input files regardless of input slice order.
func TestDetectJSSortsAcrossFiles(t *testing.T) {
	files := []lint.Source{
		{Path: "z.ts", Content: []byte(`fetch("http://x");` + "\n")},
		{Path: "a.ts", Content: []byte(`fetch("http://x");` + "\n")},
	}
	dets := lint.DetectJS(files)
	if len(dets) != 2 {
		t.Fatalf("len(dets) = %d, want 2; got %+v", len(dets), dets)
	}
	if dets[0].Location != "a.ts:1" || dets[1].Location != "z.ts:1" {
		t.Errorf("dets = %+v, want a.ts:1 then z.ts:1", dets)
	}
}

// TestDetectJSSortsByNumericLineNotLexicographic pins a real bug found in
// review: comparing Location as one flat "path:line" string sorts "path:10"
// before "path:7", since "1" is lexicographically less than "7". DetectJS
// must compare the parsed line number as an integer instead, so single and
// double digit lines on the same path come out in true numeric order.
func TestDetectJSSortsByNumericLineNotLexicographic(t *testing.T) {
	lines := make([]string, 10)
	for i := range lines {
		lines[i] = "// filler"
	}
	lines[6] = `fetch("seven");`
	lines[9] = `fetch("ten");`
	src := lint.Source{Path: "inline.ts", Content: []byte(strings.Join(lines, "\n") + "\n")}

	dets := lint.DetectJS([]lint.Source{src})
	if len(dets) != 2 {
		t.Fatalf("len(dets) = %d, want 2; got %+v", len(dets), dets)
	}
	if dets[0].Location != "inline.ts:7" || dets[1].Location != "inline.ts:10" {
		t.Errorf("dets = %+v, want inline.ts:7 then inline.ts:10 (numeric line order, not lexicographic)", dets)
	}
}

// TestDetectJSFetchWordBoundaryRejectsBareIdentifier proves the word
// boundary anchor on the fetch pattern rejects an identifier that merely
// contains "fetch(" as a substring, such as a hypothetical customfetch(
// call, since that is not a real fetch call site.
func TestDetectJSFetchWordBoundaryRejectsBareIdentifier(t *testing.T) {
	src := lint.Source{Path: "inline.ts", Content: []byte("customfetch(1);\n")}
	dets := lint.DetectJS([]lint.Source{src})
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (customfetch( must not trigger the fetch pattern); got %+v", len(dets), dets)
	}
}

// TestDetectJSAxiosWordBoundaryRejectsBareIdentifier proves the word
// boundary anchor on the axios pattern rejects an identifier that merely
// contains "axios" as a substring, such as myaxioswrapper, since that names
// no real axios import or reference.
func TestDetectJSAxiosWordBoundaryRejectsBareIdentifier(t *testing.T) {
	src := lint.Source{Path: "inline.ts", Content: []byte("const myaxioswrapper = 1;\n")}
	dets := lint.DetectJS([]lint.Source{src})
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (myaxioswrapper must not trigger the axios pattern); got %+v", len(dets), dets)
	}
}

// TestDetectJSExtensionMatchIsCaseInsensitive proves an uppercase extension
// such as .TS is still recognized and scanned, not silently skipped.
func TestDetectJSExtensionMatchIsCaseInsensitive(t *testing.T) {
	src := lint.Source{Path: "sample.TS", Content: []byte(`fetch("http://x");` + "\n")}
	dets := lint.DetectJS([]lint.Source{src})
	if len(dets) != 1 {
		t.Errorf("len(dets) = %d, want 1 (an uppercase .TS extension must still be scanned); got %+v", len(dets), dets)
	}
}

// TestDetectJSSkipsNonJSExtensionsSilently proves files outside the JS/TS
// extension set are skipped without error or detection, even when their
// content would otherwise match the table.
func TestDetectJSSkipsNonJSExtensionsSilently(t *testing.T) {
	files := []lint.Source{
		{Path: "notes.py", Content: []byte(`require("http")` + "\n")},
		{Path: "readme.md", Content: []byte(`fetch("http://x")` + "\n")},
		{Path: "data.json", Content: []byte(`{"child_process": true}` + "\n")},
	}
	dets := lint.DetectJS(files)
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (non JS/TS extensions must be skipped silently); got %+v", len(dets), dets)
	}
}

// TestDetectJSScansAllRecognizedExtensions proves every extension task 4.1
// names (.js, .jsx, .ts, .tsx, .mjs, .cjs) is actually scanned.
func TestDetectJSScansAllRecognizedExtensions(t *testing.T) {
	exts := []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
	var files []lint.Source
	for _, ext := range exts {
		files = append(files, lint.Source{
			Path:    "sample" + ext,
			Content: []byte(`fetch("http://x");` + "\n"),
		})
	}
	dets := lint.DetectJS(files)
	if len(dets) != len(exts) {
		t.Fatalf("len(dets) = %d, want %d; got %+v", len(dets), len(exts), dets)
	}
}

// TestDetectJSDeterministic proves the same input produces byte identical
// output across repeated calls.
func TestDetectJSDeterministic(t *testing.T) {
	src := loadJSFixture(t, "network.ts")
	first := lint.DetectJS([]lint.Source{src})
	second := lint.DetectJS([]lint.Source{src})
	if !reflect.DeepEqual(first, second) {
		t.Errorf("DetectJS is not deterministic:\nfirst  = %+v\nsecond = %+v", first, second)
	}
}
