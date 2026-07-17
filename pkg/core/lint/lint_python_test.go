package lint_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/lint"
)

// pyFixtureDir is the committed Python fixture corpus for task 4.2, relative
// to this test package.
const pyFixtureDir = "../../../testdata/lint/py"

// loadPyFixture reads one committed fixture file and returns it as a
// lint.Source. Test file I/O is fine here; DetectPython itself never touches
// the filesystem, since sources arrive pre read (the pkg/core purity guard).
func loadPyFixture(t *testing.T, name string) lint.Source {
	t.Helper()
	path := filepath.Join(pyFixtureDir, name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	return lint.Source{Path: path, Content: content}
}

func TestDetectPythonNetworkClass(t *testing.T) {
	src := loadPyFixture(t, "network.py")
	dets := lint.DetectPython([]lint.Source{src})

	mustDetect(t, dets, src, `import requests`, "network", "requests")
	mustDetect(t, dets, src, `from requests import get`, "network", "requests")
	mustDetect(t, dets, src, `import httpx`, "network", "httpx")
	mustDetect(t, dets, src, `from httpx import Client`, "network", "httpx")
	mustDetect(t, dets, src, `import urllib`, "network", "urllib")
	mustDetect(t, dets, src, `from urllib import request`, "network", "urllib")
	mustDetect(t, dets, src, `import socket`, "network", "socket")
	mustDetect(t, dets, src, `from socket import socket as raw_socket`, "network", "socket")
	mustDetect(t, dets, src, `import aiohttp`, "network", "aiohttp")
	mustDetect(t, dets, src, `from aiohttp import ClientSession`, "network", "aiohttp")

	if len(dets) != 10 {
		t.Errorf("len(dets) = %d, want 10 (no detections beyond the network table)", len(dets))
	}
}

func TestDetectPythonFilesystemClass(t *testing.T) {
	src := loadPyFixture(t, "filesystem.py")
	dets := lint.DetectPython([]lint.Source{src})

	mustDetect(t, dets, src, `import pathlib`, "filesystem", "pathlib")
	mustDetect(t, dets, src, `from pathlib import Path`, "filesystem", "pathlib")
	mustDetect(t, dets, src, `import shutil`, "filesystem", "shutil")
	mustDetect(t, dets, src, `from shutil import copyfile`, "filesystem", "shutil")
	mustDetect(t, dets, src, `open("data.txt")`, "filesystem", "open")

	if len(dets) != 5 {
		t.Errorf("len(dets) = %d, want 5 (no detections beyond the filesystem table)", len(dets))
	}
}

func TestDetectPythonExecClass(t *testing.T) {
	src := loadPyFixture(t, "exec.py")
	dets := lint.DetectPython([]lint.Source{src})

	mustDetect(t, dets, src, `import subprocess`, "exec", "subprocess")
	mustDetect(t, dets, src, `from subprocess import run`, "exec", "subprocess")
	mustDetect(t, dets, src, `os.system("ls -la")`, "exec", "os.system")
	mustDetect(t, dets, src, `os.execvpe(`, "exec", "os.exec")
	mustDetect(t, dets, src, `os.popen("ls -la")`, "exec", "os.popen")

	if len(dets) != 5 {
		t.Errorf("len(dets) = %d, want 5 (no detections beyond the exec table)", len(dets))
	}
}

// TestDetectPythonOsExecFamily pins that the os.exec bare prefix pattern
// matches the whole family (M13, from the 4.2 minor), not just the one
// os.execvpe spelling the exec.py fixture happens to carry: every one of the
// seven exec* spellings reports an exec detection with the static os.exec
// Symbol.
func TestDetectPythonOsExecFamily(t *testing.T) {
	spellings := []string{
		"os.execv", "os.execve", "os.execl", "os.execlp",
		"os.execlpe", "os.execvp", "os.execvpe",
	}
	for _, spelling := range spellings {
		t.Run(spelling, func(t *testing.T) {
			src := lint.Source{Path: "e.py", Content: []byte(spelling + "(path, args)\n")}
			dets := lint.DetectPython([]lint.Source{src})
			found := false
			for _, d := range dets {
				if d.Class == "exec" && d.Symbol == "os.exec" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s did not report an exec/os.exec detection; dets = %+v", spelling, dets)
			}
		})
	}
}

// TestDetectPythonEnvClass pins the name aware env Symbol shape task 4.3
// adds, mirroring DetectJS: os.environ["FOO"], os.environ.get("FOO"), and
// os.getenv("FOO") all report Symbol "env:FOO", the same language neutral
// shape process.env.FOO reports, so Gaps can key off it without caring
// which language produced the Detection. A bare os.environ access
// DetectPython cannot resolve to a literal name still reports a Detection,
// just with the pre task 4.3 Symbol left bare.
func TestDetectPythonEnvClass(t *testing.T) {
	src := loadPyFixture(t, "env.py")
	dets := lint.DetectPython([]lint.Source{src})

	mustDetect(t, dets, src, `os.environ["API_KEY"]`, "env", "env:API_KEY")
	mustDetect(t, dets, src, `os.getenv("DEBUG")`, "env", "env:DEBUG")
	mustDetect(t, dets, src, `os.environ.get("TIMEOUT")`, "env", "env:TIMEOUT")
	mustDetect(t, dets, src, `whole_env = os.environ`, "env", "os.environ")

	if len(dets) != 4 {
		t.Errorf("len(dets) = %d, want 4 (no detections beyond the env table)", len(dets))
	}
}

// TestKnownFalseNegativeDynamicImportModule pins the spec 1.3 honesty
// posture for Python: importlib.import_module(CAPABILITY_MODULE) carries a
// variable specifier, not a literal "import subprocess" or "from subprocess"
// statement, so DetectPython never follows it, even though the line's text
// contains the substring "import" twice over (once in "importlib", once in
// "import_module") and the module name "subprocess" appears elsewhere in the
// fixture as a plain string literal. Neither collision fires a detection,
// since every DetectPython import pattern requires "import" or "from" to be
// followed by at least one space and then the module name.
func TestKnownFalseNegativeDynamicImportModule(t *testing.T) {
	src := loadPyFixture(t, "falsenegatives.py")
	dets := lint.DetectPython([]lint.Source{src})
	mustNotDetectLine(t, dets, src, `importlib.import_module(CAPABILITY_MODULE)`)
}

// TestKnownFalseNegativeEvalPython pins the same honesty posture for eval:
// the string handed to eval is never scanned, so a capability reference
// hidden behind runtime evaluation (here, an opaque encoded variable rather
// than a literal, so no literal import or os.* text ever collides with a
// line pattern) is not detected.
func TestKnownFalseNegativeEvalPython(t *testing.T) {
	src := loadPyFixture(t, "falsenegatives.py")
	dets := lint.DetectPython([]lint.Source{src})
	mustNotDetectLine(t, dets, src, `eval(encoded)`)
}

// TestKnownFalsePositiveCommentedImport pins the flip side of the honesty
// posture, and the deliberate choice to keep it consistent with DetectJS:
// DetectPython does not parse comments out, so a commented out
// "import requests" sitting alone at line start still matches the same line
// anchored pattern a live import would. This is an accepted, documented
// limitation (heuristic, advisory), not a defect, and is asserted here
// rather than only described in prose, mirroring
// TestKnownFalsePositiveCommentedRequire for DetectJS.
func TestKnownFalsePositiveCommentedImport(t *testing.T) {
	src := loadPyFixture(t, "falsenegatives.py")
	dets := lint.DetectPython([]lint.Source{src})
	mustDetect(t, dets, src, `# import requests`, "network", "requests")
}

// TestDetectPythonMidSentenceCommentDoesNotFire proves the other half of the
// anchor's posture: a comment that merely mentions a module name mid
// sentence, rather than opening with "import" or "from" right after the
// optional "#", never fires, even though the word "import" appears in the
// line.
func TestDetectPythonMidSentenceCommentDoesNotFire(t *testing.T) {
	src := loadPyFixture(t, "falsenegatives.py")
	dets := lint.DetectPython([]lint.Source{src})
	mustNotDetectLine(t, dets, src, `known false negatives live here`)
}

// TestDetectPythonOpenWordBoundaryRejectsBareIdentifier proves the word
// boundary anchor on the open( pattern rejects an identifier that merely
// contains "open(" as a substring, such as a hypothetical reopen( call,
// since that is not a real open() call site.
func TestDetectPythonOpenWordBoundaryRejectsBareIdentifier(t *testing.T) {
	src := lint.Source{Path: "inline.py", Content: []byte("reopen(1)\n")}
	dets := lint.DetectPython([]lint.Source{src})
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (reopen( must not trigger the open( pattern); got %+v", len(dets), dets)
	}
}

// TestDetectPythonUrllibWordBoundaryRejectsBareIdentifier proves the word
// boundary anchor on the urllib import pattern rejects a module name that
// merely shares the "urllib" prefix, such as urllib3, since that is a
// distinct package this table entry does not claim to cover.
func TestDetectPythonUrllibWordBoundaryRejectsBareIdentifier(t *testing.T) {
	src := lint.Source{Path: "inline.py", Content: []byte("import urllib3\n")}
	dets := lint.DetectPython([]lint.Source{src})
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (import urllib3 must not trigger the urllib pattern); got %+v", len(dets), dets)
	}
}

// TestDetectPythonIndentedImportStillFires proves the anchor's leading
// whitespace allowance: a real import nested inside a function or try block
// carries indentation before "import", and must still be detected.
func TestDetectPythonIndentedImportStillFires(t *testing.T) {
	src := lint.Source{
		Path:    "inline.py",
		Content: []byte("def lazy():\n    import requests\n    return requests\n"),
	}
	dets := lint.DetectPython([]lint.Source{src})
	mustDetect(t, dets, src, `import requests`, "network", "requests")
}

// TestDetectPythonExtensionMatchIsCaseInsensitive proves an uppercase
// extension such as .PY is still recognized and scanned, not silently
// skipped.
func TestDetectPythonExtensionMatchIsCaseInsensitive(t *testing.T) {
	src := lint.Source{Path: "sample.PY", Content: []byte("import requests\n")}
	dets := lint.DetectPython([]lint.Source{src})
	if len(dets) != 1 {
		t.Errorf("len(dets) = %d, want 1 (an uppercase .PY extension must still be scanned); got %+v", len(dets), dets)
	}
}

// TestDetectPythonSkipsNonPyExtensionsSilently proves files outside the .py
// extension are skipped without error or detection, even when their content
// would otherwise match the table.
func TestDetectPythonSkipsNonPyExtensionsSilently(t *testing.T) {
	files := []lint.Source{
		{Path: "notes.js", Content: []byte("import requests\n")},
		{Path: "readme.md", Content: []byte("os.system(\"ls\")\n")},
	}
	dets := lint.DetectPython(files)
	if len(dets) != 0 {
		t.Errorf("len(dets) = %d, want 0 (non .py extensions must be skipped silently); got %+v", len(dets), dets)
	}
}

// TestDetectPythonOneDetectionPerLinePerClass proves the determinism rule
// carries over from DetectJS: even when two patterns of the same class both
// match one line, only a single Detection is emitted for that line and
// class.
func TestDetectPythonOneDetectionPerLinePerClass(t *testing.T) {
	src := lint.Source{
		Path:    "inline.py",
		Content: []byte("import requests  # also mentions httpx and aiohttp here\n"),
	}
	dets := lint.DetectPython([]lint.Source{src})
	if len(dets) != 1 {
		t.Fatalf("len(dets) = %d, want 1 (one detection per line per class); got %+v", len(dets), dets)
	}
	if dets[0].Class != "network" || dets[0].Symbol != "requests" {
		t.Errorf("dets[0] = %+v, want {network requests inline.py:1}", dets[0])
	}
}

// TestDetectPythonDistinctClassesSameLineEachDetect proves the other half of
// the same rule: distinct classes matching the same line each produce their
// own Detection.
func TestDetectPythonDistinctClassesSameLineEachDetect(t *testing.T) {
	src := lint.Source{
		Path:    "inline.py",
		Content: []byte(`import requests; open("f"); os.system(x); os.getenv("X")` + "\n"),
	}
	dets := lint.DetectPython([]lint.Source{src})
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

// TestDetectPythonSortsByNumericLineNotLexicographic pins the same numeric
// sort guarantee DetectJS carries: single and double digit lines on the same
// path come out in true numeric order, not lexicographic string order.
func TestDetectPythonSortsByNumericLineNotLexicographic(t *testing.T) {
	lines := make([]string, 10)
	for i := range lines {
		lines[i] = "# filler"
	}
	lines[6] = `import requests`
	lines[9] = `import httpx`
	src := lint.Source{Path: "inline.py", Content: []byte(strings.Join(lines, "\n") + "\n")}

	dets := lint.DetectPython([]lint.Source{src})
	if len(dets) != 2 {
		t.Fatalf("len(dets) = %d, want 2; got %+v", len(dets), dets)
	}
	if dets[0].Location != "inline.py:7" || dets[1].Location != "inline.py:10" {
		t.Errorf("dets = %+v, want inline.py:7 then inline.py:10 (numeric line order, not lexicographic)", dets)
	}
}

// TestDetectPythonDeterministic proves the same input produces byte
// identical output across repeated calls.
func TestDetectPythonDeterministic(t *testing.T) {
	src := loadPyFixture(t, "network.py")
	first := lint.DetectPython([]lint.Source{src})
	second := lint.DetectPython([]lint.Source{src})
	if !reflect.DeepEqual(first, second) {
		t.Errorf("DetectPython is not deterministic:\nfirst  = %+v\nsecond = %+v", first, second)
	}
}
