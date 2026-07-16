package compose

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// cannedBOM is a minimal, fixed CycloneDX 1.5 JSON document: exactly what the
// fake forgeseal binary below writes to its --output path in the happy path
// scenarios. Its bytes never change, which is what lets
// pinnedHappyPathDigest stay a frozen constant rather than something
// recomputed on every run (mirroring pkg/core/bundle's pinned vector rule).
const cannedBOM = `{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":[{"type":"library","name":"example-dep","version":"1.2.3","purl":"pkg:generic/example-dep@1.2.3"}]}`

// pinnedHappyPathDigest is sha256(cannedBOM), computed once and then frozen:
// recompute only if the digest algorithm itself is believed wrong, never to
// make a failing test pass.
const pinnedHappyPathDigest = "1c5058ef04d8ec5c4a798c9d7919a315b0ebb6c4624589c0c67d2056dd720069"

// malformedBOM is deliberately not valid JSON at all, so cyclonedx-go's
// strict decode fails outright: this is the "malformed BOM output rejected"
// scenario (controller resolution point 5, Task 2.4), proving Generate never
// silently passes bad output through to a digest.
const malformedBOM = `this is not json at all`

// emptyBOM is syntactically valid JSON that decodes into cdx.BOM with no
// error while carrying neither a bomFormat marker nor a specVersion. Before
// the structural check landed, Generate accepted this and produced the
// nonsense SBOMFormat "application/vnd.cyclonedx+json;version=SpecVersion(0)",
// which a signed manifest would then have carried forever.
const emptyBOM = `{}`

// installFakeForgeseal writes a fake forgeseal executable into a fresh
// t.TempDir() and prepends that directory to PATH via t.Setenv, so
// exec.LookPath("forgeseal") finds it for the duration of the test (Task
// 2.4 controller resolution point 5). The fake understands exactly the two
// subcommands this package's Generate ever issues, in the exact fixed
// argument order Generate always uses ("sbom --dir <dir> --output <file>"),
// so it can locate the output path positionally rather than parsing flags
// generically:
//   - "version" prints the contents of a sibling version-output.txt file,
//     which the real forgeseal CLI documents as "forgeseal <version>" on its
//     first line followed by further indented lines (commit, built).
//   - "sbom" copies a sibling bom-source.json file to the --output path
//     verbatim, byte for byte, so the digest Generate computes over the
//     read back bytes matches whatever bomBody the test supplied exactly.
//
// A unix shell script is written on every platform except Windows; a
// Windows .bat is written when runtime.GOOS is "windows", since a shell
// script is not directly executable there.
func installFakeForgeseal(t *testing.T, versionOutput, bomBody string) {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "version-output.txt"), []byte(versionOutput), 0o644); err != nil {
		t.Fatalf("writing fake version output: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bom-source.json"), []byte(bomBody), 0o644); err != nil {
		t.Fatalf("writing fake bom source: %v", err)
	}

	var scriptPath, script string
	if runtime.GOOS == "windows" {
		scriptPath = filepath.Join(dir, "forgeseal.bat")
		script = "@echo off\r\n" +
			"if \"%~1\"==\"version\" (\r\n" +
			"  type \"%~dp0version-output.txt\"\r\n" +
			"  exit /b 0\r\n" +
			")\r\n" +
			"if \"%~1\"==\"sbom\" (\r\n" +
			"  copy /y \"%~dp0bom-source.json\" \"%~5\" >nul\r\n" +
			"  exit /b 0\r\n" +
			")\r\n" +
			"exit /b 1\r\n"
	} else {
		scriptPath = filepath.Join(dir, "forgeseal")
		script = "#!/bin/sh\n" +
			"dir=$(dirname \"$0\")\n" +
			"if [ \"$1\" = \"version\" ]; then\n" +
			"  cat \"$dir/version-output.txt\"\n" +
			"  exit 0\n" +
			"fi\n" +
			"if [ \"$1\" = \"sbom\" ]; then\n" +
			"  cp \"$dir/bom-source.json\" \"$5\"\n" +
			"  exit 0\n" +
			"fi\n" +
			"exit 1\n"
	}
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake forgeseal script: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestGenerateHappyPath(t *testing.T) {
	installFakeForgeseal(t, "forgeseal v0.3.0\n  commit: abc1234\n  built: 2024-01-01T00:00:00Z\n", cannedBOM)

	result, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if string(result.BOM) != cannedBOM {
		t.Errorf("BOM = %q, want %q", result.BOM, cannedBOM)
	}
	if got := result.Ref.SBOMDigest["sha256"]; got != pinnedHappyPathDigest {
		t.Errorf("SBOMDigest[sha256] = %s, want %s", got, pinnedHappyPathDigest)
	}
	if want := "application/vnd.cyclonedx+json;version=1.5"; result.Ref.SBOMFormat != want {
		t.Errorf("SBOMFormat = %s, want %s", result.Ref.SBOMFormat, want)
	}
	if result.Ref.Locator != "" {
		t.Errorf("Locator = %q, want empty (assigned later by push)", result.Ref.Locator)
	}
}

func TestGenerateAcceptsDevVersion(t *testing.T) {
	installFakeForgeseal(t, "forgeseal dev\n  commit: abc1234\n  built: 2024-01-01T00:00:00Z\n", cannedBOM)

	result, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Generate with dev version: %v", err)
	}
	if got := result.Ref.SBOMDigest["sha256"]; got != pinnedHappyPathDigest {
		t.Errorf("SBOMDigest[sha256] = %s, want %s", got, pinnedHappyPathDigest)
	}
}

func TestGenerateRejectsOldVersion(t *testing.T) {
	installFakeForgeseal(t, "forgeseal v0.0.1\n  commit: abc1234\n  built: 2024-01-01T00:00:00Z\n", cannedBOM)

	_, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	assertCode(t, err, codes.SBOMForgesealVersionUnsupported)
}

func TestGenerateRejectsUnparseableVersion(t *testing.T) {
	installFakeForgeseal(t, "forgeseal notaversion\n", cannedBOM)

	_, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	assertCode(t, err, codes.SBOMForgesealVersionUnsupported)
	if !strings.Contains(err.Error(), "notaversion") {
		t.Errorf("err = %v, want the raw unparseable version string in the detail", err)
	}
}

func TestGenerateRejectsMalformedBOM(t *testing.T) {
	installFakeForgeseal(t, "forgeseal v0.3.0\n  commit: abc1234\n  built: 2024-01-01T00:00:00Z\n", malformedBOM)

	_, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	assertCode(t, err, codes.SBOMForgesealOutputInvalid)
}

// TestGenerateRejectsEmptyBOMDocument proves a syntactically valid but
// semantically empty document never reaches the digest step: {} decodes with
// no error, so only the post decode structural check can catch it. The happy
// path counterpart, a valid BOM whose specVersion is present pinning the
// exact SBOMFormat string, is TestGenerateHappyPath above.
func TestGenerateRejectsEmptyBOMDocument(t *testing.T) {
	installFakeForgeseal(t, "forgeseal v0.3.0\n  commit: abc1234\n  built: 2024-01-01T00:00:00Z\n", emptyBOM)

	_, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	assertCode(t, err, codes.SBOMForgesealOutputInvalid)
	if !strings.Contains(err.Error(), "bomFormat") {
		t.Errorf("err = %v, want a detail naming the missing bomFormat field", err)
	}
}

func TestGenerateMissingBinary(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := NewForgesealCLI().Generate(context.Background(), t.TempDir())
	assertCode(t, err, codes.SBOMForgesealMissing)
}

func TestParseSemver(t *testing.T) {
	tests := []struct {
		in                              string
		wantMajor, wantMinor, wantPatch int
		wantOK                          bool
	}{
		{"v1.2.3", 1, 2, 3, true},
		{"0.1.0", 0, 1, 0, true},
		{"v0.1.0", 0, 1, 0, true},
		{"v0.10.0", 0, 10, 0, true}, // two digit field parses as the number ten
		{"1.2", 0, 0, 0, false},
		{"1.2.3.4", 0, 0, 0, false},
		{"1.2.x", 0, 0, 0, false},
		{"1.2.3-rc1", 0, 0, 0, false}, // no prerelease support, by design
		{"dev", 0, 0, 0, false},
		{"", 0, 0, 0, false},
	}
	for _, tt := range tests {
		major, minor, patch, ok := parseSemver(tt.in)
		if ok != tt.wantOK {
			t.Errorf("parseSemver(%q) ok = %v, want %v", tt.in, ok, tt.wantOK)
			continue
		}
		if !ok {
			continue
		}
		if major != tt.wantMajor || minor != tt.wantMinor || patch != tt.wantPatch {
			t.Errorf("parseSemver(%q) = %d.%d.%d, want %d.%d.%d",
				tt.in, major, minor, patch, tt.wantMajor, tt.wantMinor, tt.wantPatch)
		}
	}
}

func TestCheckForgesealVersion(t *testing.T) {
	tests := []struct {
		in       string
		wantCode string // empty means no error
	}{
		{"dev", ""},
		{"v0.1.0", ""}, // exactly the minimum: accepted
		{"0.1.0", ""},  // no v prefix also accepted
		{"v1.0.0", ""},
		{"v0.10.0", ""}, // two digit minor: numeric comparison accepts it
		{"v0.0.9", codes.SBOMForgesealVersionUnsupported},
		{"v0.1.0-beta", codes.SBOMForgesealVersionUnsupported},
		{"garbage", codes.SBOMForgesealVersionUnsupported},
	}
	for _, tt := range tests {
		err := checkForgesealVersion(tt.in)
		if tt.wantCode == "" {
			if err != nil {
				t.Errorf("checkForgesealVersion(%q) = %v, want nil", tt.in, err)
			}
			continue
		}
		assertCode(t, err, tt.wantCode)
	}
}

// TestSemverLess pins the two digit boundary the version gate must get
// right: 0.9.0 sorts before 0.10.0 numerically, while a lexicographic
// string comparison would wrongly order "0.10.0" before "0.9.0".
func TestSemverLess(t *testing.T) {
	if !semverLess(0, 9, 0, 0, 10, 0) {
		t.Error("semverLess(0.9.0, 0.10.0) = false, want true (numeric, not lexicographic)")
	}
	if semverLess(0, 10, 0, 0, 9, 0) {
		t.Error("semverLess(0.10.0, 0.9.0) = true, want false (numeric, not lexicographic)")
	}
	if semverLess(0, 1, 0, 0, 1, 0) {
		t.Error("semverLess(0.1.0, 0.1.0) = true, want false (equal is not less)")
	}
}

func TestFirstLineSecondField(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"forgeseal v0.3.0\n  commit: abc\n  built: today\n", "v0.3.0"},
		{"forgeseal dev", "dev"},
		{"forgeseal", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstLineSecondField([]byte(tt.in)); got != tt.want {
			t.Errorf("firstLineSecondField(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
