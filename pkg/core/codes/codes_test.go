package codes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func readCodesDoc(t *testing.T) string {
	t.Helper()
	_, self, _, _ := runtime.Caller(0)
	doc, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "..", "docs", "codes.md"))
	if err != nil {
		t.Fatalf("reading docs/codes.md: %v", err)
	}
	return string(doc)
}

func TestEveryCodeIsDocumented(t *testing.T) {
	doc := readCodesDoc(t)
	for _, c := range All() {
		if !strings.Contains(doc, "`"+c+"`") {
			t.Errorf("code %s is not documented in docs/codes.md", c)
		}
	}
	if len(All()) == 0 {
		t.Fatal("code registry is empty")
	}
}

// TestEveryDocumentedCodeExists is the reverse direction of the sync test: a
// table row in docs/codes.md whose constant was deleted from the registry
// must fail, so the doc can never drift ahead of the code.
func TestEveryDocumentedCodeExists(t *testing.T) {
	doc := readCodesDoc(t)
	registered := map[string]bool{}
	for _, c := range All() {
		registered[c] = true
	}
	token := regexp.MustCompile("`([A-Z][A-Z0-9_]*)`")
	found := 0
	for _, line := range strings.Split(doc, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		for _, m := range token.FindAllStringSubmatch(line, -1) {
			found++
			if !registered[m[1]] {
				t.Errorf("docs/codes.md documents %s but it is not in the registry", m[1])
			}
		}
	}
	if found == 0 {
		t.Fatal("no documented codes found in docs/codes.md table rows")
	}
}

// screamingSnake rejects leading, trailing, or doubled underscores in
// addition to constraining the character set.
var screamingSnake = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)

// TestErrorAsExtractsCode proves a coded error survives wrapping: errors.As
// pulls the *Error back out of a wrapped chain, and its Code is intact. This
// is the machine readable path callers use instead of substring matching.
func TestErrorAsExtractsCode(t *testing.T) {
	inner := E(ManifestSchemaVersionUnsupported, "at %s", "schemaVersion")
	if got, want := inner.Error(), "MANIFEST_SCHEMA_VERSION_UNSUPPORTED: at schemaVersion"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	wrapped := fmt.Errorf("outer context: %w", inner)
	var e *Error
	if !errors.As(wrapped, &e) {
		t.Fatalf("errors.As did not find *Error in %v", wrapped)
	}
	if e.Code != ManifestSchemaVersionUnsupported {
		t.Errorf("extracted code = %q, want %q", e.Code, ManifestSchemaVersionUnsupported)
	}
}

func TestCodesAreUniqueAndShaped(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c] {
			t.Errorf("duplicate code %s", c)
		}
		seen[c] = true
		if !screamingSnake.MatchString(c) {
			t.Errorf("code %s is not SCREAMING_SNAKE", c)
		}
	}
}
