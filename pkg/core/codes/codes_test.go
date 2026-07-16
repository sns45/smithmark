package codes

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEveryCodeIsDocumented(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	doc, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "..", "docs", "codes.md"))
	if err != nil {
		t.Fatalf("reading docs/codes.md: %v", err)
	}
	for _, c := range All() {
		if !strings.Contains(string(doc), "`"+c+"`") {
			t.Errorf("code %s is not documented in docs/codes.md", c)
		}
	}
	if len(All()) == 0 {
		t.Fatal("code registry is empty")
	}
}

func TestCodesAreUniqueAndShaped(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c] {
			t.Errorf("duplicate code %s", c)
		}
		seen[c] = true
		for _, r := range c {
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				t.Errorf("code %s is not SCREAMING_SNAKE", c)
			}
		}
	}
}
