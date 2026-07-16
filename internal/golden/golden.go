// Package golden implements golden file assertions with a -update flag
// (spec 9: golden file snapshots with -update).
package golden

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files with observed output")

// Assert compares got against the golden file at path, rewriting it when
// tests run with -update.
func Assert(t *testing.T, got []byte, path string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file %s (run with -update to create): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n got: %s\nwant: %s", path, got, want)
	}
}
