package discover_test

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"

	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/discover"
)

// writeSourceFile writes content to name (which may include subdirectories)
// under dir, creating parents as needed.
func writeSourceFile(t *testing.T, dir, name, content string) {
	t.Helper()
	full := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// sourcePaths returns the relative forward slash paths of the walked sources,
// sorted, so a test asserts the set independent of walk order.
func sourcePaths(sources []lint.Source) []string {
	paths := make([]string, len(sources))
	for i, s := range sources {
		paths[i] = s.Path
	}
	sort.Strings(paths)
	return paths
}

// TestWalkSourcesCollectsRecognizedExtensions proves WalkSources collects every
// lint recognized extension (case insensitive), returns relative forward slash
// paths, and reads content, while skipping files with unrecognized extensions.
func TestWalkSourcesCollectsRecognizedExtensions(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"a.js", "b.jsx", "c.ts", "d.tsx", "e.mjs", "f.cjs", "g.py",
		"nested/deep/h.TS", // case insensitive, nested
		"ignore.txt", "SKILL.md", "smithmark.yaml", "data.json",
	} {
		writeSourceFile(t, dir, name, "content of "+name)
	}

	sources, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources: %v", err)
	}
	want := []string{"a.js", "b.jsx", "c.ts", "d.tsx", "e.mjs", "f.cjs", "g.py", "nested/deep/h.TS"}
	if got := sourcePaths(sources); !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v", got, want)
	}
	for _, s := range sources {
		if len(s.Content) == 0 {
			t.Errorf("source %s has no content", s.Path)
		}
	}
}

// TestWalkSourcesSkipsExcludedDirs proves node_modules, dist, .git, and any
// dot directory are skipped at every depth, so vendored or build output code
// is never scanned.
func TestWalkSourcesSkipsExcludedDirs(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "keep.ts", "keep")
	writeSourceFile(t, dir, "node_modules/dep/index.js", "vendored")
	writeSourceFile(t, dir, "dist/bundle.js", "built")
	writeSourceFile(t, dir, ".git/hooks/pre-commit.js", "hook")
	writeSourceFile(t, dir, ".cache/tmp.ts", "dot dir")
	writeSourceFile(t, dir, "src/nested/node_modules/x.ts", "nested vendored")

	sources, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources: %v", err)
	}
	if got, want := sourcePaths(sources), []string{"keep.ts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v (excluded dirs must be skipped at every depth)", got, want)
	}
}

// TestWalkSourcesSkipsSymlinksSilently proves a symlink is skipped without an
// error, the advisory posture that contrasts with the bundle walker (WalkSkill)
// rejecting symlinks outright.
func TestWalkSourcesSkipsSymlinksSilently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is unreliable on Windows CI without elevation")
	}
	dir := t.TempDir()
	writeSourceFile(t, dir, "real.ts", "real")
	target := filepath.Join(dir, "real.ts")
	link := filepath.Join(dir, "link.ts")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("creating symlink: %v", err)
	}

	sources, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources must not error on a symlink (lint is advisory): %v", err)
	}
	if got, want := sourcePaths(sources), []string{"real.ts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v (the symlink must be skipped silently)", got, want)
	}
}

// TestWalkSourcesEmptyTreeIsNotAnError proves a tree with no recognized source
// files walks cleanly and returns an empty result, not an error.
func TestWalkSourcesEmptyTreeIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "README.md", "docs only")
	sources, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %v, want none", sources)
	}
}
