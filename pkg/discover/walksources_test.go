package discover_test

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
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

	sources, _, err := discover.WalkSources(dir)
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

	sources, _, err := discover.WalkSources(dir)
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

	sources, _, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources must not error on a symlink (lint is advisory): %v", err)
	}
	if got, want := sourcePaths(sources), []string{"real.ts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("paths = %v, want %v (the symlink must be skipped silently)", got, want)
	}
}

// TestWalkSourcesResolvesSymlinkedRoot proves that when the root itself is a
// symlink to a directory, WalkSources resolves it and lints the real contents,
// yielding the same sources as walking the real path (M1). This is the one
// place a symlink is followed: only symlinks ENCOUNTERED DURING descent are
// skipped silently. A symlinked install (a common shape for a globally linked
// package) must not silently lint nothing.
func TestWalkSourcesResolvesSymlinkedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is unreliable on Windows CI without elevation")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	writeSourceFile(t, real, "src/index.ts", "fetch('x')")
	writeSourceFile(t, real, "lib/util.py", "import os")

	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("creating symlinked root: %v", err)
	}

	realSources, _, err := discover.WalkSources(real)
	if err != nil {
		t.Fatalf("WalkSources(real): %v", err)
	}
	linkSources, _, err := discover.WalkSources(link)
	if err != nil {
		t.Fatalf("WalkSources(symlinked root): %v", err)
	}
	if got, want := sourcePaths(linkSources), sourcePaths(realSources); !reflect.DeepEqual(got, want) {
		t.Errorf("symlinked root sources = %v, want the same as the real path %v", got, want)
	}
	if len(sourcePaths(linkSources)) == 0 {
		t.Error("symlinked root yielded no sources; the root symlink was not resolved")
	}
}

// TestWalkSourcesMatchesDetectorExtensions proves WalkSources collects exactly
// the extension set the detectors scan (lint.SourceExtensions), in both
// directions: a file for every recognized extension is collected, and every
// collected file's extension is one the detectors recognize. Deriving the
// walker's set from the detectors' own tables (M12) is what this pins, so a new
// detector extension cannot be recognized by a detector yet forgotten here.
func TestWalkSourcesMatchesDetectorExtensions(t *testing.T) {
	dir := t.TempDir()
	recognized := lint.SourceExtensions()
	if len(recognized) == 0 {
		t.Fatal("lint.SourceExtensions returned no extensions")
	}
	want := make([]string, 0, len(recognized))
	for i, ext := range recognized {
		// A distinct basename per extension so the collected set is exactly one
		// file per recognized extension, independent of case.
		name := fmt.Sprintf("src%d%s", i, ext)
		writeSourceFile(t, dir, name, "content of "+name)
		want = append(want, name)
	}
	// An unrecognized extension must never be collected.
	writeSourceFile(t, dir, "ignore.txt", "not a source")
	sort.Strings(want)

	sources, _, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources: %v", err)
	}
	if got := sourcePaths(sources); !reflect.DeepEqual(got, want) {
		t.Errorf("collected = %v, want %v (walker set must equal the detectors' set)", got, want)
	}
}

// TestWalkSourcesUnreadableFileNotedNotFatal proves the M5 advisory posture: an
// unreadable file inside the tree is skipped with a note naming it, never a
// fatal error, so the readable sources still come back and a partial scan still
// stands. Only a failure at the root is fatal.
func TestWalkSourcesUnreadableFileNotedNotFatal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod based unreadability is not reliable on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses file permission bits, so an unreadable file cannot be simulated")
	}
	dir := t.TempDir()
	writeSourceFile(t, dir, "readable.ts", "fetch('x')")
	writeSourceFile(t, dir, "secret.ts", "fetch('y')")
	if err := os.Chmod(filepath.Join(dir, "secret.ts"), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "secret.ts"), 0o600) })

	sources, notes, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources must not fail on one unreadable file (M5): %v", err)
	}
	if got, want := sourcePaths(sources), []string{"readable.ts"}; !reflect.DeepEqual(got, want) {
		t.Errorf("sources = %v, want %v (the readable file survives, the unreadable one is skipped)", got, want)
	}
	joined := strings.Join(notes, "\n")
	if !strings.Contains(joined, "secret.ts") {
		t.Errorf("notes = %v, want one naming the skipped secret.ts", notes)
	}
}

// TestWalkSourcesEmptyTreeIsNotAnError proves a tree with no recognized source
// files walks cleanly and returns an empty result, not an error.
func TestWalkSourcesEmptyTreeIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	writeSourceFile(t, dir, "README.md", "docs only")
	sources, _, err := discover.WalkSources(dir)
	if err != nil {
		t.Fatalf("WalkSources: %v", err)
	}
	if len(sources) != 0 {
		t.Errorf("sources = %v, want none", sources)
	}
}
