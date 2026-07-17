package discover

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sns45/smithmark/pkg/core/lint"
)

// lintSourceExtensions are the file extensions the capability lint scans,
// matched case insensitively. It is derived from pkg/core/lint's own
// SourceExtensions rather than restated here, so the extensions DetectJS and
// DetectPython gate on are the single source of truth: the detectors silently
// skip any Source whose path does not end in one of these, so collecting
// exactly this set here avoids reading files the detectors would only discard.
// Deriving it from the detectors' own tables means a new detector extension
// cannot be recognized by a detector yet forgotten by the walker
// (TestWalkSourcesMatchesDetectorExtensions pins the agreement).
var lintSourceExtensions = lint.SourceExtensions()

// skippedSourceDirs are directory names WalkSources never descends into, at any
// depth: vendored dependencies and build output that would flood a scan with
// third party code the maker did not write, and the VCS metadata directory. Any
// directory whose name begins with a dot is also skipped (see WalkSources), so
// .git is both named here for clarity and covered by that rule.
var skippedSourceDirs = map[string]bool{
	"node_modules": true,
	"dist":         true,
	".git":         true,
}

// WalkSources collects every lint scannable source file under root as a
// pre read lint.Source, so the pure detectors (DetectJS, DetectPython) can run
// over the bytes without themselves touching the filesystem (the pkg/core
// purity guard). A file is collected when its extension is one of
// lintSourceExtensions, matched case insensitively; every returned Source
// carries a root relative, forward slash Path (the file half of a Finding's
// Location) and the file's raw Content. The result is sorted by Path so a scan
// of identical bytes is deterministic.
//
// Directories named node_modules, dist, or .git, and any directory whose name
// begins with a dot, are skipped entirely at every depth, so vendored code,
// build output, and VCS metadata never enter a scan.
//
// Symlinks encountered DURING descent are skipped silently, and WalkSources
// never follows one. This is a deliberate contrast with the skill bundle walker
// (WalkSkill), which rejects a symlink outright with BUNDLE_SYMLINK_REJECTED: a
// bundle digest must be an exact, unambiguous account of what will be installed,
// so a symlink there is a hard error; the capability lint is advisory and
// static, promising detection of obvious undeclared capabilities rather than a
// complete account, so a symlink it cannot safely resolve is simply passed over
// rather than failing the whole advisory pass.
//
// The root itself is the one exception: when root is a symlink to a directory
// (a globally linked install is exactly this shape), it is resolved before the
// walk begins, so the real contents are scanned rather than nothing. WalkDir
// lstats root and would treat a symlinked root as a non directory, walking
// nothing at all; resolving it first (filepath.EvalSymlinks) starts descent at
// the real target. Only the root is resolved this way; descent symlinks remain
// skipped by the check inside the walk.
//
// A file (or subdirectory) that cannot be read DURING descent is skipped with
// an advisory note rather than failing the whole pass (M5): the lint is
// advisory, so one unreadable file inside the tree is a partial result plus a
// note naming it, never a fatal error, and it never changes which sources the
// rest of the tree contributes. Only a failure at the ROOT itself (the root
// cannot be resolved, stat'd, or walked, or a single file argument cannot be
// read) is fatal and returned as an error, since then there is nothing to scan
// at all. The returned notes name every skipped path; the caller surfaces them
// on stderr.
func WalkSources(root string) ([]lint.Source, []string, error) {
	// Resolve the root once so a symlinked install lints its real contents (M1).
	// EvalSymlinks also cleans the path; walking the resolved target and taking
	// every Path relative to it keeps the returned Paths identical to walking the
	// real path directly, since the tree beneath is the same either way.
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, nil, fmt.Errorf("walk sources %s: %w", root, err)
	}
	info, err := os.Stat(resolvedRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("walk sources %s: %w", root, err)
	}
	// A single file argument scans exactly that file (M2), so `smithmark lint
	// path/to/one.ts` works, not only a directory root. Its Path is the file's
	// base name rather than the "." a directory walk of a file would yield, so a
	// finding reads as one.ts:line, not .:line. A single file whose extension no
	// detector recognizes yields nothing, the same silent skip the walk applies.
	// The file argument IS the root, so an unreadable one is fatal, not a note.
	if !info.IsDir() {
		if !hasExtension(resolvedRoot, lintSourceExtensions) {
			return []lint.Source{}, nil, nil
		}
		content, err := os.ReadFile(resolvedRoot)
		if err != nil {
			return nil, nil, fmt.Errorf("walk sources %s: reading %s: %w", root, resolvedRoot, err)
		}
		return []lint.Source{{Path: filepath.Base(resolvedRoot), Content: content}}, nil, nil
	}
	var sources []lint.Source
	var notes []string
	// relName renders a walked path as the root relative, forward slash name a
	// note carries, falling back to the raw path if it cannot be made relative.
	relName := func(path string) string {
		if rel, relErr := filepath.Rel(resolvedRoot, path); relErr == nil {
			return filepath.ToSlash(rel)
		}
		return path
	}
	walkErr := filepath.WalkDir(resolvedRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			// The root was already resolved and stat'd above, so an error at the
			// root here means the directory cannot be walked at all: fatal. An
			// error reaching any descendant (an unreadable subdirectory) is
			// advisory: note it and skip, never failing the whole pass.
			if path == resolvedRoot {
				return fmt.Errorf("walk sources %s: %w", root, err)
			}
			notes = append(notes, fmt.Sprintf("lint skipped unreadable path %s: %v", relName(path), err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// A symlink is never followed and never scanned; WalkDir already does
		// not descend into a symlinked directory, so returning nil here is
		// enough for both a symlinked file and a symlinked directory. The root
		// was already resolved above, so this only skips descent symlinks.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != resolvedRoot && skipSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !hasExtension(path, lintSourceExtensions) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			// An unreadable file inside the tree is advisory (M5): note it and
			// move on, so the completed scan of every other file still stands.
			notes = append(notes, fmt.Sprintf("lint skipped unreadable file %s: %v", relName(path), err))
			return nil
		}
		sources = append(sources, lint.Source{Path: relName(path), Content: content})
		return nil
	})
	if walkErr != nil {
		return nil, notes, walkErr
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	return sources, notes, nil
}

// skipSourceDir reports whether a directory with this base name must not be
// descended into: one of the named excluded directories, or any dot directory.
func skipSourceDir(name string) bool {
	return skippedSourceDirs[name] || strings.HasPrefix(name, ".")
}

// hasExtension reports whether path ends in one of extensions, matched case
// insensitively. It mirrors pkg/core/lint's own unexported extension check, kept
// here so WalkSources gates on exactly the same rule the detectors do without
// reaching into the pure package's internals.
func hasExtension(path string, extensions []string) bool {
	lower := strings.ToLower(path)
	for _, ext := range extensions {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}
