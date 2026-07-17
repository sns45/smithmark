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
// matched case insensitively. It mirrors the extension sets DetectJS and
// DetectPython gate on (pkg/core/lint's jsExtensions plus pyExtensions): the
// detectors silently skip any Source whose path does not end in one of these,
// so collecting exactly this set here avoids reading files the detectors would
// only discard. The two lists are kept in step deliberately; a new detector
// extension must be added in both places.
var lintSourceExtensions = []string{".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py"}

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
// Symlinks are skipped silently, and WalkSources never follows one. This is a
// deliberate contrast with the skill bundle walker (WalkSkill), which rejects a
// symlink outright with BUNDLE_SYMLINK_REJECTED: a bundle digest must be an
// exact, unambiguous account of what will be installed, so a symlink there is a
// hard error; the capability lint is advisory and static, promising detection
// of obvious undeclared capabilities rather than a complete account, so a
// symlink it cannot safely resolve is simply passed over rather than failing
// the whole advisory pass.
func WalkSources(root string) ([]lint.Source, error) {
	var sources []lint.Source
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk sources %s: %w", root, err)
		}
		// A symlink is never followed and never scanned; WalkDir already does
		// not descend into a symlinked directory, so returning nil here is
		// enough for both a symlinked file and a symlinked directory.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if path != root && skipSourceDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !hasExtension(path, lintSourceExtensions) {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("walk sources %s: reading %s: %w", root, path, err)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("walk sources %s: %w", root, err)
		}
		sources = append(sources, lint.Source{Path: filepath.ToSlash(rel), Content: content})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i].Path < sources[j].Path })
	return sources, nil
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
