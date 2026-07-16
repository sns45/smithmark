// Package bundle implements the canonical skill bundle digest (spec 4). The
// algorithm here is normative: its output is a compatibility promise that
// admission time verification recomputes bit for bit. This package never
// touches a filesystem; the Phase 2 walker reads a skill root, rejects
// symlinks, and hands the already read file set to Digest.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// Prefix identifies the digest algorithm version. It is prepended to every
// digest this package produces so a bare hex string is never mistaken for a
// bundle digest.
const Prefix = "smithmark-bundle-v1:"

// Mode is the access mode of a file inside a skill bundle.
type Mode string

const (
	ModeRegular    Mode = "regular"
	ModeExecutable Mode = "executable"
)

// File is one already read file inside a skill bundle. Path is relative to
// the skill root and uses forward slashes regardless of host operating
// system. SHA256 is the lowercase hex encoded sha256 of the file content.
type File struct {
	Path   string `json:"path"`
	Mode   Mode   `json:"mode"`
	SHA256 string `json:"sha256"`
}

// sha256HexLen is the length of a sha256 sum encoded as lowercase hex.
const sha256HexLen = sha256.Size * 2

// Digest computes the canonical bundle digest (spec 4). The I/O layer walks
// the skill root, rejects symlinks with codes.BundleSymlinkRejected, and
// hands the already read set here.
//
// The algorithm: validate every entry, sort entries bytewise by path, reject
// duplicate paths, serialize the sorted set as canonical JSON (RFC 8785:
// sorted keys, no insignificant whitespace), take the sha256 of that
// serialization, and prefix it. No mtimes, ownership, or empty directories
// ever enter the computation, so the result is stable across operating
// systems and across runs.
func Digest(files []File) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("%s: bundle has no files to digest", codes.BundleEmpty)
	}

	sorted := make([]File, len(files))
	copy(sorted, files)

	for _, f := range sorted {
		if err := validateFile(f); err != nil {
			return "", err
		}
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Path < sorted[j].Path
	})

	for i := 1; i < len(sorted); i++ {
		if sorted[i].Path == sorted[i-1].Path {
			return "", fmt.Errorf("%s: duplicate path %q", codes.BundleDuplicatePath, sorted[i].Path)
		}
	}

	raw, err := json.Marshal(sorted)
	if err != nil {
		return "", fmt.Errorf("%s: marshaling bundle: %w", codes.BundleDigestInvalid, err)
	}
	canonical, err := jsoncanonicalizer.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("%s: canonicalizing bundle: %w", codes.BundleDigestInvalid, err)
	}

	sum := sha256.Sum256(canonical)
	return Prefix + hex.EncodeToString(sum[:]), nil
}

// validateFile checks one entry against the rules of spec 4: a clean
// relative path with forward slashes, a known mode, and a well formed
// sha256.
func validateFile(f File) error {
	if !validPath(f.Path) {
		return fmt.Errorf("%s: invalid path %q", codes.BundlePathInvalid, f.Path)
	}
	switch f.Mode {
	case ModeRegular, ModeExecutable:
	default:
		return fmt.Errorf("%s: invalid mode %q for path %q", codes.BundleModeInvalid, f.Mode, f.Path)
	}
	if !validSHA256(f.SHA256) {
		return fmt.Errorf("%s: invalid sha256 %q for path %q", codes.BundleDigestInvalid, f.SHA256, f.Path)
	}
	return nil
}

// validPath reports whether path is a clean, relative path using forward
// slashes only: not empty, no backslash, not absolute, and with no "." or
// ".." segment. This is string only validation; pkg/core never imports
// path/filepath, so it never resolves paths against a filesystem.
func validPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(path, `\`) {
		return false
	}
	if strings.HasPrefix(path, "/") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		switch segment {
		case "", ".", "..":
			return false
		}
	}
	return true
}

// validSHA256 reports whether s is a lowercase hex encoded sha256 sum: sixty
// four characters, each in the range 0 to 9 or a to f.
func validSHA256(s string) bool {
	if len(s) != sha256HexLen {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
