// Package compose holds the I/O adapters that assemble a dependency SBOM for
// the artifact attest is building a manifest for (spec 2.2, decision D2).
// forgeseal exports no packages today: every generation routine sits under
// its own internal, so a library import is not possible in v0.1. This
// package shells out to the forgeseal CLI instead, hidden behind the
// SBOMGenerator interface below, so the day forgeseal does export a stable
// package, the swap is contained to this one file (see the follow up filed
// against sns45/forgeseal, recorded in docs/decisions.md D2).
package compose

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// cyclonedxMediaTypePrefix is the manifest.SBOMRef.SBOMFormat prefix this
// adapter stamps on every generated SBOM, with the parsed BOM's own
// SpecVersion string appended (controller resolution point 3, Task 2.4).
const cyclonedxMediaTypePrefix = "application/vnd.cyclonedx+json;version="

// minForgesealVersion is the oldest forgeseal release this build accepts,
// verified against the real CLI's own "forgeseal version" output shape
// (controller resolution point 2, Task 2.4). "dev" names a maintainer's own
// local build rather than a release and always bypasses this gate.
const minForgesealVersion = "v0.1.0"

// stderrCaptureLimit bounds how many bytes of a forgeseal subprocess's
// stderr this package retains for an error message, matching
// pkg/discover.ExtractTools's identical concern: a runaway or adversarial
// process must never be able to inflate an error message without bound.
const stderrCaptureLimit = 4096

// forgesealWaitDelay bounds how long cmd.Wait keeps waiting after this
// package has already killed or exited the child, for the same reason
// pkg/discover.ExtractTools sets it: a descendant that escapes and keeps the
// inherited stderr pipe open could otherwise hang Wait indefinitely.
const forgesealWaitDelay = 3 * time.Second

// SBOMResult is what a SBOMGenerator produces: the raw CycloneDX document
// bytes exactly as forgeseal wrote them, and a manifest.SBOMRef describing
// them, a digest of those same raw bytes plus a format string. Locator is
// always left empty here; a later OCI push step assigns it once the SBOM has
// somewhere to point at.
type SBOMResult struct {
	Ref *manifest.SBOMRef
	BOM []byte
}

// SBOMGenerator produces a dependency SBOM for the project rooted at
// projectDir. NewForgesealCLI is the only implementation today (decision
// D2); the interface exists so that a future forgeseal library import needs
// to change only this file, never its callers.
type SBOMGenerator interface {
	Generate(ctx context.Context, projectDir string) (*SBOMResult, error)
}

// forgesealCLI implements SBOMGenerator by shelling out to the forgeseal
// binary found on PATH. It carries no state: every call to Generate
// re-resolves the binary on PATH rather than caching a path from
// construction time, so a PATH change between building the generator and
// calling Generate is always honored. This is also what lets a test install
// a fake binary after already holding a SBOMGenerator value.
type forgesealCLI struct{}

// NewForgesealCLI returns a SBOMGenerator that finds and invokes forgeseal on
// PATH.
func NewForgesealCLI() SBOMGenerator {
	return forgesealCLI{}
}

// Generate resolves forgeseal on PATH, gates its version, runs
// "forgeseal sbom --dir <projectDir> --output <tempfile>" (flags verified
// against the real CLI: --dir defaults to ".", --output writes a file; both
// exist), strictly parses the result with cyclonedx-go, and digests the raw
// output bytes for the returned SBOMRef.
//
// A missing binary returns a *codes.Error carrying codes.SBOMForgesealMissing.
// A parseable version below minForgesealVersion, or a version string this
// adapter cannot parse as semver at all, both return
// codes.SBOMForgesealVersionUnsupported, with the raw version string folded
// into the detail either way; "dev" is always accepted regardless of this
// gate. A BOM that fails strict CycloneDX parsing is always a returned
// error, never silently passed through to the digest step.
func (forgesealCLI) Generate(ctx context.Context, projectDir string) (*SBOMResult, error) {
	path, err := exec.LookPath("forgeseal")
	if err != nil {
		return nil, codes.E(codes.SBOMForgesealMissing, "forgeseal exec adapter: %v", err)
	}

	versionOut, err := runForgeseal(ctx, path, "version")
	if err != nil {
		return nil, fmt.Errorf("forgeseal exec adapter: checking version: %w", err)
	}
	if err := checkForgesealVersion(firstLineSecondField(versionOut)); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "smithmark-forgeseal")
	if err != nil {
		return nil, fmt.Errorf("forgeseal exec adapter: creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	outputPath := filepath.Join(tmpDir, "sbom.cdx.json")

	if _, err := runForgeseal(ctx, path, "sbom", "--dir", projectDir, "--output", outputPath); err != nil {
		return nil, fmt.Errorf("forgeseal exec adapter: generating sbom: %w", err)
	}

	raw, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("forgeseal exec adapter: reading sbom output: %w", err)
	}

	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("forgeseal exec adapter: parsing CycloneDX output: %w", err)
	}

	sum := sha256.Sum256(raw)
	return &SBOMResult{
		Ref: &manifest.SBOMRef{
			SBOMDigest: manifest.DigestSet{"sha256": hex.EncodeToString(sum[:])},
			SBOMFormat: cyclonedxMediaTypePrefix + bom.SpecVersion.String(),
		},
		BOM: raw,
	}, nil
}

// runForgeseal runs the forgeseal binary at path with args under ctx and
// returns its stdout. A start failure or nonzero exit carries up to
// stderrCaptureLimit bytes of captured stderr folded into the returned
// error, mirroring pkg/discover.ExtractTools's bounded stderr handling.
func runForgeseal(ctx context.Context, path string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = forgesealWaitDelay
	stderr := &boundedWriter{limit: stderrCaptureLimit}
	cmd.Stderr = stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running %s %s: %v (stderr: %s)", path, strings.Join(args, " "), err, stderr.String())
	}
	return out, nil
}

// firstLineSecondField extracts the second whitespace separated field of
// output's first line. Real forgeseal's "forgeseal version" prints
// "forgeseal <version>" as its first line, with further indented lines
// (commit, built) following (controller resolution point 2, Task 2.4). An
// empty result here, fewer than two fields on the first line, is handled by
// checkForgesealVersion the same as any other unparseable string.
func firstLineSecondField(output []byte) string {
	line := output
	if i := bytes.IndexByte(output, '\n'); i >= 0 {
		line = output[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return ""
	}
	return fields[1]
}

// checkForgesealVersion gates a forgeseal version string. "dev" is always
// accepted, a maintainer's own local build rather than a release. Any other
// parseable version below minForgesealVersion, and any string this adapter
// cannot parse as plain semver at all, both return
// codes.SBOMForgesealVersionUnsupported, with the raw string always folded
// into the detail.
func checkForgesealVersion(raw string) error {
	if raw == "dev" {
		return nil
	}
	major, minor, patch, ok := parseSemver(raw)
	if !ok {
		return codes.E(codes.SBOMForgesealVersionUnsupported,
			"forgeseal version %q is not a recognized version (want \"dev\" or a plain, optionally v prefixed, major.minor.patch)", raw)
	}
	minMajor, minMinor, minPatch, minOK := parseSemver(minForgesealVersion)
	if !minOK {
		// Unreachable outside a broken build: minForgesealVersion is a
		// package constant this same parser must always accept.
		panic(fmt.Sprintf("compose: minForgesealVersion %q does not parse as semver", minForgesealVersion))
	}
	if semverLess(major, minor, patch, minMajor, minMinor, minPatch) {
		return codes.E(codes.SBOMForgesealVersionUnsupported,
			"forgeseal version %s is older than the minimum supported version %s", raw, minForgesealVersion)
	}
	return nil
}

// parseSemver strips a leading "v" and splits a plain three field semver
// string into its numeric major, minor, and patch components. It handles
// plain semver only, with no prerelease or build metadata tags: every
// forgeseal release tag satisfies this shape, so pulling in a full semver
// parsing dependency for this one comparison is unnecessary.
func parseSemver(v string) (major, minor, patch int, ok bool) {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}

// semverLess reports whether the semver triple (aMajor, aMinor, aPatch)
// sorts strictly before (bMajor, bMinor, bPatch).
func semverLess(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch int) bool {
	if aMajor != bMajor {
		return aMajor < bMajor
	}
	if aMinor != bMinor {
		return aMinor < bMinor
	}
	return aPatch < bPatch
}

// boundedWriter caps how many bytes it retains, silently discarding the
// rest, so capturing a subprocess's stderr for an error message cannot let
// that subprocess inflate memory without bound. Copied verbatim from the
// unexported type of the same name in pkg/discover/mcptools.go (controller
// resolution point 4, Task 2.4): each package needs this in exactly one
// place, so it is duplicated here rather than exported across a package
// boundary for a handful of lines.
type boundedWriter struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedWriter) String() string {
	return b.buf.String()
}
