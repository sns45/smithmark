package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// declFileName is the fixed declaration file attest reads from the artifact
// root (U1). The positional path argument names the directory that holds it.
const declFileName = "smithmark.yaml"

// toolExtractionTimeout bounds a live MCP tool extraction. ExtractTools
// requires a context with a deadline (Task 2.3); this is the deadline attest
// gives a maker's own stdio server to answer initialize and tools/list.
const toolExtractionTimeout = 60 * time.Second

// attestOptions holds the parsed attest flag surface (spec 5).
type attestOptions struct {
	key             string
	skipSBOM        bool
	toolsFrom       string
	attestationBase string
	tarball         string
	output          string
	dryRun          bool
}

// newAttestCmd builds the attest command. The pipeline it drives is the
// integration point of the whole phase: load the declaration, resolve the
// subject (walk a skill directory or digest an npm tarball), complete the
// surface (walker output for a skill, tool extraction for an mcp-server),
// compose a dependency SBOM, stamp and validate the manifest, assemble and
// sign the statement, then either print it, write the bundle, or push it.
func newAttestCmd(d *deps) *cobra.Command {
	o := &attestOptions{}
	cmd := &cobra.Command{
		Use:   "attest <path>",
		Short: "Generate and sign a capability attestation for an artifact",
		Long: "Generate a signed capability attestation for the artifact rooted at " +
			"<path>. The artifact kind is read from the smithmark.yaml declaration " +
			"at that path: a skill is bundled and digested from its directory, an " +
			"mcp-server is digested from its npm tarball and has its tool listing " +
			"extracted from the running server (or read with --tools-from).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAttest(cmd.Context(), d, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.key, "key", "", "path to a PEM encoded private key for offline signing")
	f.BoolVar(&o.skipSBOM, "skip-sbom", false, "skip forgeseal dependency SBOM composition")
	f.StringVar(&o.toolsFrom, "tools-from", "", "read the MCP tool listing from a JSON file instead of launching the server")
	f.StringVar(&o.attestationBase, "attestation-base", "", "base OCI registry for the attestation ref (else SMITHMARK_ATTESTATION_BASE or package.json)")
	f.StringVar(&o.tarball, "tarball", "", "path to the npm tarball whose digest is the mcp-server subject (else the sole *.tgz in <path>)")
	f.StringVar(&o.output, "output", "", "write the signed bundle to this file instead of pushing it")
	f.BoolVar(&o.dryRun, "dry-run", false, "print the canonical statement to stdout and sign nothing")
	return cmd
}

// runAttest executes the attest pipeline for the artifact rooted at root. The
// kind specific work (subject digest and surface completion) is delegated to
// completeSkillSurface or completeMCPSurface; everything after, the SBOM,
// stamping, validation, statement assembly, and the dry-run, output, or push
// terminus, is shared.
func runAttest(ctx context.Context, d *deps, root string, o *attestOptions) error {
	decl, err := discover.LoadDeclared(filepath.Join(root, declFileName))
	if err != nil {
		return err
	}
	m := decl.Manifest

	var subjectDigest manifest.DigestSet
	switch m.Artifact.Kind {
	case manifest.KindSkill:
		subjectDigest, err = completeSkillSurface(root, decl)
	case manifest.KindMCPServer:
		subjectDigest, err = completeMCPSurface(ctx, root, decl, o)
	default:
		// LoadDeclared already rejects unknown kinds, so this is defense in
		// depth rather than a reachable path today.
		return codes.E(codes.ManifestEnumInvalid, "attest: unsupported artifact kind %q", m.Artifact.Kind)
	}
	if err != nil {
		return err
	}

	// Dependency SBOM (Task 2.4), wired into the manifest as its dependencies
	// block unless the maker skipped it.
	if !o.skipSBOM {
		res, err := d.SBOM.Generate(ctx, root)
		if err != nil {
			return err
		}
		m.Dependencies = res.Ref
		// When writing a bundle to a file, publish the raw SBOM as a sidecar
		// next to it and point the manifest's dependencies locator at that
		// file, before the manifest is validated and signed so the locator is
		// covered by the signature. A dry run writes nothing to disk even when
		// --output is also passed, so the sidecar is gated on not being a dry
		// run. When pushing instead (no --output), the locator is left empty
		// on purpose: SBOM publication and locator assignment land with M3
		// discovery or M6 release wiring (D2).
		if o.output != "" && !o.dryRun {
			sbomPath := o.output + ".sbom.json"
			if err := os.WriteFile(sbomPath, res.BOM, 0o644); err != nil {
				return fmt.Errorf("attest: writing SBOM to %s: %w", sbomPath, err)
			}
			m.Dependencies.Locator = filepath.Base(sbomPath)
		}
	}

	// Stamp the injected clock and this build's generator identity, the two
	// completion fields the pure core cannot supply.
	m.GeneratedAt = d.Now().UTC().Truncate(time.Second)
	m.Generator = manifest.GeneratorInfo{Name: generatorName, Version: version}

	if issues := m.Validate(); len(issues) > 0 {
		// Aggregate every issue into the detail as "code at path", joined by
		// semicolons, so a maker sees all of them at once rather than fixing
		// one, rerunning, and hitting the next. The error code is the first
		// issue's code; Validate's stable sort makes "first" deterministic.
		parts := make([]string, len(issues))
		for i, is := range issues {
			parts[i] = fmt.Sprintf("%s at %s", is.Code, is.Path)
		}
		return codes.E(issues[0].Code, "attest: completed manifest is invalid: %s", strings.Join(parts, "; "))
	}

	ref := manifest.ArtifactRef{
		Kind:    m.Artifact.Kind,
		Name:    m.Artifact.Name,
		Version: m.Artifact.Version,
		Digest:  subjectDigest,
		Source:  m.Artifact.Source,
	}
	stmt, err := manifest.NewStatement(ref, m)
	if err != nil {
		return err
	}
	canonical, err := stmt.Canonical()
	if err != nil {
		return fmt.Errorf("attest: canonicalizing statement: %w", err)
	}

	// --dry-run signs nothing: the canonical statement is the whole output.
	if o.dryRun {
		if _, err := d.Stdout.Write(append(canonical, '\n')); err != nil {
			return err
		}
		return nil
	}

	signed, err := d.Signer.SignStatement(ctx, canonical, compose.SignOptions{KeyPath: o.key})
	if err != nil {
		return err
	}

	// --output writes the signed bundle to a file instead of publishing it.
	if o.output != "" {
		if err := os.WriteFile(o.output, signed.Bundle, 0o644); err != nil {
			return fmt.Errorf("attest: writing bundle to %s: %w", o.output, err)
		}
		fmt.Fprintf(d.Stdout, "wrote signed bundle to %s\n", o.output)
		return nil
	}

	return pushAttestation(ctx, d, root, ref, o, signed)
}

// completeSkillSurface walks the skill directory rooted at root, cross checks
// the SKILL.md frontmatter identity against the declaration, fills the
// manifest's skill surface with the walker's entry digest and script list,
// and returns the canonical bundle digest as a subject digest set. It leaves
// the declared invokesTools list untouched, since the declaration owns that
// key, never the walker.
func completeSkillSurface(root string, decl *discover.Declaration) (manifest.DigestSet, error) {
	m := decl.Manifest
	files, surface, info, err := discover.WalkSkill(root, decl.Executables)
	if err != nil {
		return nil, err
	}

	// The declaration is the authoritative identity; SKILL.md is cross checked
	// against it. A name that disagrees is a subject mismatch: the two must
	// name the same artifact (U4). When SKILL.md carries no frontmatter name
	// there is nothing to check, so the declaration stands alone.
	if info.Name != "" && info.Name != m.Artifact.Name {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"attest: SKILL.md frontmatter name %q does not match declared name %q", info.Name, m.Artifact.Name)
	}
	// A skill's version lives in its SKILL.md frontmatter (U4). Adopt it when
	// present; if the declaration also pinned a version, the two must agree.
	if info.Version != "" {
		if m.Artifact.Version != "" && m.Artifact.Version != info.Version {
			return nil, codes.E(codes.StatementSubjectMismatch,
				"attest: SKILL.md frontmatter version %q does not match declared version %q", info.Version, m.Artifact.Version)
		}
		m.Artifact.Version = info.Version
	}

	m.Skill.EntryDigest = surface.EntryDigest
	m.Skill.Scripts = surface.Scripts

	digest, err := bundle.Digest(files)
	if err != nil {
		return nil, err
	}
	return manifest.SubjectDigestFromBundle(digest)
}

// completeMCPSurface fills the manifest's mcp surface with an extracted tool
// listing and returns the npm tarball's sha512 as the subject digest set.
// Tools come from --tools-from when supplied, else from launching the declared
// command and speaking MCP to it (U2). Resources and prompts are empty but non
// nil in v0.1: extraction covers tools only, and a nil slice would fail
// validation as an absent key. Transports stay whatever the declaration set.
//
// When BOTH a --tools-from reference file AND a declared launch command are
// present, the two are cross checked and any disagreement fails closed with
// TOOL_LISTING_MISMATCH (decision U2 addendum): attest is the one command that
// may execute the artifact, so it is the only place the maker's static tool
// listing can be checked against what the server actually serves. Signing a
// manifest whose tool listing deviates from the live server is exactly the
// misdeclaration this project exists to catch, so it is refused rather than
// silently preferring one source over the other.
func completeMCPSurface(ctx context.Context, root string, decl *discover.Declaration, o *attestOptions) (manifest.DigestSet, error) {
	m := decl.Manifest

	tools, err := resolveMCPTools(ctx, decl, o)
	if err != nil {
		return nil, err
	}

	m.MCP.Tools = tools
	m.MCP.Resources = []string{}
	m.MCP.Prompts = []string{}

	_, digest, tarName, tarVersion, err := discover.TarballDigest(root, o.tarball)
	if err != nil {
		return nil, err
	}
	// Cross check the tarball's own package.json identity against the
	// declaration: the two must name the same artifact (U4, D6). The
	// declaration is the authority, so a disagreement is a subject mismatch
	// naming both sides.
	if tarName != m.Artifact.Name {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"attest: tarball package.json name %q does not match declared name %q", tarName, m.Artifact.Name)
	}
	if tarVersion != m.Artifact.Version {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"attest: tarball package.json version %q does not match declared version %q", tarVersion, m.Artifact.Version)
	}
	return digest, nil
}

// resolveMCPTools produces the tool listing completeMCPSurface stamps, choosing
// among three cases. With both a --tools-from file and a declared command, it
// extracts live, compares the two, and fails closed on any disagreement
// (TOOL_LISTING_MISMATCH). With only a --tools-from file, it reads the file
// (verify's escape hatch, no execution). With only a command, it launches the
// server and extracts live. With neither, it fails closed naming both remedies.
func resolveMCPTools(ctx context.Context, decl *discover.Declaration, o *attestOptions) ([]manifest.ToolDecl, error) {
	hasFile := o.toolsFrom != ""
	hasCommand := len(decl.Command) > 0

	switch {
	case hasFile && hasCommand:
		fileTools, err := discover.ToolsFromFile(o.toolsFrom)
		if err != nil {
			return nil, err
		}
		liveTools, err := extractLiveTools(ctx, decl.Command)
		if err != nil {
			return nil, err
		}
		if disagreement := toolListingDisagreement(fileTools, liveTools); disagreement != "" {
			return nil, codes.E(codes.ToolListingMismatch,
				"attest: the --tools-from listing disagrees with the live server: %s. Refusing to sign a manifest whose declared tools deviate from what the server actually lists (U2)", disagreement)
		}
		return fileTools, nil
	case hasFile:
		return discover.ToolsFromFile(o.toolsFrom)
	case hasCommand:
		return extractLiveTools(ctx, decl.Command)
	default:
		return nil, codes.E(codes.ToolExtractionFailed,
			"attest: mcp-server declaration carries no command to launch for tool extraction; add a command to smithmark.yaml or pass --tools-from")
	}
}

// extractLiveTools launches command under the bounded extraction timeout and
// returns its live tool listing (U2). It is shared by the command only and the
// cross check paths so the deadline is applied identically in both.
func extractLiveTools(ctx context.Context, command []string) ([]manifest.ToolDecl, error) {
	extractCtx, cancel := context.WithTimeout(ctx, toolExtractionTimeout)
	defer cancel()
	tools, _, err := discover.ExtractTools(extractCtx, command)
	return tools, err
}

// toolListingDisagreement compares a static tool listing against a live one by
// tool name and inputSchemaDigest, returning a human readable description of the
// first disagreement it finds or "" when the two agree. The comparison is order
// independent (a server and a hand written file need not list tools in the same
// order) and deterministic (names are compared in sorted order), so the same
// mismatch always yields the same message.
//
// A duplicate tool name on EITHER side is itself a disagreement (M4): a well
// formed MCP tools list has unique names, so a repeated name is a malformed
// listing worth failing on, not a detail to collapse away. Both sides are
// checked for duplicates before the set comparison, so a duplicate can never be
// silently reconciled last wins and signed.
func toolListingDisagreement(fileTools, liveTools []manifest.ToolDecl) string {
	if dup := duplicateToolName(fileTools); dup != "" {
		return fmt.Sprintf("--tools-from lists tool %q more than once; a well formed MCP tools list has unique names", dup)
	}
	if dup := duplicateToolName(liveTools); dup != "" {
		return fmt.Sprintf("the live server lists tool %q more than once; a well formed MCP tools list has unique names", dup)
	}

	fileByName := indexToolsByName(fileTools)
	liveByName := indexToolsByName(liveTools)

	for _, name := range sortedToolNames(fileByName) {
		if _, ok := liveByName[name]; !ok {
			return fmt.Sprintf("--tools-from declares tool %q which the live server does not list", name)
		}
	}
	for _, name := range sortedToolNames(liveByName) {
		if _, ok := fileByName[name]; !ok {
			return fmt.Sprintf("the live server lists tool %q which --tools-from does not declare", name)
		}
	}
	for _, name := range sortedToolNames(fileByName) {
		if !digestSetsEqual(fileByName[name].InputSchemaDigest, liveByName[name].InputSchemaDigest) {
			return fmt.Sprintf("tool %q input schema digest disagrees between --tools-from and the live server", name)
		}
	}
	return ""
}

// indexToolsByName keys a tool listing by tool name. A well formed MCP server
// never lists a name twice, and toolListingDisagreement rejects any listing that
// does (duplicateToolName) before calling this, so by the time indexing runs
// every name is unique and no collapsing can hide a disagreement.
func indexToolsByName(tools []manifest.ToolDecl) map[string]manifest.ToolDecl {
	m := make(map[string]manifest.ToolDecl, len(tools))
	for _, t := range tools {
		m[t.Name] = t
	}
	return m
}

// duplicateToolName reports the first tool name (in sorted order, so the result
// is deterministic) that appears more than once in tools, or "" when every name
// is unique. A duplicate makes the whole listing malformed, so
// toolListingDisagreement treats it as a fail closed disagreement rather than
// collapsing it.
func duplicateToolName(tools []manifest.ToolDecl) string {
	seen := make(map[string]bool, len(tools))
	var dups []string
	for _, t := range tools {
		if seen[t.Name] {
			dups = append(dups, t.Name)
		}
		seen[t.Name] = true
	}
	if len(dups) == 0 {
		return ""
	}
	sort.Strings(dups)
	return dups[0]
}

// sortedToolNames returns the tool names in a listing index, sorted, so every
// comparison and error message this file produces is deterministic.
func sortedToolNames(byName map[string]manifest.ToolDecl) []string {
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// digestSetsEqual reports whether two digest sets carry the same keys and
// values. An inputSchemaDigest is a single sha256 entry in practice, but this
// compares the whole set so a future multi algorithm digest is handled too.
func digestSetsEqual(a, b manifest.DigestSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// pushAttestation resolves the deterministic attestation ref for ref, opens a
// target for its repository, and pushes the signed bundle there (Tasks 2.6,
// 2.7). The base registry is resolved from the flag, the environment, or the
// artifact's package.json in that order (D3).
func pushAttestation(ctx context.Context, d *deps, root string, ref manifest.ArtifactRef, o *attestOptions, signed *compose.SignedBundle) error {
	base, err := discover.ResolveAttestationBase(o.attestationBase, root)
	if err != nil {
		return err
	}
	repo, tag, err := discover.AttestationRef(base, ref)
	if err != nil {
		return err
	}
	target, err := d.NewTarget(ctx, repo)
	if err != nil {
		return fmt.Errorf("attest: resolving OCI target for %s: %w", repo, err)
	}
	digest, err := compose.PushAttestation(ctx, target, repo, tag, signed)
	if err != nil {
		return err
	}
	fmt.Fprintf(d.Stdout, "pushed attestation to %s:%s (%s)\n", repo, tag, digest)
	return nil
}
