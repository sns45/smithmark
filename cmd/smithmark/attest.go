package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

// attestationBaseEnvVar is the environment variable consulted second in the
// D3 base resolution order, after the --attestation-base flag and before the
// package.json fallback.
const attestationBaseEnvVar = "SMITHMARK_ATTESTATION_BASE"

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
	}

	// Stamp the injected clock and this build's generator identity, the two
	// completion fields the pure core cannot supply.
	m.GeneratedAt = d.Now().UTC().Truncate(time.Second)
	m.Generator = manifest.GeneratorInfo{Name: generatorName, Version: version}

	if issues := m.Validate(); len(issues) > 0 {
		first := issues[0]
		return codes.E(first.Code, "attest: completed manifest is invalid at %s: %s", first.Path, first.Detail)
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
func completeMCPSurface(ctx context.Context, root string, decl *discover.Declaration, o *attestOptions) (manifest.DigestSet, error) {
	m := decl.Manifest

	var tools []manifest.ToolDecl
	var err error
	if o.toolsFrom != "" {
		tools, err = discover.ToolsFromFile(o.toolsFrom)
	} else {
		if len(decl.Command) == 0 {
			return nil, codes.E(codes.ToolExtractionFailed,
				"attest: mcp-server declaration carries no command to launch for tool extraction; add a command to smithmark.yaml or pass --tools-from")
		}
		extractCtx, cancel := context.WithTimeout(ctx, toolExtractionTimeout)
		defer cancel()
		tools, _, err = discover.ExtractTools(extractCtx, decl.Command)
	}
	if err != nil {
		return nil, err
	}

	m.MCP.Tools = tools
	m.MCP.Resources = []string{}
	m.MCP.Prompts = []string{}

	return resolveTarballDigest(root, o.tarball)
}

// resolveTarballDigest digests the npm tarball that identifies an mcp-server
// subject. An explicit --tarball path wins; otherwise attest autodetects
// exactly one *.tgz in the artifact root. Zero or several is ambiguous and
// fails closed with ATTEST_SUBJECT_UNRESOLVED rather than guessing which
// tarball to attest. The digest is sha512 (U6), the algorithm npm's own
// integrity string uses.
func resolveTarballDigest(root, explicit string) (manifest.DigestSet, error) {
	tarball := explicit
	if tarball == "" {
		matches, err := filepath.Glob(filepath.Join(root, "*.tgz"))
		if err != nil {
			return nil, fmt.Errorf("attest: scanning %s for a tarball: %w", root, err)
		}
		switch len(matches) {
		case 1:
			tarball = matches[0]
		case 0:
			return nil, codes.E(codes.AttestSubjectUnresolved,
				"attest: no *.tgz tarball found in %s; pass --tarball to name the subject", root)
		default:
			return nil, codes.E(codes.AttestSubjectUnresolved,
				"attest: found %d *.tgz tarballs in %s; pass --tarball to select the subject", len(matches), root)
		}
	}

	f, err := os.Open(tarball)
	if err != nil {
		return nil, fmt.Errorf("attest: opening tarball %s: %w", tarball, err)
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("attest: hashing tarball %s: %w", tarball, err)
	}
	return manifest.DigestSet{"sha512": hex.EncodeToString(h.Sum(nil))}, nil
}

// pushAttestation resolves the deterministic attestation ref for ref, opens a
// target for its repository, and pushes the signed bundle there (Tasks 2.6,
// 2.7). The base registry is resolved from the flag, the environment, or the
// artifact's package.json in that order (D3).
func pushAttestation(ctx context.Context, d *deps, root string, ref manifest.ArtifactRef, o *attestOptions, signed *compose.SignedBundle) error {
	base, err := resolveAttestationBase(root, o.attestationBase)
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

// resolveAttestationBase applies the D3 base resolution order: the
// --attestation-base flag, then the SMITHMARK_ATTESTATION_BASE environment
// variable, then a smithmark.attestationBase key in the artifact's
// package.json, else ATTESTATION_BASE_UNKNOWN.
func resolveAttestationBase(root, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if env := os.Getenv(attestationBaseEnvVar); env != "" {
		return env, nil
	}
	base, ok, err := attestationBaseFromPackageJSON(root)
	if err != nil {
		return "", err
	}
	if ok {
		return base, nil
	}
	return "", codes.E(codes.AttestationBaseUnknown,
		"attest: no attestation base; set --attestation-base, %s, or a smithmark.attestationBase key in package.json", attestationBaseEnvVar)
}

// attestationBaseFromPackageJSON reads the smithmark.attestationBase discovery
// key from the artifact's package.json (D3). A missing package.json, or one
// without the key, is not an error here: it simply means this resolution step
// did not supply a base. package.json carries only this discovery metadata,
// never capability declarations (U1).
func attestationBaseFromPackageJSON(root string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("attest: reading package.json: %w", err)
	}
	var pkg struct {
		Smithmark struct {
			AttestationBase string `json:"attestationBase"`
		} `json:"smithmark"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", false, fmt.Errorf("attest: parsing package.json: %w", err)
	}
	if pkg.Smithmark.AttestationBase == "" {
		return "", false, nil
	}
	return pkg.Smithmark.AttestationBase, true, nil
}
