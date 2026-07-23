package main

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
	"github.com/sns45/smithmark/pkg/discover"
)

// registryOptions holds the parsed `registry check` flag surface (spec 5,
// decision D5): a deliberate subset of verify's own flags. There is no
// --strict (findings land in M4, and registry check's own checks are always
// informational so a lint gate has nothing to flag), no --bundle (an
// explicit bundle makes no sense against a registry entry whose whole point
// is discovering what the entry itself points at), and no
// --certificate-identity or --certificate-oidc-issuer (keyless verification is a
// verify concern; a registry entry's npm package is verified key based here, and
// a keyless entry can always be verified directly with `smithmark verify`).
type registryOptions struct {
	attestationBase string
	trustRoot       string
	output          string
}

// newRegistryCmd builds the `registry` command group. `check` is its only
// subcommand today.
func newRegistryCmd(d *deps) *cobra.Command {
	root := &cobra.Command{
		Use:   "registry",
		Short: "Inspect MCP Registry entries",
	}
	root.AddCommand(newRegistryCheckCmd(d))
	return root
}

// newRegistryCheckCmd builds `registry check <server-name>` (Task 3.6): the
// demo surface for the MCP Registry provenance RFC. It shows what the
// registry cannot answer today (no attestation reference field on any entry)
// while running the standard verification pipeline against whatever the
// entry actually points at.
func newRegistryCheckCmd(d *deps) *cobra.Command {
	o := &registryOptions{}
	cmd := &cobra.Command{
		Use:   "check <server-name>",
		Short: "Check an MCP Registry entry's attestation posture",
		Long: "Fetch <server-name> from the MCP Registry and report its attestation posture: " +
			"whether the entry carries the attestation reference field the MCP Registry " +
			"provenance RFC proposes (no real entry does today, which is the gap this " +
			"command demonstrates) and, when the entry carries an npm package, the same " +
			"verification report smithmark verify would produce for it. An entry with no " +
			"npm package (for example a remote only, hosted endpoint entry) carries only " +
			"the registry specific checks and always exits 0 (decision D5: informational, " +
			"not an error); an npm backed entry follows verify's own exit code contract.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRegistryCheck(cmd.Context(), d, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.attestationBase, "attestation-base", "", "base OCI registry for attestation discovery (else SMITHMARK_ATTESTATION_BASE or package.json)")
	f.StringVar(&o.trustRoot, "trust-root", "", "path to a PEM public key to verify key based bundles against (used when the entry carries an npm package)")
	f.StringVar(&o.output, "output", outputSummary, "output format: summary or json")
	return cmd
}

// runRegistryCheck fetches serverName's MCP Registry entry, builds the two
// registry specific checks (pkg/core/verify.RegistryChecks), and either
// merges them into the full verify pipeline's report (when the entry carries
// an npm package, reusing discoverForVerification and verifyDiscovered, the
// same helpers verify.go's own runVerify calls) or returns a report carrying
// only those two checks (every other entry shape; D5). The exit code is the
// same D4 classification verify uses: registry checks are informational, so
// a remote only entry always exits 0, while an npm backed entry's own
// verification failures exit 1 and discovery failures exit 3.
func runRegistryCheck(ctx context.Context, d *deps, serverName string, o *registryOptions) error {
	if err := validateOutputFormat(o.output); err != nil {
		return err
	}
	entry, err := discover.FetchRegistryEntry(ctx, serverName, discover.ResolveOptions{
		Transport: d.Transport,
	})
	if err != nil {
		return err
	}

	remotes := make([]string, len(entry.Remotes))
	for i, r := range entry.Remotes {
		remotes[i] = fmt.Sprintf("%s (%s)", r.URL, r.Transport)
	}
	packageTypes := make([]string, len(entry.Packages))
	for i, p := range entry.Packages {
		packageTypes[i] = p.Type
	}
	_, hasNPM := entry.NPMPackage()
	registryChecks := verify.RegistryChecks(entry.HasAttRef, hasNPM, packageTypes, remotes)

	report, err := buildRegistryReport(ctx, d, entry, registryChecks, o)
	if err != nil {
		return err
	}

	// registry check exposes no --strict flag (see registryOptions' doc
	// comment), so the strict lint gate never fires here; false is the fixed
	// second argument.
	code := verifyExitCode(report, false)
	if err := writeReport(d.Stdout, report, o.output, code); err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	return &verifyExit{code: code}
}

// buildRegistryReport builds the report runRegistryCheck writes. With no npm
// package, the report is built by hand from registryChecks alone: no
// verification stage runs at all (D5), so there is no ATTESTATION_MISSING, no
// SIGNATURE_VALID, none of the verify pipeline's own checks, and no evidence
// block, since no attestation bundle was ever fetched to build one from. With
// an npm package, the shared discovery and verification core runs exactly as
// verify's own runVerify does, and registryChecks is merged into the
// resulting report's Checks, which are then sorted by Code again (the same
// determinism guarantee every VerificationReport carries). Either shape returns
// the same VerificationReport type, so registry check and verify emit one JSON
// output schema and a consumer needs only a single parser for both commands.
func buildRegistryReport(ctx context.Context, d *deps, entry *discover.RegistryEntry, registryChecks []verify.CheckResult, o *registryOptions) (*verify.VerificationReport, error) {
	npmPkg, hasNPM := entry.NPMPackage()
	if !hasNPM {
		return &verify.VerificationReport{
			Subject: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   entry.Name,
				Source: manifest.SourceMCPRegistry,
			},
			Checks:   sortedChecks(registryChecks),
			Findings: []lint.Finding{},
			Evidence: nil,
			// No attestation bundle was ever fetched for a no npm entry, so there
			// is no winning candidate to build evidence from.
			WinningBundle: -1,
			VerifiedAt:    d.Now().UTC(),
		}, nil
	}

	arg := npmPkg.Name + "@" + npmPkg.Version
	disc, err := discoverForVerification(ctx, d, arg, o.attestationBase, "")
	if err != nil {
		return nil, err
	}
	report, err := verifyDiscovered(d, disc, trustConfig{trustRoot: o.trustRoot})
	if err != nil {
		return nil, err
	}
	report.Checks = sortedChecks(append(report.Checks, registryChecks...))
	return report, nil
}

// sortedChecks sorts checks by Code in place and returns it, the same
// determinism guarantee verify.Run's own report carries (spec 3): every
// consumer, including the golden and the human summary, relies on Checks
// being in Code order regardless of which command produced the report.
func sortedChecks(checks []verify.CheckResult) []verify.CheckResult {
	sort.Slice(checks, func(i, j int) bool { return checks[i].Code < checks[j].Code })
	return checks
}
