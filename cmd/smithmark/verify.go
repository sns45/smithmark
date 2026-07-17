package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
	"github.com/sns45/smithmark/pkg/discover"
)

// Output format values for --output. summary is the default human surface; json
// is the deterministic machine surface the golden test pins.
const (
	outputSummary = "summary"
	outputJSON    = "json"
)

// summaryDetailWidth caps how much of a check's detail the summary table prints
// on one line, so a long detail never wraps the terminal into an unreadable
// block. The full detail is always available in --output json.
const summaryDetailWidth = 80

// undeclaredFindingPrefix is the lint finding code family the --strict gate
// reacts to (spec 3). A passing verification that carries a finding whose code
// begins with it exits 2 rather than 0. Findings are empty until Phase 4 (M4)
// populates them, so the gate never fires today; the placeholder test pins that.
const undeclaredFindingPrefix = "UNDECLARED_"

// verifyOptions holds the parsed verify flag surface (spec 5, decision D4).
type verifyOptions struct {
	strict                bool
	bundle                string
	attestationBase       string
	trustRoot             string
	certificateIdentity   string
	certificateOIDCIssuer string
	output                string
}

// verifyExit carries the classified verify exit code (0, 1, or 2) from
// runVerify up to runMain without going through the operational error contract.
// verify writes its report to stdout itself; this sentinel conveys only the exit
// code the decision D4 classification produced, so runMain returns it directly
// rather than emitting the operational stderr error line a real failure would.
type verifyExit struct{ code int }

func (e *verifyExit) Error() string {
	return fmt.Sprintf("verify completed with exit code %d", e.code)
}

// newVerifyCmd builds the verify command. Its pipeline resolves the artifact and
// its candidate attestation bundles through discovery (Task 3.2), reads trust
// material, runs the pure verification core (Task 3.3), attaches the assayward
// compatible evidence block for the winning candidate (Task 3.4), and emits the
// report in the requested format. The process exit code is classified by
// decision D4 and returned through runMain.
func newVerifyCmd(d *deps) *cobra.Command {
	o := &verifyOptions{}
	cmd := &cobra.Command{
		Use:   "verify <artifact>",
		Short: "Verify a capability attestation for an artifact",
		Long: "Verify the capability attestation for <artifact>, an npm name@version, " +
			"a local artifact directory, an OCI reference, or (with --bundle) an " +
			"explicit bundle file. Candidate attestations are discovered, their DSSE " +
			"signatures verified against the --trust-root PEM public key, and a " +
			"classified report is printed. The exit code is 0 when every failing " +
			"class check passes, 1 when any fails, 2 when a passing verification is " +
			"flagged under --strict, and 3 on an operational failure.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(cmd.Context(), d, args[0], o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.strict, "strict", false, "exit 2 when a passing verification carries any UNDECLARED_ lint finding (findings land in M4)")
	f.StringVar(&o.bundle, "bundle", "", "verify this explicit attestation bundle file instead of discovering one")
	f.StringVar(&o.attestationBase, "attestation-base", "", "base OCI registry for attestation discovery (else SMITHMARK_ATTESTATION_BASE or package.json)")
	f.StringVar(&o.trustRoot, "trust-root", "", "path to a PEM public key to verify key based bundles against (the Sigstore TUF trust root form lands in M6)")
	f.StringVar(&o.certificateIdentity, "certificate-identity", "", "expected signing certificate identity for keyless verification (accepted; verification lands with M6 trust root support)")
	f.StringVar(&o.certificateOIDCIssuer, "certificate-oidc-issuer", "", "expected OIDC issuer for keyless verification (accepted; verification lands with M6 trust root support)")
	f.StringVar(&o.output, "output", outputSummary, "output format: summary or json")
	return cmd
}

// runVerify executes the verify pipeline for arg. Every operational failure
// (bad configuration, unreachable discovery, an unusable verifier) returns a
// coded error that runMain surfaces as exit 3; a completed verification instead
// writes its report to stdout and returns a *verifyExit carrying the classified
// exit code, so a negative verdict is never confused with an operational error.
func runVerify(ctx context.Context, d *deps, arg string, o *verifyOptions) error {
	// Keyless verification is accepted but fails closed in v0.1: the cosign
	// certificate flags are recognized so a caller's invocation is not rejected
	// as unknown, but honoring them needs the Sigstore TUF trust root, which
	// lands with M6. Fail closed here, never a silent ignore.
	if o.certificateIdentity != "" || o.certificateOIDCIssuer != "" {
		return codes.E(codes.SigningConfigInvalid,
			"verify: keyless certificate verification is not supported in v0.1; --certificate-identity and --certificate-oidc-issuer verification lands with M6 trust root support")
	}

	opts := discover.ResolveOptions{
		Base:       o.attestationBase,
		BundlePath: o.bundle,
		Transport:  d.Transport,
		Registry:   d.Registry,
	}
	// Attestation discovery needs a read only OCI target; an explicit --bundle
	// short circuits discovery, so a target is constructed only when discovering.
	// The repo argument is a best effort hint the production factory scopes its
	// client with; discovery itself keys the lookup off the deterministic
	// attestation tag, and live registry scoping is refined when M6 wires
	// verification against a real registry.
	if o.bundle == "" {
		target, err := d.ReadTarget(ctx, o.attestationBase)
		if err != nil {
			return fmt.Errorf("verify: resolving OCI target for discovery: %w", err)
		}
		opts.Target = target
	}

	disc, err := discover.Resolve(ctx, arg, opts)
	if err != nil {
		return err
	}

	// Trust material is required whenever bundles were discovered: v0.1 verifies
	// key based bundles against a PEM public key named by --trust-root. Bundles
	// present with no trust root is a configuration error naming the flag, never
	// a silent skip of signature verification.
	var trust []byte
	if len(disc.Bundles) > 0 {
		if o.trustRoot == "" {
			return codes.E(codes.SigningConfigInvalid,
				"verify: %d attestation bundle(s) were discovered but no --trust-root was provided; v0.1 verifies key based bundles against a PEM public key (the Sigstore TUF trust root form lands in M6)", len(disc.Bundles))
		}
		trust, err = os.ReadFile(o.trustRoot)
		if err != nil {
			return codes.E(codes.SigningConfigInvalid, "verify: reading --trust-root %s: %v", o.trustRoot, err)
		}
	}

	report, err := verify.Run(verify.Input{
		Ref:           disc.Ref,
		Bundles:       disc.Bundles,
		NPMProvenance: disc.NPMProvenance,
		TrustMaterial: trust,
		Now:           d.Now().UTC(),
	}, d.Verifier)
	if err != nil {
		return err
	}

	// Attach the assayward compatible evidence block built from the winning
	// candidate's own bytes, but only when a candidate passed every failing
	// class stage; with no winner there is no attestation worth carrying and the
	// evidence stays null (spec 7, U5).
	if report.WinningBundle >= 0 {
		ev, err := report.EvidenceBlock(disc.Bundles[report.WinningBundle])
		if err != nil {
			return err
		}
		report.Evidence = ev
	}

	code := verifyExitCode(report, o.strict)
	if err := writeReport(d.Stdout, report, o.output, code); err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	return &verifyExit{code: code}
}

// verifyExitCode classifies a completed report into its process exit code
// (decision D4). It is the single extension of the exit contract for verify: 1
// when any failing class check failed (delegated to the exported authority so
// the rule is never reimplemented), 2 when a passing verification is flagged by
// --strict for an UNDECLARED_ finding, and 0 otherwise. Informational checks
// that are false by design never drive it.
func verifyExitCode(report *verify.VerificationReport, strict bool) int {
	if verify.FailingChecksFailed(report) {
		return 1
	}
	if strict && hasUndeclaredFinding(report) {
		return 2
	}
	return 0
}

// hasUndeclaredFinding reports whether the report carries any lint finding in
// the UNDECLARED_ family. Findings are empty until Phase 4, so this is false
// today for every input.
func hasUndeclaredFinding(report *verify.VerificationReport) bool {
	for _, f := range report.Findings {
		if strings.HasPrefix(f.Code, undeclaredFindingPrefix) {
			return true
		}
	}
	return false
}

// writeReport emits the report in the requested format. json is the
// deterministic machine surface (two space indent, trailing newline) the golden
// pins; any other value renders the human summary table.
func writeReport(w io.Writer, report *verify.VerificationReport, output string, code int) error {
	if output == outputJSON {
		b, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("verify: marshaling report: %w", err)
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("verify: writing report: %w", err)
		}
		return nil
	}
	return writeSummary(w, report, code)
}

// writeSummary prints one line per check, tagged PASS, FAIL, or INFO, followed
// by a final verdict line. It is asserted loosely by tests (it must carry the
// check codes and the verdict word), never goldened, so its exact spacing is
// free to change.
func writeSummary(w io.Writer, report *verify.VerificationReport, code int) error {
	var b strings.Builder
	for _, c := range report.Checks {
		tag := "PASS"
		switch {
		case c.Informational:
			tag = "INFO"
		case !c.Passed:
			tag = "FAIL"
		}
		detail := truncateDetail(c.Detail, summaryDetailWidth)
		if detail == "" {
			fmt.Fprintf(&b, "%-4s  %s\n", tag, c.Code)
		} else {
			fmt.Fprintf(&b, "%-4s  %-32s  %s\n", tag, c.Code, detail)
		}
	}
	fmt.Fprintf(&b, "%s  %s\n", verdictWord(code), manifest.SubjectName(report.Subject))
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("verify: writing summary: %w", err)
	}
	return nil
}

// verdictWord renders the exit code as the human verdict the summary ends with:
// VERIFIED for a clean pass, FAILED for a failing class failure, and FLAGGED for
// a strict mode UNDECLARED_ flag on an otherwise passing verification.
func verdictWord(code int) string {
	switch code {
	case 0:
		return "VERIFIED"
	case 2:
		return "FLAGGED"
	default:
		return "FAILED"
	}
}

// truncateDetail shortens s to at most max runes, appending an ellipsis when it
// had to cut, so the summary table stays one line per check.
func truncateDetail(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}
