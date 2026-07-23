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
// begins with it exits 2 rather than 0. M4 populates Findings from the
// capability lint over a local source tree (attachLintFindings), so the gate
// now fires live over a misdeclared local artifact.
const undeclaredFindingPrefix = "UNDECLARED_"

// verifyOptions holds the parsed verify flag surface (spec 5, decision D4).
type verifyOptions struct {
	strict                bool
	bundle                string
	attestationBase       string
	trustRoot             string
	certificateIdentity   string
	certificateOIDCIssuer string
	sigstoreTrustRoot     string
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
	f.BoolVar(&o.strict, "strict", false, "exit 2 when a passing verification carries any UNDECLARED_ lint finding")
	f.StringVar(&o.bundle, "bundle", "", "verify this explicit attestation bundle file instead of discovering one")
	f.StringVar(&o.attestationBase, "attestation-base", "", "base OCI registry for attestation discovery (else SMITHMARK_ATTESTATION_BASE or package.json)")
	f.StringVar(&o.trustRoot, "trust-root", "", "path to a PEM public key to verify key based bundles against (mutually exclusive with the keyless certificate flags)")
	f.StringVar(&o.certificateIdentity, "certificate-identity", "", "expected signing certificate identity (SubjectAlternativeName) for keyless verification; requires --certificate-oidc-issuer")
	f.StringVar(&o.certificateOIDCIssuer, "certificate-oidc-issuer", "", "expected OIDC issuer for keyless verification; requires --certificate-identity")
	f.StringVar(&o.sigstoreTrustRoot, "sigstore-trust-root", "", "path to a Sigstore trusted root JSON to verify keyless bundles against offline (default: the public good live TUF root)")
	f.StringVar(&o.output, "output", outputSummary, "output format: summary or json")
	return cmd
}

// runVerify executes the verify pipeline for arg. Every operational failure
// (bad configuration, unreachable discovery, an unusable verifier) returns a
// coded error that runMain surfaces as exit 3; a completed verification instead
// writes its report to stdout and returns a *verifyExit carrying the classified
// exit code, so a negative verdict is never confused with an operational error.
func runVerify(ctx context.Context, d *deps, arg string, o *verifyOptions) error {
	if err := validateOutputFormat(o.output); err != nil {
		return err
	}
	// Select and validate the trust mode before any discovery, so a
	// contradictory invocation fails closed early rather than after network work.
	if err := validateVerifyTrustMode(o); err != nil {
		return err
	}

	disc, err := discoverForVerification(ctx, d, arg, o.attestationBase, o.bundle)
	if err != nil {
		return err
	}

	report, err := verifyDiscovered(d, disc, verifyTrustConfig(o))
	if err != nil {
		return err
	}

	// Surface discovery notes on stderr (summary mode only) so a human sees which
	// resolution path ran and why, while stdout stays a clean, parseable report.
	writeStderrNotes(d.Stderr, o.output == outputJSON, disc.Notes)

	// Capability lint over the local source tree (decision D4 addendum). Only a
	// local directory argument carries source to scan; a remote or bundle only
	// verification leaves Findings empty and notes that lint was skipped. The
	// findings never change any verify check outcome; they only feed the
	// --strict exit 2 gate below.
	lintNotes, err := attachLintFindings(arg, report)
	if err != nil {
		return err
	}
	writeStderrNotes(d.Stderr, o.output == outputJSON, lintNotes)

	code := verifyExitCode(report, o.strict)
	if err := writeReport(d.Stdout, report, o.output, code); err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	return &verifyExit{code: code}
}

// validateOutputFormat rejects an --output value other than the two this build
// understands, failing closed with a coded error rather than silently treating
// an unrecognized format as the human summary. Both verify and registry check
// call it, so the two commands share one definition of the valid set.
func validateOutputFormat(output string) error {
	switch output {
	case outputSummary, outputJSON:
		return nil
	default:
		return codes.E(codes.OutputFormatInvalid,
			"unknown --output value %q; valid values are %q and %q", output, outputSummary, outputJSON)
	}
}

// writeStderrNotes prints each advisory or discovery note to w (stderr) as a
// "note:" line, but only when jsonMode is false. Keeping notes on stderr leaves
// stdout a clean, parseable report and the json golden untouched; json mode
// prints nothing here, because surfacing notes as a report schema field is a
// deliberate M4 decision, not something to smuggle into the json surface. It is
// the one helper both verify (discovery notes, lint skipped notes) and lint
// (advisory notes) share, so the two never format the stderr note surface two
// different ways.
func writeStderrNotes(w io.Writer, jsonMode bool, notes []string) {
	if jsonMode {
		return
	}
	for _, n := range notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

// discoverForVerification builds discover.ResolveOptions from the shared
// attestation discovery flags and resolves arg through discover.Resolve. An
// explicit bundlePath short circuits attestation discovery entirely (no OCI
// target factory is set, matching discover.Resolve's own BundlePath
// contract); every other case passes d.ReadTarget straight through, since
// discovery itself now computes the per artifact repository and calls the
// factory with it. Both verify and registry check's npm continuation (Task
// 3.6) share this, so the discovery wiring is never duplicated between the
// two commands.
func discoverForVerification(ctx context.Context, d *deps, arg, attestationBase, bundlePath string) (*discover.Discovered, error) {
	opts := discover.ResolveOptions{
		Base:       attestationBase,
		BundlePath: bundlePath,
		Transport:  d.Transport,
		Registry:   d.Registry,
	}
	// Attestation discovery needs a factory that scopes a read only OCI target
	// to the per artifact repository discovery computes. An explicit --bundle
	// short circuits discovery, so the factory is only consulted when
	// discovering. Base resolution and repository scoping both live inside
	// discovery now, so the CLI passes the factory straight through.
	if bundlePath == "" {
		opts.NewTarget = d.ReadTarget
	}
	return discover.Resolve(ctx, arg, opts)
}

// trustConfig carries the verify trust mode selection into verifyDiscovered: a
// key based PEM public key path, or a keyless certificate identity and issuer
// with an optional injected Sigstore trusted root JSON. It decouples
// verifyDiscovered from verifyOptions so `registry check`, which offers only the
// key based --trust-root, reaches the same helper without inheriting the keyless
// flags it deliberately omits.
type trustConfig struct {
	trustRoot             string
	certificateIdentity   string
	certificateOIDCIssuer string
	sigstoreTrustRoot     string
}

// keyless reports whether the config selects the keyless trust mode: either
// certificate field being set. validateVerifyTrustMode has already ensured both
// are set together and that --trust-root is not also present, so this is a clean
// binary selector by the time verifyDiscovered consults it.
func (tc trustConfig) keyless() bool {
	return tc.certificateIdentity != "" || tc.certificateOIDCIssuer != ""
}

// verifyTrustConfig projects the verify flag surface into a trustConfig.
func verifyTrustConfig(o *verifyOptions) trustConfig {
	return trustConfig{
		trustRoot:             o.trustRoot,
		certificateIdentity:   o.certificateIdentity,
		certificateOIDCIssuer: o.certificateOIDCIssuer,
		sigstoreTrustRoot:     o.sigstoreTrustRoot,
	}
}

// validateVerifyTrustMode fails closed on a contradictory or half specified
// trust mode before any discovery runs. Key based (--trust-root) and keyless
// (the certificate flags) are mutually exclusive, and keyless requires both the
// certificate identity and the OIDC issuer: a single certificate flag alone
// would leave half the identity unpinned, which for keyless verification is fail
// open, so it is refused. An injected --sigstore-trust-root is only meaningful in
// keyless mode.
func validateVerifyTrustMode(o *verifyOptions) error {
	keyless := o.certificateIdentity != "" || o.certificateOIDCIssuer != ""
	if keyless && o.trustRoot != "" {
		return codes.E(codes.SigningConfigInvalid,
			"verify: --trust-root (key based) and the keyless certificate flags are mutually exclusive; pass one trust mode, not both")
	}
	if keyless && (o.certificateIdentity == "" || o.certificateOIDCIssuer == "") {
		return codes.E(codes.SigningConfigInvalid,
			"verify: keyless verification requires both --certificate-identity and --certificate-oidc-issuer; a single flag leaves the signing identity half unpinned")
	}
	if !keyless && o.sigstoreTrustRoot != "" {
		return codes.E(codes.SigningConfigInvalid,
			"verify: --sigstore-trust-root applies only to keyless verification; set --certificate-identity and --certificate-oidc-issuer to use it")
	}
	return nil
}

// verifyDiscovered runs the pure verification core over disc and attaches the
// assayward compatible evidence block when a candidate won (Task 3.4). Check
// outcomes are decided in exactly one place regardless of which command
// reached here (spec 3): both verify and registry check's npm continuation
// (Task 3.6) call this rather than each running verify.Run by hand.
func verifyDiscovered(d *deps, disc *discover.Discovered, tc trustConfig) (*verify.VerificationReport, error) {
	// Trust material is required whenever bundles were discovered. Key based
	// verification needs the PEM public key named by --trust-root; keyless
	// verification needs the certificate identity and issuer (validated already)
	// and reads an optional injected Sigstore trusted root JSON. Bundles present
	// with neither trust mode configured is a configuration error naming both
	// remedies, never a silent skip of signature verification.
	in := verify.Input{
		Ref:           disc.Ref,
		Bundles:       disc.Bundles,
		NPMProvenance: disc.NPMProvenance,
		Now:           d.Now().UTC(),
	}
	if len(disc.Bundles) > 0 {
		if tc.keyless() {
			in.CertificateIdentity = tc.certificateIdentity
			in.CertificateOIDCIssuer = tc.certificateOIDCIssuer
			if tc.sigstoreTrustRoot != "" {
				rootJSON, err := os.ReadFile(tc.sigstoreTrustRoot)
				if err != nil {
					return nil, codes.E(codes.SigningConfigInvalid, "reading --sigstore-trust-root %s: %v", tc.sigstoreTrustRoot, err)
				}
				in.SigstoreTrustRoot = rootJSON
			}
		} else {
			if tc.trustRoot == "" {
				return nil, codes.E(codes.SigningConfigInvalid,
					"%d attestation bundle(s) were discovered but no trust material was provided; pass --trust-root for a key based bundle, or --certificate-identity and --certificate-oidc-issuer for a keyless bundle", len(disc.Bundles))
			}
			trust, err := os.ReadFile(tc.trustRoot)
			if err != nil {
				return nil, codes.E(codes.SigningConfigInvalid, "reading --trust-root %s: %v", tc.trustRoot, err)
			}
			in.TrustMaterial = trust
		}
	}

	report, err := verify.Run(in, d.Verifier)
	if err != nil {
		return nil, err
	}

	// Attach the assayward compatible evidence block built from the winning
	// candidate's own bytes, but only when a candidate passed every failing
	// class stage; with no winner there is no attestation worth carrying and the
	// evidence stays null (spec 7, U5).
	if report.WinningBundle >= 0 {
		ev, err := report.EvidenceBlock(disc.Bundles[report.WinningBundle])
		if err != nil {
			return nil, err
		}
		report.Evidence = ev
	}
	return report, nil
}

// attachLintFindings runs the capability lint over arg's local source tree and
// stores the result in report.Findings, returning any advisory notes for the
// stderr surface (decision D4 addendum). Lint attaches to verify only for a
// local source tree, because verify never executes an artifact (U2) and a
// remote or bundle only argument carries no source to scan: in that case
// report.Findings is left as verify.Run set it (an empty, non nil slice) and a
// single "lint skipped: no local sources" note is returned instead. A local
// directory always reached here through discovery, which already loaded its
// declaration, so the only error attachLintFindings can surface is an
// operational one from a root walk failure, propagated so runMain maps it to
// exit 3; a single unreadable file inside the tree is advisory (M5), skipped
// with a note and never swallowing the completed verification report.
func attachLintFindings(arg string, report *verify.VerificationReport) ([]string, error) {
	info, statErr := os.Stat(arg)
	if statErr != nil || !info.IsDir() {
		return []string{"lint skipped: no local sources"}, nil
	}
	findings, notes, err := lintTree(arg)
	if err != nil {
		return nil, err
	}
	report.Findings = findings
	return notes, nil
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
// the UNDECLARED_ family, the family the strict gate flags. Findings are
// populated by attachLintFindings for a local source tree and empty otherwise.
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
	fmt.Fprintf(&b, "%s  %s\n", verdictWord(code, report), manifest.SubjectName(report.Subject))
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("verify: writing summary: %w", err)
	}
	return nil
}

// verdictWord renders the exit code as the human verdict the summary ends with:
// VERIFIED for a clean pass, FAILED for a failing class failure, and FLAGGED for
// a strict mode UNDECLARED_ flag on an otherwise passing verification. A clean
// exit 0 whose report ran no failing class check at all (every check is
// informational, as for a remote only registry entry) is NOT EVALUATED rather
// than VERIFIED: nothing was actually verified, so claiming a verified verdict
// would overstate what happened.
func verdictWord(code int, report *verify.VerificationReport) string {
	switch code {
	case 0:
		if !anyFailingClassCheckRan(report) {
			return "NOT EVALUATED"
		}
		return "VERIFIED"
	case 2:
		return "FLAGGED"
	default:
		return "FAILED"
	}
}

// anyFailingClassCheckRan reports whether the report carries any failing class
// (non informational) check. When it carries none, no failing class check ever
// ran, so a clean exit reflects "nothing to verify" rather than a passed
// verification.
func anyFailingClassCheckRan(report *verify.VerificationReport) bool {
	for _, c := range report.Checks {
		if !c.Informational {
			return true
		}
	}
	return false
}

// truncateDetail shortens s to at most max runes, appending an ellipsis when it
// had to cut, so the summary table stays one line per check. It counts and
// slices by rune, never by byte, so a multi byte rune is never split into
// invalid UTF-8 at the boundary.
func truncateDetail(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}
