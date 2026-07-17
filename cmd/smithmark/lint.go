package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// lintOptions holds the parsed lint flag surface (spec 5). lint carries no
// --strict flag: the strict gate is a verify concept (decision D4), and lint
// findings never drive an exit code on their own (spec section 5, lint findings
// alone do not fail; policy is assayward's job).
type lintOptions struct {
	output string
}

// newLintCmd builds the lint command: a static, advisory capability lint over
// an artifact's local source tree (spec 3, U2). It never executes the
// artifact; DetectJS and DetectPython match literal source text only, and the
// declared capabilities come from the on disk smithmark.yaml.
func newLintCmd(d *deps) *cobra.Command {
	o := &lintOptions{}
	cmd := &cobra.Command{
		Use:   "lint <path>",
		Short: "Statically scan an artifact's sources for undeclared capabilities",
		Long: "Statically scan the source tree rooted at <path> for capabilities its " +
			"smithmark.yaml declaration does not cover, and report each as an " +
			"UNDECLARED_ finding. The scan never executes the artifact (U2): it " +
			"matches literal source text only, so it is deliberately advisory, " +
			"detecting obvious undeclared capabilities rather than proving their " +
			"absence. A missing smithmark.yaml is treated as an empty declaration, " +
			"so every detected capability is reported as undeclared. Findings never " +
			"fail the command: lint always exits 0 unless an operational error " +
			"prevents the scan (exit 3). The strict gate that turns findings into a " +
			"nonzero exit lives on verify, not here (decision D4).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLint(d, args[0], o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.output, "output", outputSummary, "output format: summary or json")
	return cmd
}

// runLint executes the lint pipeline for root. Every operational failure
// (an unreadable source tree, a malformed declaration) returns a coded error
// runMain surfaces as exit 3; a completed scan writes its findings to stdout and
// returns nil (exit 0), whether or not it found anything, since lint findings
// never fail the command (spec section 5).
func runLint(d *deps, root string, o *lintOptions) error {
	if err := validateOutputFormat(o.output); err != nil {
		return err
	}
	findings, notes, err := lintTree(root)
	if err != nil {
		return err
	}
	writeAdvisoryNotes(d.Stderr, notes, o.output)
	return writeLintReport(d.Stdout, findings, o.output)
}

// lintReportDoc is the json surface of a lint run: a single object carrying the
// findings array, so the machine surface is a stable, self describing document
// rather than a bare array. Findings is always non nil, so it renders as []
// rather than null even when the scan found nothing.
type lintReportDoc struct {
	Findings []lint.Finding `json:"findings"`
}

// lintTree runs the whole capability lint over the source tree rooted at root
// and returns its findings plus any advisory notes. It is the shared core both
// the lint command and verify's local source gate (decision D4 addendum) call,
// so the two never scan a tree two different ways.
//
// The declared capabilities come from root's smithmark.yaml (U1): when the file
// is absent the declaration is treated as empty, so every detected capability is
// reported as undeclared and a note explains why. Any other load failure (a
// malformed declaration) is returned as an operational error. Sources are walked
// by discover.WalkSources, scanned by both DetectJS and DetectPython, and the
// declared versus detected gap is computed by lint.Gaps. Findings is always non
// nil (lint.Gaps' own convention).
func lintTree(root string) (findings []lint.Finding, notes []string, err error) {
	caps, capNotes, err := declaredCapabilities(root)
	if err != nil {
		return nil, nil, err
	}
	notes = append(notes, capNotes...)

	sources, err := discover.WalkSources(root)
	if err != nil {
		return nil, nil, fmt.Errorf("lint: walking sources at %s: %w", root, err)
	}

	detections := append(lint.DetectJS(sources), lint.DetectPython(sources)...)
	return lint.Gaps(caps, detections), notes, nil
}

// declaredCapabilities loads the CapabilitySet the lint gap engine keys off from
// root's smithmark.yaml. A missing declaration yields an empty CapabilitySet
// (every capability then reads as undeclared) plus a note recording that the
// declaration was absent; any other load error is operational and returned as
// is. The loader validates structure but not capability grammar, so lint.Gaps'
// own blank entry hygiene is what keeps an unvalidated stray entry from masking
// a gap.
func declaredCapabilities(root string) (manifest.CapabilitySet, []string, error) {
	decl, err := discover.LoadDeclared(filepath.Join(root, declFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return manifest.CapabilitySet{}, []string{fmt.Sprintf(
				"no %s declaration found at %s; treating every detected capability as undeclared", declFileName, root)}, nil
		}
		return manifest.CapabilitySet{}, nil, err
	}
	return decl.Manifest.Capabilities, nil, nil
}

// writeAdvisoryNotes prints each advisory note to w (stderr) as a "note:" line,
// but only outside json mode, so stdout stays a clean, parseable report and the
// json golden is never disturbed. It mirrors verify's writeDiscoveryNotes.
func writeAdvisoryNotes(w io.Writer, notes []string, output string) {
	if output == outputJSON {
		return
	}
	for _, n := range notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
}

// writeLintReport emits the findings in the requested format. json is the
// deterministic machine surface (a {"findings": [...]} document, two space
// indent, trailing newline) the golden pins; any other value renders the human
// summary, one line per finding plus a trailing count line.
func writeLintReport(w io.Writer, findings []lint.Finding, output string) error {
	if output == outputJSON {
		b, err := json.MarshalIndent(lintReportDoc{Findings: findings}, "", "  ")
		if err != nil {
			return fmt.Errorf("lint: marshaling findings: %w", err)
		}
		if _, err := w.Write(append(b, '\n')); err != nil {
			return fmt.Errorf("lint: writing findings: %w", err)
		}
		return nil
	}
	return writeLintSummary(w, findings)
}

// writeLintSummary prints one line per finding as "severity code detail
// location", followed by a count line. It is asserted loosely by tests (it must
// carry the codes and the count), never goldened, so its exact spacing is free
// to change.
func writeLintSummary(w io.Writer, findings []lint.Finding) error {
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "%-6s  %-28s  %s  (%s)\n", f.Severity, f.Code, f.Detail, f.Location)
	}
	fmt.Fprintf(&b, "%d finding(s)\n", len(findings))
	if _, err := io.WriteString(w, b.String()); err != nil {
		return fmt.Errorf("lint: writing summary: %w", err)
	}
	return nil
}
