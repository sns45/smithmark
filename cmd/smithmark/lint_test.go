package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sns45/smithmark/internal/golden"
	"github.com/sns45/smithmark/pkg/core/codes"
)

// misdeclaredFixturePath points at the committed misdeclared MCP server fixture
// (spec section 9): a smithmark.yaml declaring zero capabilities beside a
// src/index.ts that calls fetch.
const misdeclaredFixturePath = "../../testdata/misdeclared"

// decodeLintDoc parses the {"findings": [...]} document lint --output json
// writes to stdout.
func decodeLintDoc(t *testing.T, stdout []byte) lintReportDoc {
	t.Helper()
	var doc lintReportDoc
	if err := json.Unmarshal(stdout, &doc); err != nil {
		t.Fatalf("stdout is not a lint findings document: %v\n%s", err, stdout)
	}
	return doc
}

// TestLintMisdeclaredGolden pins the json findings document a lint of the
// misdeclared fixture produces: a single UNDECLARED_NETWORK_EGRESS finding
// naming the fetch call site's file and line. It exits 0 because lint findings
// never fail the command.
func TestLintMisdeclaredGolden(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"lint", "--output", "json", misdeclaredFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	golden.Assert(t, stdout.Bytes(), filepath.Join("testdata", "golden", "lint_misdeclared.json"))

	// Cross check the golden actually carries the mandated finding, so a bad
	// golden regeneration cannot silently pin an empty result.
	doc := decodeLintDoc(t, stdout.Bytes())
	if len(doc.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", doc.Findings)
	}
	if doc.Findings[0].Code != codes.UndeclaredNetworkEgress {
		t.Errorf("code = %q, want %q", doc.Findings[0].Code, codes.UndeclaredNetworkEgress)
	}
	if !strings.HasPrefix(doc.Findings[0].Location, "src/index.ts:") {
		t.Errorf("location = %q, want a src/index.ts:line", doc.Findings[0].Location)
	}
}

// TestLintMisdeclaredSummary proves the human summary carries the severity,
// code, and location for each finding, plus a count line, and still exits 0.
func TestLintMisdeclaredSummary(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"lint", "--output", "summary", misdeclaredFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{codes.UndeclaredNetworkEgress, "high", "src/index.ts", "1 finding(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary does not contain %q:\n%s", want, out)
		}
	}
}

// TestLintMissingDeclarationTreatsAllUndeclared proves a source tree with no
// smithmark.yaml is linted against an empty declaration, so a detected
// capability still fires, and a note on stderr explains the absence.
func TestLintMissingDeclarationTreatsAllUndeclared(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.ts"), []byte("fetch(\"http://x\");\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"lint", "--output", "json", dir}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	doc := decodeLintDoc(t, stdout.Bytes())
	if len(doc.Findings) != 1 || doc.Findings[0].Code != codes.UndeclaredNetworkEgress {
		t.Errorf("findings = %+v, want one UNDECLARED_NETWORK_EGRESS", doc.Findings)
	}
	// json mode suppresses notes on stderr; rerun summary to observe the note.
	stdout.Reset()
	stderr.Reset()
	if code := runMain(d, []string{"lint", "--output", "summary", dir}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no smithmark.yaml") {
		t.Errorf("stderr does not note the missing declaration:\n%s", stderr.String())
	}
}

// TestLintCleanTreeExitsZeroWithEmptyFindings proves a tree with no scannable
// source (the hello-skill fixture, whose only script is a .sh the lint does not
// scan) yields an empty, non nil findings array and exits 0.
func TestLintCleanTreeExitsZeroWithEmptyFindings(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"lint", "--output", "json", skillFixturePath}); code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr.String())
	}
	doc := decodeLintDoc(t, stdout.Bytes())
	if len(doc.Findings) != 0 {
		t.Errorf("findings = %+v, want none for a tree with no scannable sources", doc.Findings)
	}
	// The findings array must render as [] rather than null.
	if !strings.Contains(stdout.String(), "\"findings\": []") {
		t.Errorf("json must carry an empty findings array, got:\n%s", stdout.String())
	}
}

// TestLintInvalidOutputExitsThree proves an unrecognized --output value fails
// closed with exit 3 and the OUTPUT_FORMAT_INVALID code, the same fail closed
// posture verify and registry check take.
func TestLintInvalidOutputExitsThree(t *testing.T) {
	var stdout, stderr bytes.Buffer
	d := newDeps(t, &stdout, &stderr, fakeSBOM{})

	if code := runMain(d, []string{"lint", "--output", "yaml", misdeclaredFixturePath}); code != 3 {
		t.Fatalf("exit = %d, want 3; stderr: %s", code, stderr.String())
	}
	if line := decodeErrLine(t, stderr.Bytes()); line.Code != codes.OutputFormatInvalid {
		t.Errorf("code = %q, want %q", line.Code, codes.OutputFormatInvalid)
	}
}
