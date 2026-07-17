package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/lint"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
)

// Committed Task 6.1 dogfood fixtures, relative to this package (cmd/smithmark):
// the two real first party server snapshots plus the deliberately misdeclared
// fixture, each with an honest smithmark.yaml declaration and a signed capability
// attestation, and the throwaway dogfood public key every bundle verifies against.
const (
	dogfoodServersDir = "../../testdata/servers"
	dogfoodTrustRoot  = dogfoodServersDir + "/dogfood-signing-key-pub.pem"
)

// dogfoodServer is one committed dogfood attestation under test. digestHex mirrors
// the fabricated subject digest testdata/servers/gen builds each subject with (a
// visibly synthetic repeating npm sha512), so the test asserts the committed
// bundle carries exactly that digest, not merely a self consistent one. If the gen
// kit's digests change, these must change in the same commit.
type dogfoodServer struct {
	name         string
	version      string
	digestHex    string
	wantFindings []string // lint codes expected over its src; empty means it lints clean
}

func dogfoodServers() []dogfoodServer {
	return []dogfoodServer{
		{name: "better-call-claude", version: "3.1.1", digestHex: strings.Repeat("bcc0", 32)},
		{name: "dear-claude", version: "1.1.0", digestHex: strings.Repeat("dc1a", 32)},
		{name: "misdeclared-server", version: "1.0.0", digestHex: strings.Repeat("bad0", 32), wantFindings: []string{codes.UndeclaredNetworkEgress}},
	}
}

// TestDogfoodAttestationsVerifyOffline is the Task 6.1 honesty pin. For every
// committed first party server attestation it proves, with no network and without
// executing the artifact (U2): the bundle verifies offline against the committed
// throwaway dogfood public key; its subject carries the expected fabricated
// digest; its predicate validates; and the capability lint over its src produces
// the expected finding set, empty for the two honestly declared real servers and
// exactly UNDECLARED_NETWORK_EGRESS for the deliberately misdeclared fixture. It
// also asserts the completed D4 exit contract: a passing verification exits 0
// without --strict, and exits 2 under --strict only when an UNDECLARED_ finding is
// present, which is exactly how the Task 6.5 hook blocks a validly signed server
// on the capability gap alone.
func TestDogfoodAttestationsVerifyOffline(t *testing.T) {
	trust, err := os.ReadFile(dogfoodTrustRoot)
	if err != nil {
		t.Fatalf("reading committed dogfood trust root: %v", err)
	}

	for _, s := range dogfoodServers() {
		t.Run(s.name, func(t *testing.T) {
			dir := filepath.Join(dogfoodServersDir, s.name)
			bundle, err := os.ReadFile(filepath.Join(dir, "attestation.sigstore.json"))
			if err != nil {
				t.Fatalf("reading committed attestation: %v", err)
			}

			ref := manifest.ArtifactRef{
				Kind:    manifest.KindMCPServer,
				Name:    s.name,
				Version: s.version,
				Source:  manifest.SourceNPM,
				Digest:  manifest.DigestSet{"sha512": s.digestHex},
			}
			report, err := verify.Run(verify.Input{
				Ref:           ref,
				Bundles:       [][]byte{bundle},
				TrustMaterial: trust,
				Now:           fixedNow,
			}, compose.NewVerifier())
			if err != nil {
				t.Fatalf("verify.Run: %v", err)
			}

			// Real offline signature verification against the committed dogfood key,
			// the expected subject digest, and a valid predicate.
			if !findCheck(t, report, codes.SignatureValid).Passed {
				t.Errorf("SIGNATURE_VALID did not pass against the committed dogfood public key; detail: %s",
					findCheck(t, report, codes.SignatureValid).Detail)
			}
			if !findCheck(t, report, codes.SubjectDigestMatch).Passed {
				t.Errorf("SUBJECT_DIGEST_MATCH did not pass; the committed bundle does not carry the expected digest; detail: %s",
					findCheck(t, report, codes.SubjectDigestMatch).Detail)
			}
			if !findCheck(t, report, codes.ManifestSchemaValid).Passed {
				t.Errorf("MANIFEST_SCHEMA_VALID did not pass; the committed predicate is invalid; detail: %s",
					findCheck(t, report, codes.ManifestSchemaValid).Detail)
			}

			// Capability lint over the src, attached exactly as verify attaches it.
			findings, _, err := lintTree(dir)
			if err != nil {
				t.Fatalf("lintTree over %s: %v", dir, err)
			}
			// Stitch the lint findings onto the report exactly as verify does. This
			// is a stand in until the assayward Evidence block carries lint findings
			// (assayward#1); today findings live only on smithmark's own report.
			report.Findings = findings
			assertFindingCodes(t, findings, s.wantFindings)

			// D4 exit contract: passing verification exits 0 without --strict; with
			// --strict it exits 2 only when an UNDECLARED_ finding is present.
			if got := verifyExitCode(report, false); got != 0 {
				t.Errorf("verifyExitCode(strict=false) = %d, want 0", got)
			}
			wantStrict := 0
			if len(s.wantFindings) > 0 {
				wantStrict = 2
			}
			if got := verifyExitCode(report, true); got != wantStrict {
				t.Errorf("verifyExitCode(strict=true) = %d, want %d", got, wantStrict)
			}
		})
	}
}

// TestDogfoodMisdeclaredServerBlocksUnderStrict pins the Task 6.5 obligation
// directly: the misdeclared server is a real, validly signed MCP server whose only
// defect is an under declared capability set. A plain verify passes it (exit 0),
// the lint over its src reports UNDECLARED_NETWORK_EGRESS, and --strict turns that
// finding into an exit 2, so the hook can block a signed server on the capability
// gap the signature cannot catch.
func TestDogfoodMisdeclaredServerBlocksUnderStrict(t *testing.T) {
	trust, err := os.ReadFile(dogfoodTrustRoot)
	if err != nil {
		t.Fatalf("reading committed dogfood trust root: %v", err)
	}
	dir := filepath.Join(dogfoodServersDir, "misdeclared-server")
	bundle, err := os.ReadFile(filepath.Join(dir, "attestation.sigstore.json"))
	if err != nil {
		t.Fatalf("reading committed attestation: %v", err)
	}

	ref := manifest.ArtifactRef{
		Kind:    manifest.KindMCPServer,
		Name:    "misdeclared-server",
		Version: "1.0.0",
		Source:  manifest.SourceNPM,
		Digest:  manifest.DigestSet{"sha512": strings.Repeat("bad0", 32)},
	}
	report, err := verify.Run(verify.Input{
		Ref:           ref,
		Bundles:       [][]byte{bundle},
		TrustMaterial: trust,
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("verify.Run: %v", err)
	}
	if verify.FailingChecksFailed(report) {
		t.Fatal("a validly signed misdeclared server must pass every failing class check; only the capability declaration is dishonest")
	}

	findings, _, err := lintTree(dir)
	if err != nil {
		t.Fatalf("lintTree: %v", err)
	}
	// Stand in until assayward Evidence carries lint findings (assayward#1).
	report.Findings = findings
	if !hasFinding(report, codes.UndeclaredNetworkEgress) {
		t.Fatalf("lint over the misdeclared server src carries no %s finding; findings: %+v", codes.UndeclaredNetworkEgress, findings)
	}

	if got := verifyExitCode(report, false); got != 0 {
		t.Errorf("plain verify of the misdeclared server = %d, want 0 (crypto is honest)", got)
	}
	if got := verifyExitCode(report, true); got != 2 {
		t.Errorf("strict verify of the misdeclared server = %d, want 2 (capability gap blocks it)", got)
	}
}

// assertFindingCodes asserts the multiset of finding codes equals want, order
// independent, so a clean server asserts an empty set and the misdeclared server
// asserts exactly its one expected code.
func assertFindingCodes(t *testing.T, findings []lint.Finding, want []string) {
	t.Helper()
	got := make([]string, len(findings))
	for i, f := range findings {
		got[i] = f.Code
	}
	sort.Strings(got)
	sorted := append([]string(nil), want...)
	sort.Strings(sorted)
	if strings.Join(got, ",") != strings.Join(sorted, ",") {
		t.Errorf("lint finding codes = %v, want %v", got, sorted)
	}
}
