// contract_test.go is the cross repo drift alarm decision U5 calls for. It
// pins github.com/sns45/assayward in go.mod (currently an @main pseudo
// version carrying the unreleased v0.2.0 Evidence schema; see go.mod and the
// PR that introduced this pin for the note to switch to the v0.2.0 tag once
// assayward cuts it) and round trips smithmark's Evidence block through
// assayward's own strict assaywardcore.DecodeEvidence, which rejects unknown
// fields AND validates schemaVersion. A version bump of the pinned module is
// a deliberate, loud act: bumping the pin and rerunning this test is how a
// shape drift between the two repos is caught before it ships, rather than
// discovered by a consumer at runtime.
//
// smithmark's subject maps directly onto assayward's kind tagged
// ArtifactRef{Kind, Name, Digest, Source}; no shim is needed. Because
// DecodeEvidence validates schemaVersion in both directions, the drift alarm
// is no longer one directional the way the ImageRef era's manual decode was:
// a field smithmark emits that assayward does not expect is rejected by
// strict decoding, and a schemaVersion smithmark emits that does not match
// assayward's EvidenceSchemaVersion is rejected too.
package verify_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	assaywardcore "github.com/sns45/assayward/pkg/core"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
)

// validSkillReport builds a report from the valid hello-skill fixture via the
// real compose verifier, the same report a caller would hand its bundle bytes
// alongside.
func validSkillReport(t *testing.T) (*verify.VerificationReport, []byte) {
	t.Helper()
	bundleBytes := loadBundle(t, "skill", "valid")
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{bundleBytes},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !checkFor(t, report, codes.SignatureValid).Passed {
		t.Fatalf("fixture must verify for the contract test to exercise a valid attestation")
	}
	return report, bundleBytes
}

func TestEvidenceBlockMatchesAssaywardContract(t *testing.T) {
	report, bundleBytes := validSkillReport(t)
	ref := skillRef(t)

	raw, err := report.EvidenceBlock(bundleBytes)
	if err != nil {
		t.Fatalf("EvidenceBlock: %v", err)
	}

	// Strict decode via the PINNED assayward module's own decoder: an unknown
	// field means our block carries something assayward does not expect, and a
	// mismatched schemaVersion means our block declares a schema assayward's
	// pinned version does not accept. Both are the stronger contract check
	// DecodeEvidence gives us over a hand rolled decode.
	ev, err := assaywardcore.DecodeEvidence(raw)
	if err != nil {
		t.Fatalf("decoding Evidence block via the pinned assayward core.DecodeEvidence: %v", err)
	}

	wantName := manifest.SubjectName(ref)
	if ev.Artifact.Name != wantName {
		t.Errorf("Artifact.Name = %q, want %q", ev.Artifact.Name, wantName)
	}
	if got, want := ev.Artifact.Digest["smithmark-bundle-v1"], ref.Digest["smithmark-bundle-v1"]; got != want {
		t.Errorf("Artifact.Digest[%q] = %q, want %q", "smithmark-bundle-v1", got, want)
	}
	if ev.Artifact.Kind != "skill" {
		t.Errorf("Artifact.Kind = %q, want %q", ev.Artifact.Kind, "skill")
	}
	if ev.SchemaVersion != assaywardcore.EvidenceSchemaVersion {
		t.Errorf("SchemaVersion = %q, want %q", ev.SchemaVersion, assaywardcore.EvidenceSchemaVersion)
	}
	if len(ev.Attestations) != 1 {
		t.Fatalf("Attestations has %d entries, want exactly 1", len(ev.Attestations))
	}
	att := ev.Attestations[0]
	if att.PredicateType != manifest.PredicateType {
		t.Errorf("PredicateType = %q, want %q", att.PredicateType, manifest.PredicateType)
	}
	if !att.Verified {
		t.Error("Verified = false, want true for a validly signed fixture")
	}
	const wantNote = "smithmark agent capability attestation; signature valid"
	if att.SignatureNote != wantNote {
		t.Errorf("SignatureNote = %q, want %q", att.SignatureNote, wantNote)
	}
	if !ev.FetchedAt.Equal(fixedNow) {
		t.Errorf("FetchedAt = %s, want %s", ev.FetchedAt, fixedNow)
	}
	if ev.Identity != nil {
		t.Errorf("Identity = %+v, want nil; smithmark carries no workload identity", ev.Identity)
	}

	// The envelope bytes must parse as a DSSE envelope whose payload equals
	// the statement the fixture signs, extracted independently straight from
	// the same bundle bytes as a cross check against EvidenceBlock's own
	// extraction.
	wantPayload := fixturePayload(t, bundleBytes)

	var gotEnvelope struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(att.Envelope, &gotEnvelope); err != nil {
		t.Fatalf("Envelope bytes did not parse as a DSSE envelope: %v", err)
	}
	gotPayload, err := base64.StdEncoding.DecodeString(gotEnvelope.Payload)
	if err != nil {
		t.Fatalf("base64 decoding Evidence envelope payload: %v", err)
	}
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Errorf("Evidence envelope payload does not equal the statement the fixture signs:\n got: %s\nwant: %s", gotPayload, wantPayload)
	}

	// A structural parse confirms it is the smithmark statement itself, not
	// merely bytes that happen to be equal.
	stmt, err := manifest.ParseStatement(gotPayload)
	if err != nil {
		t.Fatalf("Evidence envelope payload did not parse as a smithmark statement: %v", err)
	}
	if stmt.Subject[0].Name != wantName {
		t.Errorf("parsed statement subject name = %q, want %q", stmt.Subject[0].Name, wantName)
	}
}

// fixturePayload extracts the DSSE payload of a committed sigstore bundle
// directly, independent of EvidenceBlock's own extraction, so the contract
// test has an independent source of truth to compare against.
func fixturePayload(t *testing.T, bundleBytes []byte) []byte {
	t.Helper()
	var doc struct {
		DSSEEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleBytes, &doc); err != nil {
		t.Fatalf("decoding fixture bundle JSON: %v", err)
	}
	payload, err := base64.StdEncoding.DecodeString(doc.DSSEEnvelope.Payload)
	if err != nil {
		t.Fatalf("base64 decoding fixture payload: %v", err)
	}
	return payload
}

func TestEvidenceBlockSignatureNoteReflectsUnverified(t *testing.T) {
	bundleBytes := loadBundle(t, "skill", "tampered")
	report, err := verify.Run(verify.Input{
		Ref:           skillRef(t),
		Bundles:       [][]byte{bundleBytes},
		TrustMaterial: loadTrust(t),
		Now:           fixedNow,
	}, compose.NewVerifier())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if checkFor(t, report, codes.SignatureValid).Passed {
		t.Fatalf("fixture must fail signature verification for this test to exercise the unverified path")
	}

	raw, err := report.EvidenceBlock(bundleBytes)
	if err != nil {
		t.Fatalf("EvidenceBlock: %v", err)
	}
	var ev assaywardcore.Evidence
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("decoding Evidence block: %v", err)
	}
	if ev.Attestations[0].Verified {
		t.Error("Verified = true, want false for a tampered signature")
	}
	const wantNote = "smithmark agent capability attestation; signature invalid"
	if ev.Attestations[0].SignatureNote != wantNote {
		t.Errorf("SignatureNote = %q, want %q", ev.Attestations[0].SignatureNote, wantNote)
	}
}

// TestEvidenceBlockRejectsSubjectWithoutDigest exercises the
// STATEMENT_SUBJECT_INVALID error path: a report subject must carry at least
// one digest to fit assayward's ArtifactRef{Digest DigestSet} shape (U5). The
// report is a normal valid report mutated by hand for this negative case,
// since nothing in the verified pipeline itself can produce a zero digest
// subject.
//
// A subject carrying several digests is no longer a negative case:
// ArtifactRef.Digest is a map, so multiple algorithms are valid and all of
// them must survive into the block, which this test also asserts by decoding
// the result through the pinned assayward core.DecodeEvidence.
func TestEvidenceBlockRejectsSubjectWithoutDigest(t *testing.T) {
	report, bundleBytes := validSkillReport(t)

	report.Subject.Digest = manifest.DigestSet{}
	if _, err := report.EvidenceBlock(bundleBytes); err == nil {
		t.Error("EvidenceBlock did not error on a subject with zero digests")
	} else {
		var coded *codes.Error
		if !errors.As(err, &coded) || coded.Code != codes.StatementSubjectInvalid {
			t.Errorf("error = %v, want a %s coded error", err, codes.StatementSubjectInvalid)
		}
	}

	report.Subject.Digest = manifest.DigestSet{"sha256": "aa", "sha512": "bb"}
	raw, err := report.EvidenceBlock(bundleBytes)
	if err != nil {
		t.Fatalf("EvidenceBlock errored on a subject with two digests, want success: %v", err)
	}
	ev, err := assaywardcore.DecodeEvidence(raw)
	if err != nil {
		t.Fatalf("decoding multi digest Evidence block via the pinned assayward core.DecodeEvidence: %v", err)
	}
	if got, want := ev.Artifact.Digest["sha256"], "aa"; got != want {
		t.Errorf("Artifact.Digest[%q] = %q, want %q", "sha256", got, want)
	}
	if got, want := ev.Artifact.Digest["sha512"], "bb"; got != want {
		t.Errorf("Artifact.Digest[%q] = %q, want %q", "sha512", got, want)
	}
}

func TestEvidenceBlockErrorsOnUnparseableBundle(t *testing.T) {
	report, _ := validSkillReport(t)
	if _, err := report.EvidenceBlock([]byte("not json")); err == nil {
		t.Error("EvidenceBlock did not error on a bundle that is not JSON")
	}
	if _, err := report.EvidenceBlock([]byte(`{"mediaType":"x"}`)); err == nil {
		t.Error("EvidenceBlock did not error on a bundle carrying no dsseEnvelope object")
	}
}
