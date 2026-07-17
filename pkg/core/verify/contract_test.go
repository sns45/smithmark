// contract_test.go is the cross repo drift alarm decision U5 calls for. It
// pins github.com/sns45/assayward at its v0.1.0 release tag in go.mod and
// round trips smithmark's Evidence block through assayward's own
// pkg/core.Evidence type with strict decoding (DisallowUnknownFields). A
// version bump of the pinned module is a deliberate, loud act: bumping the
// pin and rerunning this test is how a shape drift between the two repos is
// caught before it ships, rather than discovered by a consumer at runtime.
//
// Until assayward ships a kind tagged ArtifactRef, smithmark's subject is
// mapped into assayward's existing ImageRef{Name, Digest} shape, and the
// artifact kind rides along in SignatureNote prose as a shim this test also
// pins; the M5 gh issue (Task 5.4) removes both the pin's need for a shim and
// this comment once assayward's Evidence widens to accept a kind directly.
//
// Caveat: the drift alarm is one directional. It catches a field smithmark
// emits that assayward v0.1.0 does not expect (strict decode rejects it), but
// not the reverse: a field assayward adds that smithmark never emits decodes
// silently into a zero value here and raises nothing. Closing that gap needs an
// explicit schemaVersion on Evidence so a consumer can pin and detect either
// direction of drift; that is the second request in the Task 5.4 M5 issue.
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

	// Strict decode into the PINNED assayward type: an unknown field here
	// means our block carries something assayward v0.1.0 does not expect.
	var ev assaywardcore.Evidence
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		t.Fatalf("decoding Evidence block into the pinned assayward core.Evidence type: %v", err)
	}

	wantName := manifest.SubjectName(ref)
	if ev.Image.Name != wantName {
		t.Errorf("Image.Name = %q, want %q", ev.Image.Name, wantName)
	}
	wantDigest := "smithmark-bundle-v1:" + ref.Digest["smithmark-bundle-v1"]
	if ev.Image.Digest != wantDigest {
		t.Errorf("Image.Digest = %q, want %q", ev.Image.Digest, wantDigest)
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
	const wantNote = "kind=skill; smithmark agent capability attestation; signature valid"
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
	const wantNote = "kind=skill; smithmark agent capability attestation; signature invalid"
	if ev.Attestations[0].SignatureNote != wantNote {
		t.Errorf("SignatureNote = %q, want %q", ev.Attestations[0].SignatureNote, wantNote)
	}
}

// TestEvidenceBlockRejectsSubjectWithoutExactlyOneDigest exercises the
// STATEMENT_SUBJECT_INVALID error path: a report subject must carry exactly
// one digest to fit assayward's ImageRef{Name, Digest} shape (U5). The report
// is a normal valid report mutated by hand for this negative case, since
// nothing in the verified pipeline itself can produce a zero or multi digest
// subject.
func TestEvidenceBlockRejectsSubjectWithoutExactlyOneDigest(t *testing.T) {
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
	if _, err := report.EvidenceBlock(bundleBytes); err == nil {
		t.Error("EvidenceBlock did not error on a subject with two digests")
	} else {
		var coded *codes.Error
		if !errors.As(err, &coded) || coded.Code != codes.StatementSubjectInvalid {
			t.Errorf("error = %v, want a %s coded error", err, codes.StatementSubjectInvalid)
		}
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
