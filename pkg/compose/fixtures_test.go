//go:build !wasip1

package compose

// This test is the CI guard that the committed signed verification fixtures
// under testdata/signature stay honest. It loads each committed bundle,
// verifies (or, for the tampered variant, refuses) the DSSE signature against
// the committed public key using the same sigstore primitives the sign_native
// round trip test uses, and asserts the payload statement parses (or fails to
// parse) exactly as each variant intends. The fixtures themselves are produced
// by the deterministic generation kit at testdata/gen; run `go run
// ./testdata/gen` from the repository root to regenerate them.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// Fixture layout, relative to this package. The generation kit writes the key
// pair and both subject directories under testdata/signature.
const (
	fixtureSignatureDir = "../../testdata/signature"
	fixturePubKeyPath   = fixtureSignatureDir + "/test-signing-key-pub.pem"
	fixtureSkillRoot    = "../../testdata/skills/hello-skill"
)

// The fabricated npm subject digests these tests expect. They must match the
// constants the generation kit (testdata/gen/gen.go) signs into the fixtures;
// a drift on either side turns this guard red, which is the point. The valid
// digest is the subject the npm fixtures attest; the mismatch digest is the
// deliberately wrong subject the digest-mismatch variant carries.
const (
	fakeNPMDigestHex   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fakeNPMMismatchHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	predicateTypeV2    = "https://in8.sh/attestation/agent-capability/v2"
)

// loadFixturePubKey loads the committed test signing public key as an ECDSA
// public key.
func loadFixturePubKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	pemBytes, err := os.ReadFile(fixturePubKeyPath)
	if err != nil {
		t.Fatalf("reading committed public key (run `go run ./testdata/gen` to generate fixtures): %v", err)
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		t.Fatalf("parsing committed public key: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("committed public key is %T, want *ecdsa.PublicKey", pub)
	}
	return ecPub
}

// loadFixtureEnvelope loads a committed fixture bundle and returns its DSSE
// envelope.
func loadFixtureEnvelope(t *testing.T, subject, variant string) *protodsse.Envelope {
	t.Helper()
	path := filepath.Join(fixtureSignatureDir, subject, variant+".sigstore.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s (run `go run ./testdata/gen`): %v", path, err)
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("fixture %s is not valid protojson: %v", path, err)
	}
	env := pb.GetDsseEnvelope()
	if env == nil {
		t.Fatalf("fixture %s carries no DSSE envelope", path)
	}
	return env
}

// dsseSignatureVerifies reports whether the envelope's single DSSE signature
// verifies against pub over the sigstore reconstructed pre-auth encoding, the
// exact bytes signWithKey signed. It never hand rolls ecdsa.Verify.
func dsseSignatureVerifies(t *testing.T, pub *ecdsa.PublicKey, env *protodsse.Envelope) bool {
	t.Helper()
	sigs := env.GetSignatures()
	if len(sigs) != 1 {
		t.Fatalf("envelope carries %d signatures, want 1", len(sigs))
	}
	pae := (&sign.DSSEData{Data: env.GetPayload(), PayloadType: env.GetPayloadType()}).PreAuthEncoding()
	verifier, err := sigsig.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		t.Fatalf("loading sigstore ECDSA verifier: %v", err)
	}
	return verifier.VerifySignature(bytes.NewReader(sigs[0].GetSig()), bytes.NewReader(pae)) == nil
}

// expectedSkillDigest recomputes the hello-skill fixture's true canonical
// bundle digest through the real discovery and bundle path, so the guard tracks
// the skill's on disk content rather than a hard coded literal that could
// silently drift from it.
func expectedSkillDigest(t *testing.T) manifest.DigestSet {
	t.Helper()
	decl, err := discover.LoadDeclared(filepath.Join(fixtureSkillRoot, "smithmark.yaml"))
	if err != nil {
		t.Fatalf("loading hello-skill declaration: %v", err)
	}
	files, _, _, err := discover.WalkSkill(fixtureSkillRoot, decl.Executables)
	if err != nil {
		t.Fatalf("walking hello-skill: %v", err)
	}
	dg, err := bundle.Digest(files)
	if err != nil {
		t.Fatalf("digesting hello-skill bundle: %v", err)
	}
	ds, err := manifest.SubjectDigestFromBundle(dg)
	if err != nil {
		t.Fatalf("converting hello-skill bundle digest: %v", err)
	}
	return ds
}

// TestSignedFixturesAreHonest is the CI guard over the committed fixtures. For
// both subjects (the hello-skill fixture and the fake-caller npm identity) it
// checks the five variants behave exactly as their names promise.
func TestSignedFixturesAreHonest(t *testing.T) {
	pub := loadFixturePubKey(t)

	cases := []struct {
		subject      string
		trueDigest   manifest.DigestSet
		wrongDigest  manifest.DigestSet
		subjectMatch func(got manifest.DigestSet) bool
	}{
		{
			subject:     "skill",
			trueDigest:  expectedSkillDigest(t),
			wrongDigest: manifest.DigestSet{"smithmark-bundle-v1": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
		},
		{
			subject:     "npm",
			trueDigest:  manifest.DigestSet{"sha512": fakeNPMDigestHex},
			wrongDigest: manifest.DigestSet{"sha512": fakeNPMMismatchHex},
		},
	}

	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			// valid: signature verifies, statement parses, predicate validates,
			// and the subject digest is the true one.
			validEnv := loadFixtureEnvelope(t, tc.subject, "valid")
			if !dsseSignatureVerifies(t, pub, validEnv) {
				t.Fatal("valid fixture signature did not verify against the committed public key")
			}
			stmt, err := manifest.ParseStatement(validEnv.GetPayload())
			if err != nil {
				t.Fatalf("valid fixture statement did not parse: %v", err)
			}
			if issues := stmt.Predicate.Validate(); len(issues) != 0 {
				t.Fatalf("valid fixture predicate is not valid: %v", issues)
			}
			if !digestSetEqual(stmt.Subject[0].Digest, tc.trueDigest) {
				t.Fatalf("valid fixture subject digest = %v, want the true digest %v", stmt.Subject[0].Digest, tc.trueDigest)
			}

			// tampered: same payload as valid, but the flipped signature byte
			// means it must no longer verify.
			tamperedEnv := loadFixtureEnvelope(t, tc.subject, "tampered")
			if !bytes.Equal(tamperedEnv.GetPayload(), validEnv.GetPayload()) {
				t.Fatal("tampered fixture payload differs from valid; only the signature should change")
			}
			if dsseSignatureVerifies(t, pub, tamperedEnv) {
				t.Fatal("tampered fixture signature verified; the byte flip did not take")
			}

			// digest-mismatch: signature verifies, statement parses, but the
			// subject digest is the deliberately wrong one, not the true digest.
			mismatchEnv := loadFixtureEnvelope(t, tc.subject, "digest-mismatch")
			if !dsseSignatureVerifies(t, pub, mismatchEnv) {
				t.Fatal("digest-mismatch fixture signature did not verify; it must be validly signed over the wrong subject")
			}
			mismatchStmt, err := manifest.ParseStatement(mismatchEnv.GetPayload())
			if err != nil {
				t.Fatalf("digest-mismatch fixture statement did not parse: %v", err)
			}
			if digestSetEqual(mismatchStmt.Subject[0].Digest, tc.trueDigest) {
				t.Fatal("digest-mismatch fixture subject digest matches the true digest; it should not")
			}
			if !digestSetEqual(mismatchStmt.Subject[0].Digest, tc.wrongDigest) {
				t.Fatalf("digest-mismatch fixture subject digest = %v, want the wrong digest %v", mismatchStmt.Subject[0].Digest, tc.wrongDigest)
			}

			// schema-invalid: signature verifies, statement parses structurally,
			// but the predicate fails semantic validation on its schemaVersion.
			schemaEnv := loadFixtureEnvelope(t, tc.subject, "schema-invalid")
			if !dsseSignatureVerifies(t, pub, schemaEnv) {
				t.Fatal("schema-invalid fixture signature did not verify")
			}
			schemaStmt, err := manifest.ParseStatement(schemaEnv.GetPayload())
			if err != nil {
				t.Fatalf("schema-invalid fixture statement did not parse structurally: %v", err)
			}
			issues := schemaStmt.Predicate.Validate()
			if !hasIssueCode(issues, codes.ManifestSchemaVersionUnsupported) {
				t.Fatalf("schema-invalid fixture predicate did not report %s; issues: %v", codes.ManifestSchemaVersionUnsupported, issues)
			}

			// unknown-predicate: signature verifies, the payload carries the v2
			// predicate type, and strict statement parsing rejects it on that.
			unknownEnv := loadFixtureEnvelope(t, tc.subject, "unknown-predicate")
			if !dsseSignatureVerifies(t, pub, unknownEnv) {
				t.Fatal("unknown-predicate fixture signature did not verify")
			}
			var probe struct {
				PredicateType string `json:"predicateType"`
			}
			if err := json.Unmarshal(unknownEnv.GetPayload(), &probe); err != nil {
				t.Fatalf("unknown-predicate fixture payload is not JSON: %v", err)
			}
			if probe.PredicateType != predicateTypeV2 {
				t.Fatalf("unknown-predicate fixture predicateType = %q, want %q", probe.PredicateType, predicateTypeV2)
			}
			if _, err := manifest.ParseStatement(unknownEnv.GetPayload()); err == nil {
				t.Fatal("unknown-predicate fixture parsed cleanly; strict parsing must reject the v2 predicate type")
			}
		})
	}
}

// digestSetEqual reports whether two digest sets carry the same keys and
// values.
func digestSetEqual(a, b manifest.DigestSet) bool {
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

// hasIssueCode reports whether issues contains one with the given code.
func hasIssueCode(issues []manifest.Issue, code string) bool {
	for _, is := range issues {
		if is.Code == code {
			return true
		}
	}
	return false
}
