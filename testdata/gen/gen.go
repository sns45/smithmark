// Command gen is the deterministic signed fixture generation kit for
// smithmark's verification phase (Task 3.1). It writes the committed inputs
// under testdata/signature that every Phase 3 verification test consumes, so
// CI never needs a network, a Fulcio, or a Rekor to exercise the offline key
// based verification path.
//
// It lives under testdata/ on purpose: the Go toolchain excludes any directory
// named testdata from `go build ./...`, `go vet ./...`, and `go test ./...`, so
// this main package is never compiled by the ordinary build. It is invoked
// explicitly instead:
//
//	go run ./testdata/gen               # regenerate every fixture (requires the committed key)
//	go run ./testdata/gen --check       # verify the committed fixtures stay honest
//	go run ./testdata/gen --bootstrap   # mint a fresh throwaway key, then regenerate
//
// All three commands run from the repository root. Regeneration refuses to run
// when no key is committed unless --bootstrap is passed, so a missing key never
// silently swaps the trust anchor out from under the committed fixtures.
//
// DETERMINISM: the statement payloads are fully deterministic. The clock is the
// fixed constant fixedGeneratedAt, the generator identity is fixed, the skill
// subject digest is the real canonical bundle digest of testdata/skills/
// hello-skill, and the npm subject digest is a fabricated fixed hex string. The
// one thing that is NOT byte reproducible is the ECDSA signature: ECDSA signing
// draws a per signature nonce from crypto/rand, so every regeneration produces
// new signature bytes over identical payloads. That is expected and documented
// in testdata/README.md; --check is the guard that the committed bundles still
// verify against the committed public key and carry the payloads each variant
// promises, rather than a byte for byte diff.
//
// THROWAWAY KEY: the signing key this kit generates and commits at
// testdata/signature/test-signing-key.pem is a test only, throwaway key. It
// must never sign a real artifact. See testdata/README.md.
package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// Committed paths, all relative to the repository root (the working directory
// `go run ./testdata/gen` runs in).
const (
	signatureDir = "testdata/signature"
	privKeyPath  = signatureDir + "/test-signing-key.pem"
	pubKeyPath   = signatureDir + "/test-signing-key-pub.pem"
	skillRoot    = "testdata/skills/hello-skill"
)

// Fixed generator identity and clock stamped onto every generated manifest, so
// the statement payloads never depend on the wall clock or the build.
const (
	generatorName    = "smithmark"
	generatorVersion = "test"
)

// fixedGeneratedAt is the pinned generatedAt for every fixture manifest
// (2026-07-16T00:00:00Z). Using a constant keeps the payloads reproducible.
var fixedGeneratedAt = time.Date(2026, 7, 16, 0, 0, 0, 0, time.UTC)

// The fabricated npm subject digests. The npm subject is a synthetic identity
// (fake-caller 1.0.0), so no real tarball exists: verification consumes the
// bundle plus an expected digest, and these fixed hex strings stand in for that
// digest. trueDigest is what the valid npm fixtures attest; mismatchDigest is
// the deliberately wrong subject the digest-mismatch variant carries. Both are
// 128 lowercase hex characters, the shape of an npm sha512 integrity digest.
const (
	fakeNPMName        = "fake-caller"
	fakeNPMVersion     = "1.0.0"
	fakeNPMDigestHex   = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	fakeNPMMismatchHex = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
)

// skillWrongHex is the deliberately wrong 64 hex character bundle digest the
// skill digest-mismatch variant carries as its subject, distinct from the true
// canonical bundle digest of the hello-skill directory.
const skillWrongHex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// predicateTypeV2 is a predicate type this build does not understand, used for
// the unknown-predicate variant. The build understands only
// manifest.PredicateType (…/agent-capability/v1).
const predicateTypeV2 = "https://in8.sh/attestation/agent-capability/v2"

// variant file names, all suffixed .sigstore.json under the subject directory.
const (
	variantValid            = "valid"
	variantTampered         = "tampered"
	variantDigestMismatch   = "digest-mismatch"
	variantSchemaInvalid    = "schema-invalid"
	variantUnknownPredicate = "unknown-predicate"
)

func main() {
	log.SetFlags(0)
	check := flag.Bool("check", false, "verify the committed fixtures still verify and carry the expected payloads, instead of regenerating them")
	bootstrap := flag.Bool("bootstrap", false, "mint a fresh throwaway signing key when none is committed; this replaces the committed public key and every committed bundle")
	flag.Parse()

	if *check && *bootstrap {
		log.Fatalf("--check and --bootstrap are mutually exclusive: --check only reads the committed fixtures, while --bootstrap mints a new key and rewrites them")
	}

	specs := []subjectSpec{buildSkillSubject(), buildNPMSubject()}

	if *check {
		runCheck(specs)
		return
	}

	loadOrBootstrapKey(*bootstrap)
	ctx := context.Background()
	signer := compose.NewSigner()
	for _, spec := range specs {
		generate(ctx, signer, spec)
	}
	log.Printf("wrote fixtures for %d subjects under %s", len(specs), signatureDir)
	log.Printf("note: ECDSA signatures are randomized, so bundle bytes differ each run; payloads are identical. Run `go run ./testdata/gen --check` to verify.")
}

// subjectSpec is one attestation subject and everything the generator and the
// checker need to build and validate its fixture set.
type subjectSpec struct {
	name        string                       // subdirectory under signatureDir: "skill" or "npm"
	manifest    *manifest.CapabilityManifest // the fully valid, stamped predicate
	trueDigest  manifest.DigestSet           // the subject digest the valid fixtures attest
	wrongDigest manifest.DigestSet           // the wrong subject digest the digest-mismatch variant carries
}

// buildSkillSubject builds the hello-skill subject exactly as the attest
// pipeline does: load the declaration, walk the skill directory, fill the skill
// surface, stamp the fixed clock and generator, and compute the real canonical
// bundle digest.
func buildSkillSubject() subjectSpec {
	decl, err := discover.LoadDeclared(filepath.Join(skillRoot, "smithmark.yaml"))
	must("loading hello-skill declaration", err)
	files, surface, info, err := discover.WalkSkill(skillRoot, decl.Executables)
	must("walking hello-skill", err)

	m := decl.Manifest
	m.Skill.EntryDigest = surface.EntryDigest
	m.Skill.Scripts = surface.Scripts
	if info.Version != "" {
		m.Artifact.Version = info.Version
	}
	m.GeneratedAt = fixedGeneratedAt
	m.Generator = manifest.GeneratorInfo{Name: generatorName, Version: generatorVersion}
	if issues := m.Validate(); len(issues) > 0 {
		log.Fatalf("hello-skill manifest did not validate: %v", issues)
	}

	dg, err := bundle.Digest(files)
	must("digesting hello-skill bundle", err)
	trueDigest, err := manifest.SubjectDigestFromBundle(dg)
	must("converting hello-skill bundle digest", err)

	return subjectSpec{
		name:        "skill",
		manifest:    m,
		trueDigest:  trueDigest,
		wrongDigest: manifest.DigestSet{"smithmark-bundle-v1": skillWrongHex},
	}
}

// buildNPMSubject builds the synthetic fake-caller npm subject: a minimal but
// fully valid mcp-server manifest whose subject digest is a fabricated fixed
// hex string rather than a real tarball digest.
func buildNPMSubject() subjectSpec {
	m := &manifest.CapabilityManifest{
		SchemaVersion: manifest.SchemaVersion,
		Artifact: manifest.PredicateArtifact{
			Kind:    manifest.KindMCPServer,
			Name:    fakeNPMName,
			Version: fakeNPMVersion,
			Source:  manifest.SourceNPM,
		},
		MCP: &manifest.MCPSurface{
			Tools:      []manifest.ToolDecl{},
			Resources:  []string{},
			Prompts:    []string{},
			Transports: []string{"stdio"},
		},
		Capabilities: manifest.CapabilitySet{
			NetworkEgress: []manifest.EgressRule{},
			Filesystem:    []manifest.FSRule{},
			Exec:          []manifest.ExecRule{},
			Env:           []string{},
			Secrets:       []string{},
		},
		GeneratedAt: fixedGeneratedAt,
		Generator:   manifest.GeneratorInfo{Name: generatorName, Version: generatorVersion},
	}
	if issues := m.Validate(); len(issues) > 0 {
		log.Fatalf("fake-caller manifest did not validate: %v", issues)
	}
	return subjectSpec{
		name:        "npm",
		manifest:    m,
		trueDigest:  manifest.DigestSet{"sha512": fakeNPMDigestHex},
		wrongDigest: manifest.DigestSet{"sha512": fakeNPMMismatchHex},
	}
}

// generate writes all five fixture variants for one subject.
func generate(ctx context.Context, signer compose.Signer, spec subjectSpec) {
	ref := manifest.ArtifactRef{
		Kind:    spec.manifest.Artifact.Kind,
		Name:    spec.manifest.Artifact.Name,
		Version: spec.manifest.Artifact.Version,
		Digest:  spec.trueDigest,
		Source:  spec.manifest.Artifact.Source,
	}

	// valid: a correctly signed bundle over the canonical statement.
	validStmt, err := manifest.NewStatement(ref, spec.manifest)
	must(spec.name+": assembling valid statement", err)
	validBundle := signOrDie(ctx, signer, validStmt)
	writeFixture(spec.name, variantValid, validBundle)

	// tampered: the valid bundle with one byte of the DSSE signature flipped, so
	// the payload is byte identical to valid but the signature no longer
	// verifies.
	tampered, err := tamperSignature(validBundle)
	must(spec.name+": tampering signature", err)
	writeFixture(spec.name, variantTampered, tampered)

	// digest-mismatch: validly signed, but the subject digest is the wrong one.
	// The digest is altered before signing, so the signature verifies while the
	// subject is wrong.
	wrongRef := ref
	wrongRef.Digest = spec.wrongDigest
	mismatchStmt, err := manifest.NewStatement(wrongRef, spec.manifest)
	must(spec.name+": assembling digest-mismatch statement", err)
	writeFixture(spec.name, variantDigestMismatch, signOrDie(ctx, signer, mismatchStmt))

	// schema-invalid: validly signed over a statement whose predicate fails
	// Validate. The statement is assembled by hand to bypass NewStatement, which
	// would reject the 9.9.9 schemaVersion. Only schemaVersion changes; the
	// subject keeps the true digest.
	schemaManifest := *spec.manifest
	schemaManifest.SchemaVersion = "9.9.9"
	schemaStmt := &manifest.Statement{
		Type:          validStmt.Type,
		Subject:       validStmt.Subject,
		PredicateType: manifest.PredicateType,
		Predicate:     &schemaManifest,
	}
	writeFixture(spec.name, variantSchemaInvalid, signOrDie(ctx, signer, schemaStmt))

	// unknown-predicate: validly signed over a statement whose predicateType is
	// a version this build does not understand. Assembled by hand so NewStatement
	// does not stamp the v1 predicate type. The predicate itself stays valid.
	unknownStmt := &manifest.Statement{
		Type:          validStmt.Type,
		Subject:       validStmt.Subject,
		PredicateType: predicateTypeV2,
		Predicate:     spec.manifest,
	}
	writeFixture(spec.name, variantUnknownPredicate, signOrDie(ctx, signer, unknownStmt))
}

// signOrDie canonicalizes and signs a statement with the committed key,
// returning the serialized sigstore bundle. It fatals on any error.
func signOrDie(ctx context.Context, signer compose.Signer, stmt *manifest.Statement) []byte {
	canonical, err := stmt.Canonical()
	must("canonicalizing statement", err)
	sb, err := signer.SignStatement(ctx, canonical, compose.SignOptions{KeyPath: privKeyPath})
	must("signing statement", err)
	return sb.Bundle
}

// tamperSignature parses the bundle JSON, base64 decodes the single DSSE
// signature, flips one byte of it, encodes it again, and marshals the bundle
// back to JSON. The result is valid JSON with the payload untouched and only
// the signature corrupted.
func tamperSignature(validBundle []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(validBundle, &doc); err != nil {
		return nil, fmt.Errorf("parsing bundle JSON: %w", err)
	}
	env, ok := doc["dsseEnvelope"].(map[string]any)
	if !ok {
		return nil, errors.New("bundle carries no dsseEnvelope object")
	}
	sigsAny, ok := env["signatures"].([]any)
	if !ok || len(sigsAny) == 0 {
		return nil, errors.New("dsseEnvelope carries no signatures")
	}
	sig0, ok := sigsAny[0].(map[string]any)
	if !ok {
		return nil, errors.New("signature entry is not a JSON object")
	}
	sigB64, ok := sig0["sig"].(string)
	if !ok {
		return nil, errors.New("signature sig field is not a string")
	}
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decoding signature: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("signature is empty")
	}
	// Flip one bit of a middle byte so the signature stays the same length but
	// no longer verifies.
	raw[len(raw)/2] ^= 0x01
	sig0["sig"] = base64.StdEncoding.EncodeToString(raw)
	return json.Marshal(doc)
}

// writeFixture writes one bundle to testdata/signature/<subject>/<variant>.sigstore.json.
func writeFixture(subject, variant string, data []byte) {
	dir := filepath.Join(signatureDir, subject)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("creating %s: %v", dir, err)
	}
	path := filepath.Join(dir, variant+".sigstore.json")
	out := append(bytes.Clone(data), '\n')
	if err := os.WriteFile(path, out, 0o644); err != nil {
		log.Fatalf("writing %s: %v", path, err)
	}
	log.Printf("wrote %s", path)
}

// loadOrBootstrapKey ensures the committed test signing key pair exists before
// regeneration signs anything. When the private key is already committed it is
// loaded and never regenerated, so regeneration reuses the same key and the
// committed public key keeps verifying every bundle. When no key is committed
// the behavior depends on bootstrap: without it, this refuses and exits, naming
// the expected path and the flag, so a missing key never silently mints a new
// trust anchor and resigns every fixture; with it, a fresh ECDSA P-256 key is
// minted after a loud warning. The public key is always derived afresh from the
// private key and written, so the two can never drift apart.
func loadOrBootstrapKey(bootstrap bool) {
	priv, err := readPrivateKey(privKeyPath)
	switch {
	case err == nil:
		writePublicKey(priv)
		return
	case errors.Is(err, os.ErrNotExist):
		// fall through to the bootstrap decision
	default:
		log.Fatalf("reading committed signing key %s: %v", privKeyPath, err)
	}

	if !bootstrap {
		log.Fatalf("no committed signing key at %s; refusing to mint one silently. Pass --bootstrap to generate a fresh throwaway key, which replaces the committed public key and resigns every committed bundle.", privKeyPath)
	}

	log.Printf("WARNING: --bootstrap is minting a fresh throwaway signing key at %s.", privKeyPath)
	log.Printf("WARNING: this replaces the committed public key %s and resigns every committed bundle; the old public key will no longer verify any of them.", pubKeyPath)

	if err := os.MkdirAll(signatureDir, 0o755); err != nil {
		log.Fatalf("creating %s: %v", signatureDir, err)
	}
	fresh, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must("generating test signing key", err)
	der, err := x509.MarshalPKCS8PrivateKey(fresh)
	must("marshalling private key", err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(privKeyPath, privPEM, 0o600); err != nil {
		log.Fatalf("writing %s: %v", privKeyPath, err)
	}
	log.Printf("minted a new throwaway test signing key at %s", privKeyPath)
	writePublicKey(fresh)
}

// readPrivateKey reads and parses a PEM private key, returning an ECDSA key.
func readPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, cryptoutils.SkipPassword)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is %T, want an ECDSA private key", path, key)
	}
	return ec, nil
}

// writePublicKey derives and writes the PKIX public key PEM for verifiers.
func writePublicKey(priv *ecdsa.PrivateKey) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(priv.Public())
	must("marshalling public key", err)
	if err := os.WriteFile(pubKeyPath, pemBytes, 0o644); err != nil {
		log.Fatalf("writing %s: %v", pubKeyPath, err)
	}
}

// runCheck verifies every committed fixture against the committed public key
// and asserts each variant carries the payload it promises. It exits non zero
// on the first failure so CI and a maintainer see a clear signal.
func runCheck(specs []subjectSpec) {
	pub, err := readPublicKey(pubKeyPath)
	must("reading committed public key", err)
	for _, spec := range specs {
		if err := checkSubject(spec, pub); err != nil {
			log.Fatalf("fixture check failed: %v", err)
		}
		log.Printf("ok: %s fixtures verify and carry the expected payloads", spec.name)
	}
	log.Printf("all committed fixtures are honest")
}

// checkSubject runs the same battery of assertions the CI guard test runs, for
// one subject.
func checkSubject(spec subjectSpec, pub *ecdsa.PublicKey) error {
	// valid: verifies, parses, predicate valid, true subject digest.
	valid, err := loadEnvelope(spec.name, variantValid)
	if err != nil {
		return err
	}
	if !signatureVerifies(pub, valid) {
		return fmt.Errorf("%s/valid: signature did not verify against the committed public key", spec.name)
	}
	stmt, err := manifest.ParseStatement(valid.GetPayload())
	if err != nil {
		return fmt.Errorf("%s/valid: statement did not parse: %w", spec.name, err)
	}
	if issues := stmt.Predicate.Validate(); len(issues) > 0 {
		return fmt.Errorf("%s/valid: predicate is not valid: %v", spec.name, issues)
	}
	if !digestSetEqual(stmt.Subject[0].Digest, spec.trueDigest) {
		return fmt.Errorf("%s/valid: subject digest %v is not the true digest %v", spec.name, stmt.Subject[0].Digest, spec.trueDigest)
	}

	// tampered: same payload, signature no longer verifies.
	tampered, err := loadEnvelope(spec.name, variantTampered)
	if err != nil {
		return err
	}
	if !bytes.Equal(tampered.GetPayload(), valid.GetPayload()) {
		return fmt.Errorf("%s/tampered: payload differs from valid; only the signature should change", spec.name)
	}
	if signatureVerifies(pub, tampered) {
		return fmt.Errorf("%s/tampered: signature still verifies; the byte flip did not take", spec.name)
	}

	// digest-mismatch: verifies, parses, but subject digest is not the true one.
	mismatch, err := loadEnvelope(spec.name, variantDigestMismatch)
	if err != nil {
		return err
	}
	if !signatureVerifies(pub, mismatch) {
		return fmt.Errorf("%s/digest-mismatch: signature did not verify; it must be validly signed over the wrong subject", spec.name)
	}
	mismatchStmt, err := manifest.ParseStatement(mismatch.GetPayload())
	if err != nil {
		return fmt.Errorf("%s/digest-mismatch: statement did not parse: %w", spec.name, err)
	}
	if digestSetEqual(mismatchStmt.Subject[0].Digest, spec.trueDigest) {
		return fmt.Errorf("%s/digest-mismatch: subject digest matches the true digest; it should be wrong", spec.name)
	}

	// schema-invalid: verifies, parses structurally, predicate fails on schemaVersion.
	schemaInvalid, err := loadEnvelope(spec.name, variantSchemaInvalid)
	if err != nil {
		return err
	}
	if !signatureVerifies(pub, schemaInvalid) {
		return fmt.Errorf("%s/schema-invalid: signature did not verify", spec.name)
	}
	schemaStmt, err := manifest.ParseStatement(schemaInvalid.GetPayload())
	if err != nil {
		return fmt.Errorf("%s/schema-invalid: statement did not parse structurally: %w", spec.name, err)
	}
	if !hasIssueCode(schemaStmt.Predicate.Validate(), codes.ManifestSchemaVersionUnsupported) {
		return fmt.Errorf("%s/schema-invalid: predicate did not report %s", spec.name, codes.ManifestSchemaVersionUnsupported)
	}

	// unknown-predicate: verifies, payload carries v2 predicate type, strict parse rejects it.
	unknown, err := loadEnvelope(spec.name, variantUnknownPredicate)
	if err != nil {
		return err
	}
	if !signatureVerifies(pub, unknown) {
		return fmt.Errorf("%s/unknown-predicate: signature did not verify", spec.name)
	}
	var probe struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(unknown.GetPayload(), &probe); err != nil {
		return fmt.Errorf("%s/unknown-predicate: payload is not JSON: %w", spec.name, err)
	}
	if probe.PredicateType != predicateTypeV2 {
		return fmt.Errorf("%s/unknown-predicate: predicateType %q is not %q", spec.name, probe.PredicateType, predicateTypeV2)
	}
	if _, err := manifest.ParseStatement(unknown.GetPayload()); err == nil {
		return fmt.Errorf("%s/unknown-predicate: statement parsed cleanly; strict parsing must reject the v2 predicate type", spec.name)
	}
	return nil
}

// loadEnvelope loads a committed fixture bundle and returns its DSSE envelope.
func loadEnvelope(subject, variant string) (*protodsse.Envelope, error) {
	path := filepath.Join(signatureDir, subject, variant+".sigstore.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		return nil, fmt.Errorf("%s is not valid protojson: %w", path, err)
	}
	env := pb.GetDsseEnvelope()
	if env == nil {
		return nil, fmt.Errorf("%s carries no DSSE envelope", path)
	}
	return env, nil
}

// signatureVerifies reports whether the envelope's single DSSE signature
// verifies against pub over the sigstore reconstructed pre authentication
// encoding.
func signatureVerifies(pub *ecdsa.PublicKey, env *protodsse.Envelope) bool {
	sigs := env.GetSignatures()
	if len(sigs) != 1 {
		return false
	}
	pae := (&sign.DSSEData{Data: env.GetPayload(), PayloadType: env.GetPayloadType()}).PreAuthEncoding()
	verifier, err := sigsig.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return false
	}
	return verifier.VerifySignature(bytes.NewReader(sigs[0].GetSig()), bytes.NewReader(pae)) == nil
}

// readPublicKey reads and parses a PEM public key, returning an ECDSA key.
func readPublicKey(path string) (*ecdsa.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is %T, want an ECDSA public key", path, pub)
	}
	return ec, nil
}

// digestSetEqual reports whether two digest sets carry the same keys and values.
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

// must fatals with context when err is non nil.
func must(what string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", what, err)
	}
}
