package compose

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// testBundleMediaType stands in for the real sigstore bundle media type in
// these tests. Production code never hard codes this string (PushAttestation
// and AttachReferrer both read it off bundle.MediaType), so a literal here is
// only a test fixture, not a violation of that rule.
const testBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// testSignedBundle returns a SignedBundle carrying fixed, fake DSSE bundle
// bytes: realistic enough in shape to be a plausible layer payload, but with
// no real cryptography, matching how sign_test.go's fakeSigner builds one.
func testSignedBundle() *SignedBundle {
	return &SignedBundle{
		Bundle:    []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":{"payload":"ZmFrZQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"ZmFrZS1zaWc="}]}}`),
		MediaType: testBundleMediaType,
	}
}

// assertCode fails t unless err is a *codes.Error carrying code.
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error carrying code %s, got nil", code)
	}
	var e *codes.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected a *codes.Error in %v (%T)", err, err)
	}
	if e.Code != code {
		t.Fatalf("error code = %s, want %s", e.Code, code)
	}
}

// TestPushAttestationRoundTrip pushes a bundle to a memory target and fetches
// the manifest and layer back, asserting the layer bytes equal
// bundle.Bundle byte for byte and that the manifest carries bundle.MediaType
// as both its artifactType and its single layer's mediaType.
func TestPushAttestationRoundTrip(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	bundle := testSignedBundle()

	digest, err := PushAttestation(ctx, target, "registry.example.com/attest/npm/example", "sha512-abc.att", bundle)
	if err != nil {
		t.Fatalf("PushAttestation returned error: %v", err)
	}
	if digest == "" {
		t.Fatal("PushAttestation returned an empty digest")
	}

	resolved, err := target.Resolve(ctx, "sha512-abc.att")
	if err != nil {
		t.Fatalf("resolving pushed tag: %v", err)
	}
	if resolved.Digest.String() != digest {
		t.Errorf("tag resolves to %q, want %q", resolved.Digest.String(), digest)
	}

	manifestBytes, err := content.FetchAll(ctx, target, resolved)
	if err != nil {
		t.Fatalf("fetching manifest: %v", err)
	}
	var manifestDoc ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifestDoc); err != nil {
		t.Fatalf("parsing manifest: %v", err)
	}
	if len(manifestDoc.Layers) != 1 {
		t.Fatalf("manifest has %d layers, want 1", len(manifestDoc.Layers))
	}
	if manifestDoc.Layers[0].MediaType != bundle.MediaType {
		t.Errorf("layer mediaType = %q, want %q", manifestDoc.Layers[0].MediaType, bundle.MediaType)
	}
	if manifestDoc.ArtifactType != bundle.MediaType {
		t.Errorf("manifest artifactType = %q, want %q", manifestDoc.ArtifactType, bundle.MediaType)
	}

	layerBytes, err := content.FetchAll(ctx, target, manifestDoc.Layers[0])
	if err != nil {
		t.Fatalf("fetching layer: %v", err)
	}
	if !bytes.Equal(layerBytes, bundle.Bundle) {
		t.Errorf("layer bytes do not match bundle.Bundle byte for byte:\n got  %q\n want %q", layerBytes, bundle.Bundle)
	}
}

// TestPushAttestationDeterministic pins the reproducibility requirement:
// pushing the same bundle twice, even to two independent stores, must
// produce identical manifest digests. This exercises the fixed
// ocispec.AnnotationCreated value PushAttestation sets, since oras.PackManifest
// otherwise stamps the real wall clock time into every packed manifest.
func TestPushAttestationDeterministic(t *testing.T) {
	ctx := context.Background()
	bundle := testSignedBundle()

	target1 := memory.New()
	digest1, err := PushAttestation(ctx, target1, "registry.example.com/attest/npm/example", "sha512-abc.att", bundle)
	if err != nil {
		t.Fatalf("first push: %v", err)
	}

	target2 := memory.New()
	digest2, err := PushAttestation(ctx, target2, "registry.example.com/attest/npm/example", "sha512-abc.att", bundle)
	if err != nil {
		t.Fatalf("second push: %v", err)
	}

	if digest1 != digest2 {
		t.Errorf("digests differ across two pushes of the same bundle: %s vs %s", digest1, digest2)
	}
}

func TestPushAttestationRejectsNilBundle(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	_, err := PushAttestation(ctx, target, "registry.example.com/attest/npm/example", "sha512-abc.att", nil)
	assertCode(t, err, codes.PublishBundleInvalid)
}

func TestPushAttestationRejectsEmptyBundle(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	_, err := PushAttestation(ctx, target, "registry.example.com/attest/npm/example", "sha512-abc.att", &SignedBundle{MediaType: testBundleMediaType})
	assertCode(t, err, codes.PublishBundleInvalid)
}

// TestPushAttestationRejectsInvalidTag asserts a tag violating the OCI tag
// grammar errors before any push is attempted: the tag never resolves
// afterward, proving no manifest was pushed and then merely left untagged.
func TestPushAttestationRejectsInvalidTag(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	badTag := "-leading-hyphen-not-allowed"

	_, err := PushAttestation(ctx, target, "registry.example.com/attest/npm/example", badTag, testSignedBundle())
	assertCode(t, err, codes.PublishTagInvalid)

	if _, err := target.Resolve(ctx, badTag); err == nil {
		t.Error("tag resolved even though PushAttestation should have rejected it before any push")
	}
}

// fabricatedSubject pushes and returns a descriptor for a small, valid OCI
// image manifest into target, standing in for some other artifact's already
// published manifest that AttachReferrer will link a bundle to.
func fabricatedSubject(t *testing.T, ctx context.Context, target *memory.Store) ocispec.Descriptor {
	t.Helper()
	subjectBytes := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`)
	subjectDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, subjectBytes)
	if err := target.Push(ctx, subjectDesc, bytes.NewReader(subjectBytes)); err != nil {
		t.Fatalf("pushing fabricated subject: %v", err)
	}
	return subjectDesc
}

// TestAttachReferrerLinksToSubject attaches a bundle as a referrer of a
// fabricated subject descriptor and asserts the referrers query on the
// memory store (oras-go's registry.Referrers, backed by Predecessors) finds
// it.
func TestAttachReferrerLinksToSubject(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	subjectDesc := fabricatedSubject(t, ctx, target)

	digest, err := AttachReferrer(ctx, target, subjectDesc, testSignedBundle())
	if err != nil {
		t.Fatalf("AttachReferrer returned error: %v", err)
	}

	referrers, err := registry.Referrers(ctx, target, subjectDesc, "")
	if err != nil {
		t.Fatalf("querying referrers: %v", err)
	}
	if len(referrers) != 1 {
		t.Fatalf("got %d referrers, want 1", len(referrers))
	}
	if referrers[0].Digest.String() != digest {
		t.Errorf("referrer digest = %q, want %q", referrers[0].Digest.String(), digest)
	}

	predecessors, err := target.Predecessors(ctx, subjectDesc)
	if err != nil {
		t.Fatalf("querying predecessors: %v", err)
	}
	if len(predecessors) != 1 || predecessors[0].Digest.String() != digest {
		t.Errorf("predecessors = %v, want exactly the attached manifest %s", predecessors, digest)
	}
}

func TestAttachReferrerRejectsNilBundle(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	subjectDesc := fabricatedSubject(t, ctx, target)

	_, err := AttachReferrer(ctx, target, subjectDesc, nil)
	assertCode(t, err, codes.PublishBundleInvalid)
}

// TestPushWithDiscoveredTagShape proves the two Task 2.6 and Task 2.7
// packages compose: a (repo, tag) pair produced by discover.AttestationRef
// for npm fixture values pushes with no error.
func TestPushWithDiscoveredTagShape(t *testing.T) {
	ctx := context.Background()
	target := memory.New()

	ref := manifest.ArtifactRef{
		Kind:   manifest.KindMCPServer,
		Name:   "better-call-claude",
		Source: manifest.SourceNPM,
		Digest: manifest.DigestSet{"sha512": strings.Repeat("a1", 64)},
	}
	repo, tag, err := discover.AttestationRef("registry.example.com/attest", ref)
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}

	if _, err := PushAttestation(ctx, target, repo, tag, testSignedBundle()); err != nil {
		t.Fatalf("PushAttestation with discover produced repo %q tag %q failed: %v", repo, tag, err)
	}
}
