package discover_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/memory"

	"github.com/sns45/smithmark/pkg/compose"
	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/discover"
)

// digestOf returns the canonical (sha256) digest of data, matching how
// content.NewDescriptorFromBytes computes a descriptor's digest, without
// pulling in that helper's mediaType requirement for this file's minimal
// hand built descriptors.
func digestOf(data []byte) godigest.Digest {
	return godigest.FromBytes(data)
}

// --- fixture HTTP transport -------------------------------------------------

// fixtureResponse is one canned HTTP response a fixtureTransport serves.
type fixtureResponse struct {
	status int
	body   []byte
}

// fixtureTransport is an injected http.RoundTripper that serves canned
// responses keyed by "METHOD path", failing the test loudly on any request it
// was not told to expect. This is the mechanism that keeps every npm.go test
// free of real sockets (controller resolution 6): an unexpected URL is a test
// failure, never a silent fallthrough to the live registry.
type fixtureTransport struct {
	t     *testing.T
	byKey map[string]fixtureResponse
}

func newFixtureTransport(t *testing.T) *fixtureTransport {
	t.Helper()
	return &fixtureTransport{t: t, byKey: map[string]fixtureResponse{}}
}

func (f *fixtureTransport) serve(method, path string, status int, body []byte) *fixtureTransport {
	f.byKey[method+" "+path] = fixtureResponse{status: status, body: body}
	return f
}

func (f *fixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	key := req.Method + " " + req.URL.Path
	resp, ok := f.byKey[key]
	if !ok {
		f.t.Fatalf("fixtureTransport: unexpected request %s %s; no real network is permitted in this test", req.Method, req.URL.String())
		return nil, fmt.Errorf("unreachable")
	}
	return &http.Response{
		StatusCode: resp.status,
		Status:     fmt.Sprintf("%d %s", resp.status, http.StatusText(resp.status)),
		Body:       io.NopCloser(bytes.NewReader(resp.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// --- poison OCI target ------------------------------------------------------

// poisonTarget implements oras.ReadOnlyGraphTarget by failing the test on any
// method call. It stands in for "this must never be touched" in tests that
// assert a code path (such as --bundle mode) skips OCI backed attestation
// discovery entirely, rather than merely happening not to find anything.
type poisonTarget struct{ t *testing.T }

func (p poisonTarget) Fetch(context.Context, ocispec.Descriptor) (io.ReadCloser, error) {
	p.t.Fatal("poisonTarget.Fetch called; discovery should have been skipped entirely")
	return nil, nil
}
func (p poisonTarget) Exists(context.Context, ocispec.Descriptor) (bool, error) {
	p.t.Fatal("poisonTarget.Exists called; discovery should have been skipped entirely")
	return false, nil
}
func (p poisonTarget) Resolve(context.Context, string) (ocispec.Descriptor, error) {
	p.t.Fatal("poisonTarget.Resolve called; discovery should have been skipped entirely")
	return ocispec.Descriptor{}, nil
}
func (p poisonTarget) Predecessors(context.Context, ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	p.t.Fatal("poisonTarget.Predecessors called; discovery should have been skipped entirely")
	return nil, nil
}

// --- poison HTTP transport ---------------------------------------------------

// poisonTransport implements http.RoundTripper by failing the test on any
// call. It stands in for "this argument form must never touch the npm
// registry" in tests whose argument never reaches the npm request path (a
// local skill directory, an OCI reference, or an argument Resolve rejects
// before any network call), pairing with poisonTarget's identical role for
// the OCI target.
type poisonTransport struct{ t *testing.T }

func (p poisonTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.t.Fatalf("poisonTransport: unexpected request %s %s; this test path should never touch the npm registry", req.Method, req.URL.String())
	return nil, fmt.Errorf("unreachable")
}

// mustResolveOptions builds a discover.ResolveOptions for a test, guarding a
// specific footgun: a nil Transport combined with the real npm registry
// default (an empty Registry) means net/http's own documented fallback,
// http.DefaultTransport, would silently reach the real network the moment
// any code path in the test calls the npm registry. Every ResolveOptions
// literal in this file is built through this helper, so a test that forgets
// to inject a transport fails immediately at construction time, loudly and
// long before any request would go out, rather than possibly passing by
// accident today and making a live request once some later change in this
// file makes the npm path reachable. A test whose argument form never
// touches npm at all still passes poisonTransport rather than leaving
// Transport unset, so the guard has no exception to remember.
func mustResolveOptions(t *testing.T, opts discover.ResolveOptions) discover.ResolveOptions {
	t.Helper()
	if opts.Transport == nil && opts.Registry == "" {
		t.Fatal("mustResolveOptions: Transport is nil while Registry is the real npm default; pass a fixture transport, or poisonTransport if this path must never touch npm")
	}
	return opts
}

// --- shared fixture data -----------------------------------------------------

const (
	fixturePackumentPath    = "../../testdata/npm/packument.json"
	fixtureAttestationsPath = "../../testdata/npm/attestations.json"

	fixtureNPMName    = "@modelcontextprotocol/server-filesystem"
	fixtureNPMVersion = "2026.7.10"
	// fixtureNPMDigestHex is the sha512 hex conversion of the packument's
	// dist.integrity value, computed independently (see
	// TestNPMIntegrityToHexPinnedVector) and pinned here again so a Resolve
	// level test proves the same value end to end.
	fixtureNPMDigestHex = "3268e0e1a9c5043e4ecdb3e7189380d233cf37ceb8e44461424dfc1d02e949e9f1d68c7d6df74f926033527363790b6a40614bb4a7b5dc9db446d2c199428c64"

	testBase = "registry.example.com/attest"
)

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

func npmTransport(t *testing.T, attestationsStatus int, attestationsBody []byte) *fixtureTransport {
	t.Helper()
	tr := newFixtureTransport(t)
	tr.serve(http.MethodGet, "/"+fixtureNPMName, http.StatusOK, readFile(t, fixturePackumentPath))
	tr.serve(http.MethodGet, fmt.Sprintf("/-/npm/v1/attestations/%s@%s", fixtureNPMName, fixtureNPMVersion), attestationsStatus, attestationsBody)
	return tr
}

func fixtureNPMRef() manifest.ArtifactRef {
	return manifest.ArtifactRef{
		Kind:    manifest.KindMCPServer,
		Name:    fixtureNPMName,
		Version: fixtureNPMVersion,
		Source:  manifest.SourceNPM,
		Digest:  manifest.DigestSet{"sha512": fixtureNPMDigestHex},
	}
}

// testSignedBundle mirrors pkg/compose's own test fixture bundle: realistic
// shape, no real cryptography, since these tests exercise discovery wiring,
// not signature verification.
func testSignedBundle() *compose.SignedBundle {
	return &compose.SignedBundle{
		Bundle:    []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsseEnvelope":{"payload":"ZmFrZQ==","payloadType":"application/vnd.in-toto+json","signatures":[{"sig":"ZmFrZS1zaWc="}]}}`),
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
	}
}

func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error carrying code %s, got nil", code)
	}
	var e *codes.Error
	if !errors.As(err, &e) {
		t.Fatalf("expected a *codes.Error in %v (%T)", err, err)
	}
	if e.Code != code {
		t.Fatalf("error code = %s, want %s", e.Code, code)
	}
}

// notesHavePrefix reports whether any entry in notes begins with one of
// discover's exported Note* constants (see resolve.go's notef helper): the
// stable, machine readable check Task 3.3 is expected to use, tested here
// against the constants themselves rather than restated prose substrings.
func notesHavePrefix(notes []string, prefix string) bool {
	for _, n := range notes {
		if strings.HasPrefix(n, prefix+": ") {
			return true
		}
	}
	return false
}

// notesContainSubstring reports whether any entry in notes contains substr
// anywhere, for asserting on a note's detail text (for example, that it names
// a specific path), as distinct from notesHavePrefix's check of the stable
// prefix token itself.
func notesContainSubstring(notes []string, substr string) bool {
	for _, n := range notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// --- npm argument form -------------------------------------------------------

// TestResolveNPMArgFullRoundTrip drives Resolve over the "name@version"
// argument form end to end: packument resolution, integrity to hex
// conversion, D3 tag computation and fetch against a memory OCI target, and
// npm provenance fetch, all through the injected transport with no real
// network.
func TestResolveNPMArgFullRoundTrip(t *testing.T) {
	tr := npmTransport(t, http.StatusOK, readFile(t, fixtureAttestationsPath))
	target := memory.New()

	ref := fixtureNPMRef()
	repo, tag, err := discover.AttestationRef(testBase, ref)
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	if _, err := compose.PushAttestation(context.Background(), target, repo, tag, testSignedBundle()); err != nil {
		t.Fatalf("seeding fixture tag: %v", err)
	}

	got, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if got.Ref.Kind != manifest.KindMCPServer {
		t.Errorf("Ref.Kind = %q, want mcp-server", got.Ref.Kind)
	}
	if got.Ref.Name != fixtureNPMName {
		t.Errorf("Ref.Name = %q, want %q", got.Ref.Name, fixtureNPMName)
	}
	if got.Ref.Version != fixtureNPMVersion {
		t.Errorf("Ref.Version = %q, want %q", got.Ref.Version, fixtureNPMVersion)
	}
	if got.Ref.Source != manifest.SourceNPM {
		t.Errorf("Ref.Source = %q, want npm", got.Ref.Source)
	}
	if got.Ref.Digest["sha512"] != fixtureNPMDigestHex {
		t.Errorf("Ref.Digest[sha512] = %q, want %q", got.Ref.Digest["sha512"], fixtureNPMDigestHex)
	}

	if len(got.Bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(got.Bundles))
	}
	if !bytes.Equal(got.Bundles[0], testSignedBundle().Bundle) {
		t.Errorf("bundle bytes do not match the pushed fixture")
	}

	if got.NPMProvenance == nil {
		t.Fatal("NPMProvenance is nil, want the SLSA provenance bundle bytes")
	}
	// The fixture's SLSA provenance entry (predicateType
	// https://slsa.dev/provenance/v1) carries this exact bundle mediaType,
	// distinct from the *other* attestation entry in the same fixture (the
	// npm publish attestation, predicateType
	// https://github.com/npm/attestation/tree/main/specs/publish/v0.1, whose
	// bundle mediaType is "application/vnd.dev.sigstore.bundle+json;version=0.2").
	// Asserting this exact value proves fetchNPMProvenance selected the
	// provenance entry specifically, not merely the first one in the array.
	if !bytes.Contains(got.NPMProvenance, []byte(`"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"`)) {
		t.Errorf("NPMProvenance does not look like the SLSA provenance attestation's own bundle: %s", got.NPMProvenance)
	}
}

// TestResolveNPMArgAbsentTagIsNotAnError asserts that when no attestation tag
// exists in the target, Resolve completes successfully with zero bundles and
// a note: absence of attestations is not a discovery failure (U3 assigns that
// meaning to verification's ATTESTATION_MISSING check instead).
func TestResolveNPMArgAbsentTagIsNotAnError(t *testing.T) {
	tr := npmTransport(t, http.StatusNotFound, nil)
	target := memory.New() // nothing pushed

	got, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Bundles) != 0 {
		t.Errorf("got %d bundles, want 0", len(got.Bundles))
	}
	if got.NPMProvenance != nil {
		t.Errorf("NPMProvenance = %q, want nil (404 tolerated)", got.NPMProvenance)
	}
	if !notesHavePrefix(got.Notes, discover.NoteNoAttestationTag) {
		t.Errorf("notes = %v, want a %s note for the absent tag", got.Notes, discover.NoteNoAttestationTag)
	}
	if !notesHavePrefix(got.Notes, discover.NoteNoProvenance) {
		t.Errorf("notes = %v, want a %s note for the absent provenance", got.Notes, discover.NoteNoProvenance)
	}
}

// TestResolveNPMArgUnexpectedPackumentStatusFails asserts a non 200, non 404
// packument response is a hard DISCOVERY_FAILED error, not silently ignored.
func TestResolveNPMArgUnexpectedPackumentStatusFails(t *testing.T) {
	tr := newFixtureTransport(t)
	tr.serve(http.MethodGet, "/"+fixtureNPMName, http.StatusInternalServerError, []byte("boom"))

	_, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
	}))
	assertCode(t, err, codes.DiscoveryFailed)
}

// TestResolveNPMArgUnknownVersionFails asserts a version absent from the
// packument's versions map is a DISCOVERY_FAILED error rather than a
// zero value ArtifactRef silently passed downstream.
func TestResolveNPMArgUnknownVersionFails(t *testing.T) {
	tr := newFixtureTransport(t)
	tr.serve(http.MethodGet, "/"+fixtureNPMName, http.StatusOK, readFile(t, fixturePackumentPath))

	_, err := discover.Resolve(context.Background(), fixtureNPMName+"@9.9.9-does-not-exist", mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
	}))
	assertCode(t, err, codes.DiscoveryFailed)
}

// TestResolveNPMArgMalformedBaseFails asserts an attestation base whose path
// segment violates the OCI repository path grammar (here, an uppercase
// segment) is a DISCOVERY_FAILED error, not silently treated as zero
// bundles. Reachability argument (the CRITICAL fix this pins): a source with
// no canonical attestation home at all short circuits earlier in
// discoverByTag on an empty digest, so this AttestationRef call is reached
// only by a genuine grammar or name problem, and every one of those must be
// loud.
func TestResolveNPMArgMalformedBaseFails(t *testing.T) {
	tr := npmTransport(t, http.StatusNotFound, nil)

	_, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase + "/BadSegment",
		Transport: tr,
	}))
	assertCode(t, err, codes.DiscoveryFailed)
}

// --- base resolution wiring (D3) --------------------------------------------

// TestResolveSurfacesAttestationBaseUnknown asserts that when discovery needs
// a base and none of the flag, environment variable, or (for local args)
// package.json supplies one, Resolve surfaces ATTESTATION_BASE_UNKNOWN
// verbatim, per controller resolution 4.
func TestResolveSurfacesAttestationBaseUnknown(t *testing.T) {
	t.Setenv("SMITHMARK_ATTESTATION_BASE", "")
	tr := newFixtureTransport(t)
	tr.serve(http.MethodGet, "/"+fixtureNPMName, http.StatusOK, readFile(t, fixturePackumentPath))

	_, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Transport: tr,
		Target:    memory.New(),
	}))
	assertCode(t, err, codes.AttestationBaseUnknown)
}

// TestResolveLocalDirBaseFromPackageJSON asserts the local directory argument
// form threads its own path through as ResolveAttestationBase's artifactRoot,
// so a smithmark.attestationBase key in that directory's package.json (D3's
// third resolution rung) supplies the base with no flag or environment
// variable set.
func TestResolveLocalDirBaseFromPackageJSON(t *testing.T) {
	t.Setenv("SMITHMARK_ATTESTATION_BASE", "")
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "smithmark.yaml"), []byte(hostSkillYAML))
	writeFile(t, filepath.Join(root, "SKILL.md"), []byte(hostSkillMD))
	writeFile(t, filepath.Join(root, "package.json"), []byte(`{"smithmark":{"attestationBase":"`+testBase+`"}}`))

	target := memory.New()
	got, err := discover.Resolve(context.Background(), root, mustResolveOptions(t, discover.ResolveOptions{
		Transport: poisonTransport{t: t}, // this argument form is a skill; npm must never be touched
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Ref.Kind != manifest.KindSkill {
		t.Fatalf("Ref.Kind = %q, want skill", got.Ref.Kind)
	}
	if len(got.Bundles) != 0 {
		t.Errorf("got %d bundles, want 0 (nothing was pushed, but no error either)", len(got.Bundles))
	}
}

// --- local directory argument form -------------------------------------------

const skillFixtureRoot = "../../testdata/skills/hello-skill"

// TestResolveLocalSkillDirectory drives Resolve over the local directory
// argument form for a skill: the digest must be the true, recomputed
// canonical bundle digest of the fixture directory (never a stale or hard
// coded value), and the D3 skill tag mapping must find a bundle pushed under
// that same digest.
func TestResolveLocalSkillDirectory(t *testing.T) {
	decl, err := discover.LoadDeclared(filepath.Join(skillFixtureRoot, "smithmark.yaml"))
	if err != nil {
		t.Fatalf("LoadDeclared: %v", err)
	}
	files, _, info, err := discover.WalkSkill(skillFixtureRoot, decl.Executables)
	if err != nil {
		t.Fatalf("WalkSkill: %v", err)
	}
	dg, err := bundle.Digest(files)
	if err != nil {
		t.Fatalf("bundle.Digest: %v", err)
	}
	trueDigest, err := manifest.SubjectDigestFromBundle(dg)
	if err != nil {
		t.Fatalf("SubjectDigestFromBundle: %v", err)
	}

	ref := manifest.ArtifactRef{
		Kind:    manifest.KindSkill,
		Name:    decl.Manifest.Artifact.Name,
		Version: info.Version,
		Source:  manifest.SourceLocal,
		Digest:  trueDigest,
	}
	repo, tag, err := discover.AttestationRef(testBase, ref)
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	target := memory.New()
	if _, err := compose.PushAttestation(context.Background(), target, repo, tag, testSignedBundle()); err != nil {
		t.Fatalf("seeding fixture tag: %v", err)
	}

	got, err := discover.Resolve(context.Background(), skillFixtureRoot, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: poisonTransport{t: t}, // this argument form is a skill; npm must never be touched
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Ref.Kind != manifest.KindSkill {
		t.Errorf("Ref.Kind = %q, want skill", got.Ref.Kind)
	}
	if got.Ref.Name != decl.Manifest.Artifact.Name {
		t.Errorf("Ref.Name = %q, want %q", got.Ref.Name, decl.Manifest.Artifact.Name)
	}
	if got.Ref.Digest["smithmark-bundle-v1"] != trueDigest["smithmark-bundle-v1"] {
		t.Errorf("Ref.Digest = %v, want the true recomputed bundle digest %v", got.Ref.Digest, trueDigest)
	}
	if len(got.Bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(got.Bundles))
	}
	if !bytes.Equal(got.Bundles[0], testSignedBundle().Bundle) {
		t.Error("bundle bytes do not match the pushed fixture")
	}
}

// TestResolveLocalNPMSourcedDirectory drives Resolve over a local directory
// whose smithmark.yaml declares an mcp-server with source npm: identity
// (specifically the digest) must be resolved via the packument, exactly as
// the pure npm argument form does, per controller resolution 3.
func TestResolveLocalNPMSourcedDirectory(t *testing.T) {
	tr := npmTransport(t, http.StatusNotFound, nil)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "smithmark.yaml"), []byte(fmt.Sprintf(npmSourcedYAMLTemplate, fixtureNPMName, fixtureNPMVersion)))

	target := memory.New()
	ref := fixtureNPMRef()
	repo, tag, err := discover.AttestationRef(testBase, ref)
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	if _, err := compose.PushAttestation(context.Background(), target, repo, tag, testSignedBundle()); err != nil {
		t.Fatalf("seeding fixture tag: %v", err)
	}

	got, err := discover.Resolve(context.Background(), root, mustResolveOptions(t, discover.ResolveOptions{
		Base:      testBase,
		Transport: tr,
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Ref.Source != manifest.SourceNPM {
		t.Fatalf("Ref.Source = %q, want npm", got.Ref.Source)
	}
	if got.Ref.Digest["sha512"] != fixtureNPMDigestHex {
		t.Errorf("Ref.Digest[sha512] = %q, want %q", got.Ref.Digest["sha512"], fixtureNPMDigestHex)
	}
	if len(got.Bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(got.Bundles))
	}
}

// --- explicit --bundle path --------------------------------------------------

// TestResolveBundlePathWinsOverDiscovery asserts that when opts.BundlePath is
// set, Resolve reads the bundle from that path and never touches the OCI
// target at all (proved with a target that fails the test if any of its
// methods are called), regardless of whether a normal npm argument would
// otherwise have triggered tag based discovery.
func TestResolveBundlePathWinsOverDiscovery(t *testing.T) {
	tr := npmTransport(t, http.StatusOK, readFile(t, fixtureAttestationsPath))
	bundleDir := t.TempDir()
	bundlePath := filepath.Join(bundleDir, "explicit.sigstore.json")
	explicitBytes := []byte(`{"explicit":"bundle"}`)
	writeFile(t, bundlePath, explicitBytes)

	got, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:       testBase,
		BundlePath: bundlePath,
		Transport:  tr,
		Target:     poisonTarget{t: t},
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Bundles) != 1 || !bytes.Equal(got.Bundles[0], explicitBytes) {
		t.Errorf("Bundles = %v, want exactly the explicit bundle bytes", got.Bundles)
	}
	if got.NPMProvenance != nil {
		t.Error("NPMProvenance should be nil when --bundle wins over discovery")
	}
	if !notesHavePrefix(got.Notes, discover.NoteExplicitBundle) {
		t.Errorf("notes = %v, want a %s note", got.Notes, discover.NoteExplicitBundle)
	}
	if !notesContainSubstring(got.Notes, bundlePath) {
		t.Errorf("notes = %v, want a note naming the explicit bundle path", got.Notes)
	}
	// Ref identity is still fully resolved even in bundle path mode.
	if got.Ref.Digest["sha512"] != fixtureNPMDigestHex {
		t.Errorf("Ref.Digest[sha512] = %q, want %q even in --bundle mode", got.Ref.Digest["sha512"], fixtureNPMDigestHex)
	}
}

// --- unrecognized argument ----------------------------------------------------

func TestResolveUnrecognizedArgumentFails(t *testing.T) {
	_, err := discover.Resolve(context.Background(), "totally-not-a-recognized-shape", mustResolveOptions(t, discover.ResolveOptions{
		Transport: poisonTransport{t: t}, // an unrecognized argument must never reach the npm registry
	}))
	assertCode(t, err, codes.DiscoveryFailed)
}

// --- OCI referrers path -------------------------------------------------------

// emptyOCIManifestBytes is a minimal, valid OCI v1 image manifest with no
// layers, standing in for some other artifact's already published manifest
// (mirrors pkg/compose/push_test.go's fabricatedSubject fixture).
const emptyOCIManifestBytes = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},"layers":[]}`

// TestResolveOCIRefUsesReferrers drives Resolve over an OCI reference
// argument: it resolves the tag to a subject descriptor via opts.Target,
// lists referrers, and collects the layers of any referrer whose
// artifactType matches the sigstore bundle media type family (controller
// resolution 7). The fixture is pushed with pkg/compose's own
// AttachReferrer, proving the two Task 2.7 and Task 3.2 packages compose.
func TestResolveOCIRefUsesReferrers(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	subjectBytes := []byte(emptyOCIManifestBytes)
	subjectDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digestOf(subjectBytes),
		Size:      int64(len(subjectBytes)),
	}
	if err := target.Push(ctx, subjectDesc, bytes.NewReader(subjectBytes)); err != nil {
		t.Fatalf("pushing fabricated subject: %v", err)
	}
	if err := target.Tag(ctx, subjectDesc, "v1.0.0"); err != nil {
		t.Fatalf("tagging fabricated subject: %v", err)
	}
	if _, err := compose.AttachReferrer(ctx, target, subjectDesc, testSignedBundle()); err != nil {
		t.Fatalf("AttachReferrer: %v", err)
	}

	got, err := discover.Resolve(ctx, "registry.example.com/some/repo:v1.0.0", mustResolveOptions(t, discover.ResolveOptions{
		Transport: poisonTransport{t: t}, // an OCI reference must never reach the npm registry
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Ref.Source != manifest.SourceOCI {
		t.Errorf("Ref.Source = %q, want oci", got.Ref.Source)
	}
	if got.Ref.Digest["sha256"] != subjectDesc.Digest.Encoded() {
		t.Errorf("Ref.Digest[sha256] = %q, want %q", got.Ref.Digest["sha256"], subjectDesc.Digest.Encoded())
	}
	if len(got.Bundles) != 1 {
		t.Fatalf("got %d bundles, want 1", len(got.Bundles))
	}
	if !bytes.Equal(got.Bundles[0], testSignedBundle().Bundle) {
		t.Error("bundle bytes do not match the attached fixture")
	}
}

// TestResolveOCIRefNoMatchingReferrers asserts an OCI ref whose subject has no
// referrers at all resolves successfully with zero bundles, not an error.
func TestResolveOCIRefNoMatchingReferrers(t *testing.T) {
	ctx := context.Background()
	target := memory.New()
	subjectBytes := []byte(emptyOCIManifestBytes)
	subjectDesc := ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digestOf(subjectBytes),
		Size:      int64(len(subjectBytes)),
	}
	if err := target.Push(ctx, subjectDesc, bytes.NewReader(subjectBytes)); err != nil {
		t.Fatalf("pushing fabricated subject: %v", err)
	}
	if err := target.Tag(ctx, subjectDesc, "v1.0.0"); err != nil {
		t.Fatalf("tagging fabricated subject: %v", err)
	}

	got, err := discover.Resolve(ctx, "registry.example.com/some/repo:v1.0.0", mustResolveOptions(t, discover.ResolveOptions{
		Transport: poisonTransport{t: t}, // an OCI reference must never reach the npm registry
		Target:    target,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got.Bundles) != 0 {
		t.Errorf("got %d bundles, want 0", len(got.Bundles))
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

const hostSkillYAML = `kind: skill
name: host-fixture-skill
source: local
skill:
  invokesTools: []
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`

const hostSkillMD = `---
name: host-fixture-skill
version: 0.1.0
---

# Host fixture skill

Used only by TestResolveLocalDirBaseFromPackageJSON.
`

const npmSourcedYAMLTemplate = `kind: mcp-server
name: %q
version: %q
source: npm
mcp:
  transports: [stdio]
capabilities:
  networkEgress: []
  filesystem: []
  exec: []
  env: []
  secrets: []
`
