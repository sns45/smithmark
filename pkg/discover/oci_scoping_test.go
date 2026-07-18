package discover_test

// This file is the "would have caught it live" test for smithmark#4: it stands
// up a real OCI distribution v2 registry with net/http/httptest and drives a
// real oras remote.Repository against it, rather than a memory store. The two
// tests prove the client is scoped to the per artifact repository: an
// attestation pushed to <base>/npm/<name> is found, and the same attestation
// sitting only at the bare <base> is not. The second assertion is the one that
// fails against the pre Task 2 code, which queried the bare base for every
// artifact's tags at once instead of the per artifact repository.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	godigest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/sns45/smithmark/pkg/discover"
)

// --- minimal OCI distribution v2 registry over httptest -----------------------

// repoStorage is one repository's content addressable store plus its tag index.
// Keying the whole registry by repository name (see fakeOCIRegistry.repos) is
// what makes a push to <base>/npm/<name> distinguishable from a push to the
// bare <base>: a client scoped to the wrong repository simply finds an empty
// store and a 404, never the other repository's content.
type repoStorage struct {
	blobs     map[string][]byte             // digest string ("sha256:...") -> raw bytes
	manifests map[string]ocispec.Descriptor // digest string -> manifest descriptor
	tags      map[string]string             // tag -> manifest digest string
}

func newRepoStorage() *repoStorage {
	return &repoStorage{
		blobs:     map[string][]byte{},
		manifests: map[string]ocispec.Descriptor{},
		tags:      map[string]string{},
	}
}

// fakeOCIRegistry is a minimal OCI distribution v2 registry backed by an in
// process, per repository store. It implements only the endpoints a real
// remote.Repository calls for Resolve plus content.FetchAll over one manifest
// and its layers: GET /v2/ (ping), HEAD and GET /v2/<repo>/manifests/<ref>, and
// GET /v2/<repo>/blobs/<digest>. It is test only infrastructure.
type fakeOCIRegistry struct {
	t     *testing.T
	srv   *httptest.Server
	host  string // "127.0.0.1:PORT", the scheme stripped httptest host
	mu    sync.Mutex
	repos map[string]*repoStorage
}

func newFakeOCIRegistry(t *testing.T) *fakeOCIRegistry {
	t.Helper()
	reg := &fakeOCIRegistry{t: t, repos: map[string]*repoStorage{}}
	reg.srv = httptest.NewServer(http.HandlerFunc(reg.handler))
	t.Cleanup(reg.srv.Close)
	// httptest hands back "http://127.0.0.1:PORT"; the attestation base grammar
	// and remote.NewRepository both want a bare host, so strip the scheme.
	reg.host = strings.TrimPrefix(reg.srv.URL, "http://")
	return reg
}

// handler routes the three request shapes the round trip needs. The repository
// name carries embedded slashes (npm/<scope>/<name>), so the API verb is found
// by splitting off the final path segment (always the tag or digest, never a
// slash) and matching the "/manifests" or "/blobs" suffix that precedes it.
func (reg *fakeOCIRegistry) handler(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if p == "/v2" || p == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	rest, ok := strings.CutPrefix(p, "/v2/")
	if !ok {
		reg.t.Errorf("fakeOCIRegistry: request outside /v2/: %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	lastSlash := strings.LastIndex(rest, "/")
	if lastSlash < 0 {
		reg.t.Errorf("fakeOCIRegistry: unexpected request %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ref := rest[lastSlash+1:]
	prefix := rest[:lastSlash]
	switch {
	case strings.HasSuffix(prefix, "/manifests"):
		reg.serveManifest(w, r, strings.TrimSuffix(prefix, "/manifests"), ref)
	case strings.HasSuffix(prefix, "/blobs"):
		reg.serveBlob(w, r, strings.TrimSuffix(prefix, "/blobs"), ref)
	default:
		reg.t.Errorf("fakeOCIRegistry: unexpected request %s %s", r.Method, p)
		w.WriteHeader(http.StatusNotFound)
	}
}

// serveManifest answers HEAD and GET /v2/<repoKey>/manifests/<ref>, where ref
// is either a tag or a "sha256:..." digest. The Docker-Content-Digest header is
// mandatory for the HEAD path (remote.Repository fails a HEAD that carries no
// server digest when the reference is a tag), and the Content-Type must equal
// the manifest media type on both HEAD and GET (remote.Repository fails a GET
// whose Content-Type does not match the descriptor it resolved from the HEAD).
func (reg *fakeOCIRegistry) serveManifest(w http.ResponseWriter, r *http.Request, repoKey, ref string) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	store, ok := reg.repos[repoKey]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	dg := ref
	if !strings.Contains(ref, ":") { // a tag, not a digest
		dg, ok = store.tags[ref]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}
	desc, ok := store.manifests[dg]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body := store.blobs[dg]
	w.Header().Set("Content-Type", desc.MediaType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Docker-Content-Digest", dg)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// serveBlob answers GET /v2/<repoKey>/blobs/<digest>. content.FetchAll verifies
// the bytes against the layer descriptor's own digest and size, so no
// Content-Type contract applies here; the digest header is set anyway to mirror
// a real registry.
func (reg *fakeOCIRegistry) serveBlob(w http.ResponseWriter, r *http.Request, repoKey, dg string) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	store, ok := reg.repos[repoKey]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	body, ok := store.blobs[dg]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Docker-Content-Digest", dg)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// pushAttestation builds a smithmark shaped attestation (an OCI image manifest
// whose single layer is the sigstore bundle, mirroring pkg/compose.packBundle)
// and stores it in the repository named by fullRepo under tag. fullRepo carries
// the host prefix that AttestationRef produced; the registry keys storage by
// the repository path alone (what a request URL carries), so that prefix is
// stripped here. It returns the exact layer bytes so a caller can assert the
// discovered bundle is byte identical.
func (reg *fakeOCIRegistry) pushAttestation(t *testing.T, fullRepo, tag string) []byte {
	t.Helper()
	repoKey := strings.TrimPrefix(fullRepo, reg.host+"/")

	layerBytes := testSignedBundle().Bundle
	layerMediaType := testSignedBundle().MediaType
	layerDesc := descriptorOf(layerMediaType, layerBytes)

	configBytes := []byte("{}")
	configDesc := descriptorOf("application/vnd.oci.empty.v1+json", configBytes)

	m := ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: layerMediaType,
		Config:       configDesc,
		Layers:       []ocispec.Descriptor{layerDesc},
	}
	manifestBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshaling attestation manifest: %v", err)
	}
	manifestDesc := descriptorOf(ocispec.MediaTypeImageManifest, manifestBytes)

	reg.mu.Lock()
	defer reg.mu.Unlock()
	store, ok := reg.repos[repoKey]
	if !ok {
		store = newRepoStorage()
		reg.repos[repoKey] = store
	}
	store.blobs[layerDesc.Digest.String()] = layerBytes
	store.blobs[configDesc.Digest.String()] = configBytes
	store.blobs[manifestDesc.Digest.String()] = manifestBytes
	store.manifests[manifestDesc.Digest.String()] = manifestDesc
	store.tags[tag] = manifestDesc.Digest.String()
	return layerBytes
}

// descriptorOf builds the OCI descriptor for content: its media type, its
// canonical sha256 digest, and its size, the same triple content.FetchAll
// verifies a fetched blob against.
func descriptorOf(mediaType string, content []byte) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    godigest.FromBytes(content),
		Size:      int64(len(content)),
	}
}

// remoteTargetFactory is the NewTarget the live tests inject: it builds a real
// oras remote.Repository for whatever repository discovery scopes it to, over
// plain HTTP so it can talk to the httptest server. This is the production code
// path a CLI would use, exercised end to end here.
func remoteTargetFactory(_ context.Context, r string) (oras.ReadOnlyGraphTarget, error) {
	repository, err := remote.NewRepository(r)
	if err != nil {
		return nil, err
	}
	repository.PlainHTTP = true
	return repository, nil
}

// --- the live round trip tests ------------------------------------------------

// TestLiveDiscoveryFindsAttestationInPerArtifactRepo pushes the attestation to
// the per artifact repository <base>/npm/<name> under its D3 tag and asserts a
// real remote.Repository backed discovery finds exactly that one bundle, byte
// identical to what was pushed. This is the positive half of the "would have
// caught it live" proof; the mutation check in the task report shows it fails
// (0 bundles) the moment discovery queries the bare base instead.
func TestLiveDiscoveryFindsAttestationInPerArtifactRepo(t *testing.T) {
	reg := newFakeOCIRegistry(t)
	// The attestation base is the httptest host plus a path segment, mirroring
	// a real base such as "registry.example.com/attest": the per artifact
	// repository is base/npm/<name>, and the bare base is itself a distinct,
	// valid repository, which is exactly what the mutation check queries.
	base := reg.host + "/attest"
	tr := npmTransport(t, http.StatusNotFound, nil)

	// The D3 (repo, tag) is computed from the same npm ArtifactRef that Resolve
	// derives from the fixture packument npmTransport serves, so the tag the
	// registry is seeded with is exactly the tag discovery will request.
	repo, tag, err := discover.AttestationRef(base, fixtureNPMRef())
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	want := reg.pushAttestation(t, repo, tag)

	disc, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      base,
		Transport: tr,
		NewTarget: remoteTargetFactory,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(disc.Bundles) != 1 {
		t.Fatalf("found %d bundles, want 1 at the per artifact repository %q", len(disc.Bundles), repo)
	}
	if !bytes.Equal(disc.Bundles[0], want) {
		t.Errorf("discovered bundle bytes do not match the pushed layer\n got: %s\nwant: %s", disc.Bundles[0], want)
	}
	if !notesHavePrefix(disc.Notes, discover.NoteAttestationTag) {
		t.Errorf("notes = %v, want a %s note", disc.Notes, discover.NoteAttestationTag)
	}
}

// TestLiveDiscoveryDoesNotFindAttestationAtBareBase pushes the same manifest and
// tag to the bare <base> repository only, never to the per artifact repository,
// and asserts discovery finds zero bundles with a NoteNoAttestationTag note. A
// correctly scoped client queries base/npm/<name>, which is empty, and never
// sees the decoy sitting at the bare base. This is the assertion that fails
// against the pre Task 2 code.
func TestLiveDiscoveryDoesNotFindAttestationAtBareBase(t *testing.T) {
	reg := newFakeOCIRegistry(t)
	base := reg.host + "/attest"
	tr := npmTransport(t, http.StatusNotFound, nil)

	// Seed the decoy at the bare base repository (host + "/attest"), never at
	// the per artifact repository the correctly scoped client will query.
	_, tag, err := discover.AttestationRef(base, fixtureNPMRef())
	if err != nil {
		t.Fatalf("AttestationRef: %v", err)
	}
	reg.pushAttestation(t, base, tag)

	disc, err := discover.Resolve(context.Background(), fixtureNPMName+"@"+fixtureNPMVersion, mustResolveOptions(t, discover.ResolveOptions{
		Base:      base,
		Transport: tr,
		NewTarget: remoteTargetFactory,
	}))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(disc.Bundles) != 0 {
		t.Fatalf("found %d bundles, want 0; a decoy at the bare base must not be discovered by a per artifact scoped client", len(disc.Bundles))
	}
	if !notesHavePrefix(disc.Notes, discover.NoteNoAttestationTag) {
		t.Errorf("notes = %v, want a %s note for the absent per artifact tag", disc.Notes, discover.NoteNoAttestationTag)
	}
}
