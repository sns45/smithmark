// This file implements spec section 6's discovery side: resolving a CLI
// argument (an npm "name@version", a local artifact directory, an OCI
// reference, or an explicit --bundle path) into an artifact reference plus
// whatever candidate attestation bundles can be found for it. Every network
// access, and every access to an OCI registry, is behind an injected
// http.RoundTripper or oras.ReadOnlyGraphTarget, so this package, and every
// test of it, stays free of real sockets (controller resolution 6).
package discover

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// ResolveOptions carries every input Resolve needs beyond the CLI argument
// itself. Base, BundlePath, and Registry are plain values a CLI flag surface
// sets directly; Transport and NewTarget are the two injection seams that
// keep every network and registry access replaceable in tests (controller
// resolution 2).
type ResolveOptions struct {
	// Base is the explicit --attestation-base flag value; it may be empty, in
	// which case ResolveAttestationBase falls through to the environment
	// variable and then, for local args only, package.json (D3).
	Base string
	// BundlePath is the explicit --bundle path. When set, it wins over all
	// attestation discovery (controller resolution 3): Resolve reads this
	// file directly for Discovered.Bundles and never calls opts.NewTarget for
	// attestation discovery, and never calls npm's provenance endpoint.
	// Artifact identity (Discovered.Ref) is still resolved normally from arg,
	// since a subject digest is needed for verification's digest match check
	// regardless of where the bundle bytes came from; for an OCI reference
	// argument specifically, that identity resolution step still calls
	// opts.NewTarget once, to scope a target to the image repository and
	// resolve the reference to a subject descriptor, even though the
	// referrers query that would otherwise follow never runs.
	BundlePath string
	// Transport is the http.RoundTripper every npm registry request is sent
	// through. A nil value means http.DefaultTransport (net/http's own
	// documented default when Client.Transport is nil); tests inject a
	// fixture serving round tripper instead so no test ever touches a real
	// socket.
	Transport http.RoundTripper
	// Registry is the npm registry base URL. Empty means
	// https://registry.npmjs.org.
	Registry string
	// RegistryAPI is the MCP Registry base URL FetchRegistryEntry talks to
	// (Task 3.6). Empty means the real registry.modelcontextprotocol.io,
	// the same injection pattern Registry above already uses for npm.
	RegistryAPI string
	// NewTarget constructs a read only OCI target scoped to a single
	// repository. Discovery computes the per artifact repository, the D3
	// <base>/<ecosystem>/<encoded-name> for the tag mapped path or the image
	// reference's own repository for the referrers path, and calls NewTarget
	// with it so the client queries the right path. A nil NewTarget means OCI
	// backed discovery is skipped with a note, not an error, exactly as a nil
	// target did before.
	NewTarget func(ctx context.Context, repo string) (oras.ReadOnlyGraphTarget, error)
}

// Discovered is what Resolve produces: the resolved artifact reference (with
// its digest populated whenever this package could determine one), every
// candidate sigstore bundle discovery found, npm's own provenance bundle
// when present, and human readable notes recording which resolution path was
// taken and why. Bundles being empty is never itself an error (U3 assigns
// that meaning to verification's ATTESTATION_MISSING check, not discovery).
type Discovered struct {
	Ref           manifest.ArtifactRef
	Bundles       [][]byte
	NPMProvenance []byte
	Notes         []string
}

// Note prefixes: every entry Resolve appends to Discovered.Notes begins with
// exactly one of these, followed by ": " and a human readable detail (see
// notef below). They are exported and stable so a downstream caller can key off
// the prefix rather than parsing prose. The consumer today is the CLI verify
// command's summary surface (cmd/smithmark), which prints each note to stderr as
// a "note:" line; keeping the prefix stable means a later change to the wording
// after the colon never breaks a caller keying off the prefix.
const (
	// NoteExplicitBundle reports that opts.BundlePath was set, so Bundles
	// came from that file and attestation discovery was skipped entirely.
	NoteExplicitBundle = "EXPLICIT_BUNDLE"
	// NoteNoDigest reports that no digest was resolved for the artifact at
	// all, so OCI backed attestation discovery (the D3 tag mapped path) was
	// skipped for lack of anything to map onto a tag.
	NoteNoDigest = "NO_DIGEST"
	// NoteNoDigestForSource reports that a local directory's declared
	// kind/source combination has no digest resolution path in v0.1 (only a
	// skill, or an mcp-server sourced from npm, do); identity is declaration
	// only.
	NoteNoDigestForSource = "NO_DIGEST_FOR_SOURCE"
	// NoteNoOCITarget reports that opts.NewTarget was nil, so the D3 tag
	// mapped fetch was skipped.
	NoteNoOCITarget = "NO_OCI_TARGET"
	// NoteNoAttestationTag reports that the D3 mapped tag was resolved but
	// does not exist in the target opts.NewTarget produced: an absent tag,
	// not an error (U3 assigns that meaning to verification's
	// ATTESTATION_MISSING check).
	NoteNoAttestationTag = "NO_ATTESTATION_TAG"
	// NoteAttestationTag reports that the D3 mapped tag was found in the
	// target opts.NewTarget produced, with the candidate bundle count that
	// yielded.
	NoteAttestationTag = "ATTESTATION_TAG_FOUND"
	// NoteLocalSkill reports that a local directory argument resolved to a
	// skill, with its bundle digest recomputed via the walker.
	NoteLocalSkill = "LOCAL_SKILL_RESOLVED"
	// NoteLocalNPM reports that a local directory argument declaring source
	// npm resolved its digest via the packument.
	NoteLocalNPM = "LOCAL_NPM_RESOLVED"
	// NoteNPMResolved reports that an npm package was resolved via its
	// packument (the pure npm argument form).
	NoteNPMResolved = "NPM_RESOLVED"
	// NoteNoProvenance reports that npm's attestations endpoint returned 404
	// for this package version: most packages carry no provenance at all,
	// tolerated rather than an error.
	NoteNoProvenance = "NO_PROVENANCE"
	// NoteProvenanceFound reports that npm's attestations endpoint carried an
	// entry whose predicateType is npm's SLSA provenance predicate.
	NoteProvenanceFound = "PROVENANCE_FOUND"
	// NoteProvenanceNoMatch reports that npm's attestations endpoint returned
	// attestations, but none of them carry the SLSA provenance predicate.
	NoteProvenanceNoMatch = "PROVENANCE_NO_MATCH"
	// NoteOCIResolved reports that an OCI reference argument resolved to a
	// subject descriptor via the target opts.NewTarget scoped to the image
	// repository.
	NoteOCIResolved = "OCI_RESOLVED"
	// NoteReferrers reports the outcome of the OCI referrers query: how many
	// referrers were found and how many of them matched the sigstore bundle
	// media type family.
	NoteReferrers = "REFERRERS"
)

// notef formats one Discovered.Notes entry: prefix, a colon and a space, then
// format and args rendered through fmt.Sprintf. Every note this package
// produces is built through this helper, so the prefix and the separator can
// never drift apart between call sites.
func notef(prefix, format string, args ...any) string {
	return prefix + ": " + fmt.Sprintf(format, args...)
}

// identity is Resolve's intermediate result before any attestation discovery
// runs: the resolved ArtifactRef, the local directory it was resolved from
// (empty for non local args, so ResolveAttestationBase's artifactRoot
// parameter is correctly empty per D3), and, only for the OCI reference
// argument form, the already resolved subject descriptor and the target
// already scoped to the image repository the referrers query needs.
type identity struct {
	ref          manifest.ArtifactRef
	artifactRoot string
	ociSubject   *ocispec.Descriptor
	ociTarget    oras.ReadOnlyGraphTarget
	notes        []string
}

// Resolve turns arg into a Discovered, dispatching on its shape: an existing
// local directory (kind and identity from its smithmark.yaml declaration), an
// OCI reference (referrers API against the target opts.NewTarget scopes to
// the image repository), or an npm "name@version" argument (packument
// resolution). Registry entry resolution (mcp-registry: prefixed names) is
// Task 3.6's job and is not handled here.
//
// Argument dispatch happens before opts.BundlePath is consulted: identity
// resolution is not "discovery" in spec section 6's sense (it never queries
// an attestation, only the artifact's own metadata), so it always runs.
// opts.BundlePath, when set, then short circuits every remaining step that
// would otherwise search for attestations: the OCI referrers query, the D3
// tag fetch, and the npm provenance fetch are all skipped in favor of reading
// the bundle file directly.
func Resolve(ctx context.Context, arg string, opts ResolveOptions) (*Discovered, error) {
	ident, err := resolveIdentity(ctx, arg, opts)
	if err != nil {
		return nil, err
	}
	d := &Discovered{Ref: ident.ref, Notes: append([]string(nil), ident.notes...)}

	if opts.BundlePath != "" {
		data, err := os.ReadFile(opts.BundlePath)
		if err != nil {
			return nil, codes.E(codes.DiscoveryFailed, "reading explicit bundle %s: %v", opts.BundlePath, err)
		}
		d.Bundles = [][]byte{data}
		d.Notes = append(d.Notes, notef(NoteExplicitBundle, "using explicit bundle %s; attestation discovery skipped", opts.BundlePath))
		return d, nil
	}

	if ident.ociSubject != nil {
		bundles, notes, err := discoverReferrers(ctx, ident.ociTarget, *ident.ociSubject)
		if err != nil {
			return nil, err
		}
		d.Bundles = bundles
		d.Notes = append(d.Notes, notes...)
		return d, nil
	}

	bundles, notes, err := discoverByTag(ctx, opts, ident.ref, ident.artifactRoot)
	if err != nil {
		return nil, err
	}
	d.Bundles = bundles
	d.Notes = append(d.Notes, notes...)

	if ident.ref.Source == manifest.SourceNPM {
		prov, provNotes, err := fetchNPMProvenance(ctx, opts, ident.ref.Name, ident.ref.Version)
		if err != nil {
			return nil, err
		}
		d.NPMProvenance = prov
		d.Notes = append(d.Notes, provNotes...)
	}
	return d, nil
}

// resolveIdentity classifies arg and dispatches to the matching resolution
// path: an existing local directory, an OCI reference shape, or else an npm
// "name@version" argument. An argument matching none of these is a
// DISCOVERY_FAILED error naming the argument, rather than a guess.
func resolveIdentity(ctx context.Context, arg string, opts ResolveOptions) (*identity, error) {
	if info, statErr := os.Stat(arg); statErr == nil && info.IsDir() {
		return resolveLocalIdentity(ctx, arg, opts)
	}
	if looksLikeOCIRef(arg) {
		ref, subject, target, notes, err := resolveOCIIdentity(ctx, arg, opts)
		if err != nil {
			return nil, err
		}
		return &identity{ref: ref, ociSubject: &subject, ociTarget: target, notes: notes}, nil
	}
	name, version, ok := parseNPMArg(arg)
	if !ok {
		return nil, codes.E(codes.DiscoveryFailed,
			"argument %q is not a recognized npm name@version, an existing local directory, or an oci reference", arg)
	}
	ref, notes, err := resolveNPMIdentity(ctx, name, version, opts)
	if err != nil {
		return nil, err
	}
	return &identity{ref: ref, notes: notes}, nil
}

// resolveLocalIdentity builds an ArtifactRef from a local directory's
// smithmark.yaml declaration (kind, name, version, source), then resolves the
// digest the one way each declared shape supports today: a skill's digest is
// always recomputed via the directory walker and the canonical bundle digest
// algorithm, regardless of source; an mcp-server declared with source npm
// resolves its digest via the packument, identically to the pure npm
// argument form. Any other kind/source combination has no digest resolution
// path in v0.1 and is recorded as a note rather than failed: Resolve's job is
// discovery, and an artifact this package cannot digest simply carries no
// digest forward, exactly as a caller supplying it directly would see.
func resolveLocalIdentity(ctx context.Context, root string, opts ResolveOptions) (*identity, error) {
	decl, err := LoadDeclared(filepath.Join(root, "smithmark.yaml"))
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "loading declared config at %s: %v", root, err)
	}
	ref := manifest.ArtifactRef{
		Kind:    decl.Manifest.Artifact.Kind,
		Name:    decl.Manifest.Artifact.Name,
		Version: decl.Manifest.Artifact.Version,
		Source:  decl.Manifest.Artifact.Source,
	}
	var notes []string

	switch {
	case ref.Kind == manifest.KindSkill:
		files, _, info, err := WalkSkill(root, decl.Executables)
		if err != nil {
			return nil, codes.E(codes.DiscoveryFailed, "walking skill bundle at %s: %v", root, err)
		}
		dg, err := bundle.Digest(files)
		if err != nil {
			return nil, codes.E(codes.DiscoveryFailed, "digesting skill bundle at %s: %v", root, err)
		}
		digestSet, err := manifest.SubjectDigestFromBundle(dg)
		if err != nil {
			return nil, codes.E(codes.DiscoveryFailed, "converting skill bundle digest at %s: %v", root, err)
		}
		ref.Digest = digestSet
		if ref.Version == "" && info.Version != "" {
			ref.Version = info.Version
		}
		notes = append(notes, notef(NoteLocalSkill, "resolved skill %q from local directory %s; bundle digest recomputed via the walker", ref.Name, root))
	case ref.Source == manifest.SourceNPM:
		// Deliberately verifies against what npm published, not against
		// whatever sits on disk in this local checkout: attest's
		// TarballDigest (Task 2.x) digests a local *.tgz tarball directly,
		// because attest is asserting a claim about a concrete artifact the
		// maker is about to publish. Resolve's job here is discovery for
		// verification, which must check the artifact a consumer would
		// actually install from npm, so fetching the packument's own
		// dist.integrity is the correct digest source even when the caller
		// pointed Resolve at a local source checkout. This is a deliberate
		// divergence from attest's tarball based digest, not an
		// inconsistency to reconcile.
		npmRef, npmNotes, err := resolveNPMIdentity(ctx, ref.Name, ref.Version, opts)
		if err != nil {
			return nil, err
		}
		ref.Digest = npmRef.Digest
		ref.Version = npmRef.Version
		notes = append(notes, npmNotes...)
		notes = append(notes, notef(NoteLocalNPM, "resolved npm identity for local directory %s via the packument", root))
	default:
		notes = append(notes, notef(NoteNoDigestForSource, "no digest resolution available for source %q at %s; identity is declaration only", ref.Source, root))
	}

	return &identity{ref: ref, artifactRoot: root, notes: notes}, nil
}

// parseNPMArg splits a "name@version" argument at the *last* "@", so a
// scoped package name's own leading "@scope/" marker is never mistaken for
// the version separator. An argument with no "@" past its first character
// (no version given at all) is rejected rather than guessed at: v0.1 has no
// "latest" default for the bare CLI argument form.
func parseNPMArg(arg string) (name, version string, ok bool) {
	idx := strings.LastIndexByte(arg, '@')
	if idx <= 0 {
		return "", "", false
	}
	name = arg[:idx]
	version = arg[idx+1:]
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// discoverByTag maps ref onto its D3 deterministic (repository, tag) pair and
// fetches that tag from the target opts.NewTarget produces. It is shared by
// every argument form that uses the tag mapped path: the pure npm argument,
// and a local directory resolving to a skill or an npm sourced mcp-server.
//
// Only two outcomes are notes, never errors: no OCI target factory
// configured, and an absent tag (errdef.ErrNotFound), both of which mean
// "nothing found," not "something went wrong" (U3 assigns failure meaning to
// verification's ATTESTATION_MISSING check, not to discovery). Every ref this
// function is ever called with already carries a digest (the len(ref.Digest)
// == 0 check above short circuits first, before this point, for the sources
// that have no canonical attestation home at all: a local sourced or
// mcp-registry sourced mcp-server never reaches here with a digest to map).
// That means AttestationRef can only fail here on an operational grammar or
// name problem, such as a malformed attestation base or a name segment that
// does not fit the OCI repository path grammar, never on "this source has no
// mapping": every such failure is therefore DISCOVERY_FAILED, wrapping the
// cause, not a silently swallowed note. ATTESTATION_BASE_UNKNOWN from
// ResolveAttestationBase surfaces verbatim (controller resolution 4); any
// other, unexpected error from opts.NewTarget or the target it produces is
// also DISCOVERY_FAILED.
func discoverByTag(ctx context.Context, opts ResolveOptions, ref manifest.ArtifactRef, artifactRoot string) ([][]byte, []string, error) {
	if len(ref.Digest) == 0 {
		return nil, []string{notef(NoteNoDigest, "no digest resolved for this artifact; skipping OCI backed attestation discovery")}, nil
	}

	base, err := ResolveAttestationBase(opts.Base, artifactRoot)
	if err != nil {
		return nil, nil, err
	}

	repo, tag, err := AttestationRef(base, ref)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "mapping attestation ref for %s %q: %v", ref.Kind, ref.Name, err)
	}

	if opts.NewTarget == nil {
		return nil, []string{notef(NoteNoOCITarget, "no OCI target factory configured; skipping tag based attestation discovery")}, nil
	}
	target, err := opts.NewTarget(ctx, repo)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "scoping attestation target to %q: %v", repo, err)
	}

	desc, err := target.Resolve(ctx, tag)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, []string{notef(NoteNoAttestationTag, "no attestation tag %s found", tag)}, nil
		}
		return nil, nil, codes.E(codes.DiscoveryFailed, "resolving attestation tag %s: %v", tag, err)
	}

	bundles, err := fetchManifestLayers(ctx, target, desc)
	if err != nil {
		return nil, nil, err
	}
	notes := []string{notef(NoteAttestationTag, "found attestation tag %s with %d bundle candidate(s)", tag, len(bundles))}
	return bundles, notes, nil
}

// fetchManifestLayers fetches the OCI manifest at desc and returns the raw
// bytes of each of its layers, in order. Both the D3 tag mapped path and the
// OCI referrers path (once a matching referrer manifest is found) share this:
// a smithmark attestation manifest, however it was discovered, is always a
// single OCI manifest wrapping the sigstore bundle as its one layer (mirrors
// pkg/compose.packBundle, the producer of this exact shape).
func fetchManifestLayers(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([][]byte, error) {
	manifestBytes, err := content.FetchAll(ctx, fetcher, desc)
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "fetching attestation manifest %s: %v", desc.Digest, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "decoding attestation manifest %s: %v", desc.Digest, err)
	}
	bundles := make([][]byte, 0, len(m.Layers))
	for _, layer := range m.Layers {
		layerBytes, err := content.FetchAll(ctx, fetcher, layer)
		if err != nil {
			return nil, codes.E(codes.DiscoveryFailed, "fetching attestation layer %s: %v", layer.Digest, err)
		}
		bundles = append(bundles, layerBytes)
	}
	return bundles, nil
}
