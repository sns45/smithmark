// This file implements the npm half of spec section 6 discovery: resolving
// an npm package's identity (name, version, tarball digest) from its
// packument, and fetching npm's own provenance attestation when present.
package discover

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
	"github.com/sns45/smithmark/pkg/core/verify"
)

// defaultNPMRegistry is the base URL Resolve talks to when
// ResolveOptions.Registry is left empty.
const defaultNPMRegistry = "https://registry.npmjs.org"

// maxRegistryResponseBytes caps how many bytes any single npm or MCP Registry
// response body this package reads: 32 MiB, comfortably above any real
// packument, attestations response, or registry entry, but bounded so a hostile
// or misbehaving endpoint cannot exhaust memory by streaming an unbounded body.
// It is shared by every response read here (fetchPackument, fetchNPMProvenance,
// and registry.go's FetchRegistryEntry) through readCapped.
const maxRegistryResponseBytes = 32 << 20

// readCapped reads from r up to maxRegistryResponseBytes and returns the bytes,
// treating a body that would exceed the cap as a DISCOVERY_FAILED failure rather
// than silently truncating it: a truncated body could decode into a different,
// attacker chosen shape. It reads one byte past the cap so the overflow is
// detected rather than masked by the limit landing exactly on the boundary.
func readCapped(r io.Reader, what string) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxRegistryResponseBytes+1))
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "reading %s: %v", what, err)
	}
	if int64(len(body)) > maxRegistryResponseBytes {
		return nil, codes.E(codes.DiscoveryFailed,
			"reading %s: response body exceeds the %d byte cap", what, maxRegistryResponseBytes)
	}
	return body, nil
}

// escapePackagePath percent encodes each slash separated segment of an npm
// package name for use as a URL path, keeping the scope separator slash literal
// (npm's packument and attestations endpoints expect .../@scope/name, a real
// slash between the two segments) while escaping any reserved character inside a
// segment. This stops a hostile name carrying a '?' or '#' from truncating the
// request path into a query or fragment and silently fetching a different
// resource; url.PathEscape leaves an ordinary scoped name's '@' and its
// segments untouched, so the common case still routes byte for byte.
func escapePackagePath(name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// packument is the shape this package decodes an npm packument into. A
// packument is a foreign, community owned format npm controls the schema of,
// not a smithmark authoring surface, so it is decoded leniently (a plain
// json.Unmarshal, not DisallowUnknownFields), matching this codebase's
// existing posture for every other format outside its own control: the npm
// attestations endpoint response below, package.json's smithmark key in
// attestbase.go, and SKILL.md frontmatter in local.go. Only the fields this
// type models are read; a real packument carries many more (author,
// maintainers, time, readme, per version scripts and dependencies, and
// more, repeated across every historical version it ever published), and
// every one of them is ignored rather than rejected. In contrast, smithmark's
// own formats (smithmark.yaml, the capability manifest) stay strict
// (DisallowUnknownFields), because those schemas are ours to keep exact.
// What stays loud regardless of this leniency is a needed field being
// missing or malformed: an absent version entry (resolveVersionKey returns
// false) and a malformed or absent dist.integrity (npmIntegrityToHex
// rejects it) both still fail resolution, they just do not fail merely
// because the packument carries extra fields this type does not model.
type packument struct {
	Name     string                      `json:"name"`
	DistTags map[string]string           `json:"dist-tags"`
	Versions map[string]packumentVersion `json:"versions"`
}

// packumentVersion is one entry of a packument's versions map: only the two
// dist fields Resolve needs to build an ArtifactRef.
type packumentVersion struct {
	Dist packumentDist `json:"dist"`
}

type packumentDist struct {
	Integrity string `json:"integrity"`
	Tarball   string `json:"tarball"`
}

// npmAttestationsResponse and npmAttestationEntry are the shape of npm's own
// "/-/npm/v1/attestations/{name}@{version}" endpoint response. This is
// decoded leniently (a plain json.Unmarshal, not DisallowUnknownFields),
// matching how this codebase already treats other foreign, community owned
// formats it does not control the schema of (package.json's smithmark key in
// attestbase.go, SKILL.md frontmatter in local.go): only the two fields this
// package reads are modeled, and everything else npm's response carries
// (signedAccessSignatureUrl, the full sigstore bundle's own many fields) is
// ignored rather than rejected.
type npmAttestationsResponse struct {
	Attestations []npmAttestationEntry `json:"attestations"`
}

type npmAttestationEntry struct {
	PredicateType string          `json:"predicateType"`
	Bundle        json.RawMessage `json:"bundle"`
}

// registryBase returns opts.Registry with any trailing slash trimmed, or
// defaultNPMRegistry when opts.Registry is empty.
func registryBase(opts ResolveOptions) string {
	if opts.Registry != "" {
		return strings.TrimSuffix(opts.Registry, "/")
	}
	return defaultNPMRegistry
}

// httpClient builds the *http.Client every npm request in this file is sent
// through. A nil opts.Transport is passed straight to http.Client.Transport,
// which net/http itself documents as meaning http.DefaultTransport, so no
// extra nil handling is needed here.
func httpClient(opts ResolveOptions) *http.Client {
	return &http.Client{Transport: opts.Transport}
}

// fetchPackument GETs {registry}/{name} and leniently decodes the response
// into a packument (see that type's doc comment for why leniently). Any
// request construction failure, transport error, non 200 status, or body
// that fails even a lenient decode is DISCOVERY_FAILED: unlike the
// attestations endpoint, a packument is not optional metadata, so there is
// no tolerated absence here.
func fetchPackument(ctx context.Context, opts ResolveOptions, name string) (*packument, error) {
	reqURL := fmt.Sprintf("%s/%s", registryBase(opts), escapePackagePath(name))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "building packument request for %s: %v", name, err)
	}
	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "fetching packument for %s: %v", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, codes.E(codes.DiscoveryFailed, "fetching packument for %s: unexpected status %s", name, resp.Status)
	}

	body, err := readCapped(resp.Body, fmt.Sprintf("packument body for %s", name))
	if err != nil {
		return nil, err
	}
	var pkg packument
	if err := json.Unmarshal(body, &pkg); err != nil {
		return nil, codes.E(codes.DiscoveryFailed, "decoding packument for %s: %v", name, err)
	}
	return &pkg, nil
}

// resolveVersionKey looks up version in pkg.Versions directly, then, when
// absent, treats version as a dist-tags alias (for example "latest") and
// resolves through that. Neither lookup succeeding is not itself an error;
// the caller decides what that means.
func resolveVersionKey(pkg *packument, version string) (string, bool) {
	if _, ok := pkg.Versions[version]; ok {
		return version, true
	}
	if tagged, ok := pkg.DistTags[version]; ok {
		if _, ok2 := pkg.Versions[tagged]; ok2 {
			return tagged, true
		}
	}
	return "", false
}

// npmIntegrityToHex converts an npm dist.integrity value of the form
// "sha512-<standard base64>" into its lowercase hex digest (U6). Only the
// sha512 algorithm is accepted, matching decision D3's npm tag mapping, which
// requires exactly 128 hex characters; a value under a different algorithm
// prefix, one that fails to decode as standard base64, or one that decodes
// to a length other than sha512.Size bytes, is rejected rather than silently
// truncated or padded.
func npmIntegrityToHex(integrity string) (string, error) {
	const prefix = "sha512-"
	if !strings.HasPrefix(integrity, prefix) {
		return "", codes.E(codes.DiscoveryFailed, "npm integrity value %q does not carry the sha512- prefix", integrity)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(integrity, prefix))
	if err != nil {
		return "", codes.E(codes.DiscoveryFailed, "npm integrity value %q is not valid base64: %v", integrity, err)
	}
	if len(raw) != sha512.Size {
		return "", codes.E(codes.DiscoveryFailed,
			"npm integrity value %q decodes to %d bytes, want %d (sha512)", integrity, len(raw), sha512.Size)
	}
	return hex.EncodeToString(raw), nil
}

// resolveNPMIdentity fetches name's packument, resolves version (direct or
// via a dist-tags alias), converts its dist.integrity to hex, and builds the
// resulting ArtifactRef. npm distributed artifacts are always mcp-server kind
// in this scheme (spec section 6's table has no npm distributed skill row),
// so Kind is fixed rather than taken from the caller.
func resolveNPMIdentity(ctx context.Context, name, version string, opts ResolveOptions) (manifest.ArtifactRef, []string, error) {
	pkg, err := fetchPackument(ctx, opts, name)
	if err != nil {
		return manifest.ArtifactRef{}, nil, err
	}
	verKey, ok := resolveVersionKey(pkg, version)
	if !ok {
		return manifest.ArtifactRef{}, nil, codes.E(codes.DiscoveryFailed,
			"npm packument for %s carries no version %q (and it is not a known dist-tag)", name, version)
	}
	digestHex, err := npmIntegrityToHex(pkg.Versions[verKey].Dist.Integrity)
	if err != nil {
		return manifest.ArtifactRef{}, nil, err
	}

	ref := manifest.ArtifactRef{
		Kind:    manifest.KindMCPServer,
		Name:    name,
		Version: verKey,
		Source:  manifest.SourceNPM,
		Digest:  manifest.DigestSet{"sha512": digestHex},
	}
	notes := []string{notef(NoteNPMResolved, "resolved npm package %s@%s via the packument at %s", name, verKey, registryBase(opts))}
	return ref, notes, nil
}

// fetchNPMProvenance GETs npm's own attestations endpoint for name@version
// and, when the response carries an entry whose predicateType is in the SLSA
// provenance family, returns that entry's raw bundle bytes. Selection keys off
// verify.SLSAProvenancePrefix, the exact same prefix the verify core's
// PROVENANCE_PRESENT check uses, so discovery and verification can never drift
// onto different predicate families and a newer provenance version (v2 and
// beyond) is still selected. A publish attestation carries a predicateType
// outside that family and is deliberately not what Discovered.NPMProvenance
// names. A 404 is tolerated (most packages carry no provenance at all) and
// recorded as a note, not an error; any other unexpected status, transport
// error, or undecodable body is DISCOVERY_FAILED.
func fetchNPMProvenance(ctx context.Context, opts ResolveOptions, name, version string) ([]byte, []string, error) {
	reqURL := fmt.Sprintf("%s/-/npm/v1/attestations/%s@%s", registryBase(opts), escapePackagePath(name), url.PathEscape(version))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "building npm provenance request for %s@%s: %v", name, version, err)
	}
	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "fetching npm provenance for %s@%s: %v", name, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, []string{notef(NoteNoProvenance, "no npm provenance found for %s@%s (404)", name, version)}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, codes.E(codes.DiscoveryFailed, "fetching npm provenance for %s@%s: unexpected status %s", name, version, resp.Status)
	}

	body, err := readCapped(resp.Body, fmt.Sprintf("npm provenance response for %s@%s", name, version))
	if err != nil {
		return nil, nil, err
	}
	var parsed npmAttestationsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "decoding npm provenance response for %s@%s: %v", name, version, err)
	}
	for _, a := range parsed.Attestations {
		if strings.HasPrefix(a.PredicateType, verify.SLSAProvenancePrefix) {
			return []byte(a.Bundle), []string{notef(NoteProvenanceFound, "found npm provenance attestation for %s@%s", name, version)}, nil
		}
	}
	return nil, []string{notef(NoteProvenanceNoMatch, "npm attestations present for %s@%s but none carry the SLSA provenance predicate", name, version)}, nil
}
