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
	"strings"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// defaultNPMRegistry is the base URL Resolve talks to when
// ResolveOptions.Registry is left empty.
const defaultNPMRegistry = "https://registry.npmjs.org"

// npmProvenancePredicateType identifies npm's own SLSA provenance attestation
// among the (possibly several) entries the npm attestations endpoint
// returns. A publish attestation carries a different predicateType and is
// deliberately not what Discovered.NPMProvenance names: that field is npm's
// provenance specifically, not every attestation npm happens to hold.
const npmProvenancePredicateType = "https://slsa.dev/provenance/v1"

// packument is the strict, minimal shape this package decodes an npm
// packument into. Only the fields Resolve actually consumes survive strict
// decoding (DisallowUnknownFields applies recursively, including through map
// values): a real packument carries many more fields than this type models
// (author, maintainers, time, readme, per version scripts and
// dependencies...), which is why the committed fixture
// (testdata/npm/packument.json) is a trimmed copy of a real packument rather
// than the real thing verbatim.
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

// fetchPackument GETs {registry}/{name} and strictly decodes the response
// into a packument. Any request construction failure, transport error,
// non 200 status, or undecodable body is DISCOVERY_FAILED: unlike the
// attestations endpoint, a packument is not optional metadata, so there is
// no tolerated absence here.
func fetchPackument(ctx context.Context, opts ResolveOptions, name string) (*packument, error) {
	url := fmt.Sprintf("%s/%s", registryBase(opts), name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	var pkg packument
	if err := dec.Decode(&pkg); err != nil {
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
	notes := []string{fmt.Sprintf("resolved npm package %s@%s via the packument at %s", name, verKey, registryBase(opts))}
	return ref, notes, nil
}

// fetchNPMProvenance GETs npm's own attestations endpoint for name@version
// and, when the response carries an entry whose predicateType is npm's SLSA
// provenance predicate, returns that entry's raw bundle bytes. A 404 is
// tolerated (most packages carry no provenance at all) and recorded as a
// note, not an error; any other unexpected status, transport error, or
// undecodable body is DISCOVERY_FAILED.
func fetchNPMProvenance(ctx context.Context, opts ResolveOptions, name, version string) ([]byte, []string, error) {
	url := fmt.Sprintf("%s/-/npm/v1/attestations/%s@%s", registryBase(opts), name, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "building npm provenance request for %s@%s: %v", name, version, err)
	}
	resp, err := httpClient(opts).Do(req)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "fetching npm provenance for %s@%s: %v", name, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, []string{fmt.Sprintf("no npm provenance found for %s@%s (404)", name, version)}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, codes.E(codes.DiscoveryFailed, "fetching npm provenance for %s@%s: unexpected status %s", name, version, resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "reading npm provenance response for %s@%s: %v", name, version, err)
	}
	var parsed npmAttestationsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "decoding npm provenance response for %s@%s: %v", name, version, err)
	}
	for _, a := range parsed.Attestations {
		if a.PredicateType == npmProvenancePredicateType {
			return []byte(a.Bundle), []string{fmt.Sprintf("found npm provenance attestation for %s@%s", name, version)}, nil
		}
	}
	return nil, []string{fmt.Sprintf("npm attestations present for %s@%s but none carry the SLSA provenance predicate", name, version)}, nil
}
