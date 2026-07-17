// This file implements the OCI half of spec section 6 discovery: resolving
// an OCI image reference argument to a subject descriptor via an injected
// oras.ReadOnlyGraphTarget, then walking the OCI referrers graph (the same
// API surface pkg/compose's AttachReferrer publishes onto, Task 2.7) to find
// candidate sigstore bundles attached to it.
package discover

import (
	"context"
	"regexp"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// sigstoreBundleMediaTypePrefix identifies the sigstore bundle media type
// family: both the current "application/vnd.dev.sigstore.bundle.v0.3+json"
// form and the older "application/vnd.dev.sigstore.bundle+json;version=0.1"
// style form share this prefix (per sigstore's own protobuf-specs bundle
// documentation, which requires clients to keep accepting the older forms).
// A referrer manifest's artifactType is checked against this prefix rather
// than an exact string, so a future minor bundle schema bump does not
// silently stop being discovered.
const sigstoreBundleMediaTypePrefix = "application/vnd.dev.sigstore.bundle"

// ociDigestSuffix matches an "@algo:hex" digest suffix, for example
// "@sha256:deadbeef...", the shape an OCI reference uses in place of a tag.
var ociDigestSuffix = regexp.MustCompile(`@[a-z0-9]+:[0-9a-f]{32,}$`)

// looksLikeOCIRef reports whether arg has the shape of an OCI image
// reference rather than an npm "name@version" argument (controller
// resolution 3): it carries a slash, and either a colon beyond any scheme
// prefix (a repository plus tag, or a host plus port) or an "@algo:hex"
// digest suffix. A scoped npm argument such as
// "@modelcontextprotocol/server-filesystem@1.0.0" also carries a slash and an
// "@", but never a colon, and its "@" is never followed by "algo:hex", so it
// is never misclassified as an OCI reference by this check.
func looksLikeOCIRef(arg string) bool {
	if !strings.Contains(arg, "/") {
		return false
	}
	return hasColonBeyondScheme(arg) || ociDigestSuffix.MatchString(arg)
}

// hasColonBeyondScheme reports whether arg contains a colon once any leading
// "scheme://" prefix is stripped, so a scheme's own colon and double slash
// are never themselves mistaken for a tag or port separator.
func hasColonBeyondScheme(arg string) bool {
	rest := arg
	if i := strings.Index(arg, "://"); i >= 0 {
		rest = arg[i+3:]
	}
	return strings.Contains(rest, ":")
}

// ociReference extracts the tag or digest reference oras's Target.Resolve
// expects from arg: a Target such as a memory store, or any other simple
// target, is already scoped to one repository (mirroring
// pkg/compose.PushAttestation's repo parameter, which goes unused against
// such a target for the same reason), so only the trailing tag or digest
// matters here, never the repository path.
func ociReference(arg string) string {
	if loc := ociDigestSuffix.FindStringIndex(arg); loc != nil {
		return arg[loc[0]+1:]
	}
	rest := arg
	if i := strings.Index(arg, "://"); i >= 0 {
		rest = arg[i+3:]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		return rest[i+1:]
	}
	return arg
}

// resolveOCIIdentity resolves arg's tag or digest reference against
// opts.Target and builds the resulting ArtifactRef: kind mcp-server (spec
// section 6's OCI referrers row is the OCI distributed MCP server case),
// source oci, name arg verbatim (no better identity is available from a bare
// reference), and a digest set carrying the resolved descriptor's own
// algorithm and hex encoded digest.
func resolveOCIIdentity(ctx context.Context, arg string, opts ResolveOptions) (manifest.ArtifactRef, ocispec.Descriptor, []string, error) {
	if opts.Target == nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil,
			codes.E(codes.DiscoveryFailed, "oci reference %q given but no OCI target was configured", arg)
	}
	reference := ociReference(arg)
	desc, err := opts.Target.Resolve(ctx, reference)
	if err != nil {
		return manifest.ArtifactRef{}, ocispec.Descriptor{}, nil,
			codes.E(codes.DiscoveryFailed, "resolving oci reference %q: %v", arg, err)
	}

	ref := manifest.ArtifactRef{
		Kind:   manifest.KindMCPServer,
		Name:   arg,
		Source: manifest.SourceOCI,
		Digest: manifest.DigestSet{desc.Digest.Algorithm().String(): desc.Digest.Encoded()},
	}
	notes := []string{notef(NoteOCIResolved, "resolved oci reference %q to digest %s via the injected target", arg, desc.Digest)}
	return ref, desc, notes, nil
}

// discoverReferrers lists subject's referrers in target (the same
// registry.Referrers API surface Task 2.7's AttachReferrer publishes onto)
// and collects the layer bytes of every referrer whose artifactType matches
// the sigstore bundle media type family. A referrer manifest or layer that
// fails to fetch or decode is DISCOVERY_FAILED; finding no matching
// referrers at all is not an error, just zero candidate bundles.
func discoverReferrers(ctx context.Context, target oras.ReadOnlyGraphTarget, subject ocispec.Descriptor) ([][]byte, []string, error) {
	referrers, err := registry.Referrers(ctx, target, subject, "")
	if err != nil {
		return nil, nil, codes.E(codes.DiscoveryFailed, "listing referrers for %s: %v", subject.Digest, err)
	}

	var bundles [][]byte
	for _, r := range referrers {
		if !strings.HasPrefix(r.ArtifactType, sigstoreBundleMediaTypePrefix) {
			continue
		}
		layers, err := fetchManifestLayers(ctx, target, r)
		if err != nil {
			return nil, nil, err
		}
		bundles = append(bundles, layers...)
	}
	notes := []string{notef(NoteReferrers, "found %d referrer(s), %d sigstore bundle candidate(s)", len(referrers), len(bundles))}
	return bundles, notes, nil
}
