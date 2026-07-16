// This file implements spec section 6's publish side: pushing a signed
// attestation bundle to an OCI target as a tagged artifact, and attaching it
// as a referrer of an existing OCI native artifact's subject descriptor. It
// builds on oras-go v2 (oras.land/oras-go/v2 v2.6.2, verified against that
// module's own source and tutorial at implementation time), which compiles
// cleanly under GOOS=wasip1 (unlike sigstore-go, see sign_native.go), so
// unlike the signing layer this file carries no build tag and no wasip1
// stub.

package compose

import (
	"context"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/discover"
)

// bundleManifestCreatedAnnotation is the fixed value both PushAttestation and
// AttachReferrer set for ocispec.AnnotationCreated. Left unset,
// oras.PackManifest stamps the real wall clock time into that annotation on
// every call, which would make two pushes of byte identical bundle content
// produce two different manifest digests. Pinning it to the RFC 3339 zero
// time keeps the packed manifest, and therefore its digest, reproducible
// across repeated pushes of the same bundle (controller resolution point 4,
// Task 2.7), the same technique oras-go's own PackManifest examples use to
// make their output reproducible.
const bundleManifestCreatedAnnotation = "1970-01-01T00:00:00Z"

// validateBundle rejects a nil SignedBundle, one carrying no bundle bytes,
// or one carrying an empty MediaType, coded PUBLISH_BUNDLE_INVALID, before
// either PushAttestation or AttachReferrer attempts any I/O. The MediaType
// check matters on its own: packBundle reads bundle.MediaType for both the
// layer mediaType and the manifest artifactType, and oras.PushBytes would
// otherwise happily push the layer blob under an empty mediaType before
// oras.PackManifest ever got a chance to reject it, an uncoded write that
// this check exists to prevent.
func validateBundle(bundle *SignedBundle) error {
	if bundle == nil {
		return codes.E(codes.PublishBundleInvalid, "signed bundle is nil")
	}
	if len(bundle.Bundle) == 0 {
		return codes.E(codes.PublishBundleInvalid, "signed bundle carries no bundle bytes")
	}
	if bundle.MediaType == "" {
		return codes.E(codes.PublishBundleInvalid, "signed bundle carries an empty MediaType")
	}
	return nil
}

// packBundle pushes bundle's raw bytes as a single content addressed layer
// under pusher, then packs and pushes an OCI v1.1 image manifest around that
// layer. artifactType and the layer's mediaType are both bundle.MediaType,
// read off the bundle rather than restated as a literal, so the manifest
// always advertises whatever bundle schema version produced it (spec 6).
// subject is nil for PushAttestation's tag based path and non-nil for
// AttachReferrer's referrer path; that is the only difference between the
// two call sites, so both share this helper.
func packBundle(ctx context.Context, pusher content.Pusher, subject *ocispec.Descriptor, bundle *SignedBundle) (ocispec.Descriptor, error) {
	layerDesc, err := oras.PushBytes(ctx, pusher, bundle.MediaType, bundle.Bundle)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing attestation bundle layer: %w", err)
	}
	manifestDesc, err := oras.PackManifest(ctx, pusher, oras.PackManifestVersion1_1, bundle.MediaType, oras.PackManifestOptions{
		Subject: subject,
		Layers:  []ocispec.Descriptor{layerDesc},
		ManifestAnnotations: map[string]string{
			ocispec.AnnotationCreated: bundleManifestCreatedAnnotation,
		},
	})
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("packing attestation manifest: %w", err)
	}
	return manifestDesc, nil
}

// PushAttestation packs the signed bundle as an OCI artifact (bundle.Bundle
// becomes the single layer, bundle.MediaType is both the layer's mediaType
// and the manifest's artifactType) and tags it as tag in target. It returns
// the manifest digest.
//
// repo is accepted but unused against the plain oras.Target abstraction: a
// memory store, and other simple targets, are already scoped to one
// repository, so there is nothing for repo to select at this layer. It stays
// in the signature because the CLI (a later task) resolves a remote
// repository client from repo before ever reaching this function, and
// dropping the parameter now would only mean re-adding it then.
//
// tag is validated against the OCI distribution spec tag grammar with
// discover.ValidOCITag before any push is attempted, coded
// PUBLISH_TAG_INVALID on failure. This is a last line of defense:
// pkg/discover.AttestationRef is the normative producer of push tags in this
// codebase and already builds them in a provably safe shape (Task 2.6); this
// check exists for a tag a caller assembled some other way.
func PushAttestation(ctx context.Context, target oras.Target, repo, tag string, bundle *SignedBundle) (string, error) {
	if err := validateBundle(bundle); err != nil {
		return "", err
	}
	if !discover.ValidOCITag(tag) {
		return "", codes.E(codes.PublishTagInvalid,
			"tag %q does not match the OCI distribution spec tag grammar", tag)
	}

	manifestDesc, err := packBundle(ctx, target, nil, bundle)
	if err != nil {
		return "", err
	}
	if err := target.Tag(ctx, manifestDesc, tag); err != nil {
		return "", fmt.Errorf("tagging attestation manifest as %s: %w", tag, err)
	}
	return manifestDesc.Digest.String(), nil
}

// AttachReferrer packs the bundle as a referrer of subject, for the OCI
// native artifacts publish path (spec 6): discovery walks the referrers
// graph instead of resolving a tag, so this function pushes the packed
// manifest but never tags it. On a GraphTarget such as a memory store,
// oras-go's registry.Referrers (backed by target's Predecessors) is how a
// caller later finds the manifest this returns the digest of.
func AttachReferrer(ctx context.Context, target oras.GraphTarget, subject ocispec.Descriptor, bundle *SignedBundle) (string, error) {
	if err := validateBundle(bundle); err != nil {
		return "", err
	}

	manifestDesc, err := packBundle(ctx, target, &subject, bundle)
	if err != nil {
		return "", err
	}
	return manifestDesc.Digest.String(), nil
}
