package compose

import "context"

// DSSEPayloadType is the DSSE envelope payloadType every smithmark statement is
// signed under: the in-toto JSON media type (spec 2.3). Verification (M3) and
// every Signer implementation must agree on this exact string, so it lives in
// the platform independent file and is referenced, never restated as a literal.
const DSSEPayloadType = "application/vnd.in-toto+json"

// SignOptions selects the signing mode and carries its inputs. A non empty
// KeyPath selects key based, offline signing: the CI covered path, which never
// contacts a transparency log. The keyless fields drive Fulcio OIDC signing and
// are exercised live only in the M6 release workflow, where signing also submits
// to Rekor. When KeyPath is empty and the keyless inputs are incomplete, a
// native Signer fails closed with codes.SigningConfigInvalid rather than
// guessing.
type SignOptions struct {
	// KeyPath is the path to a PEM encoded private key. When set, signing runs
	// in key based, offline mode.
	KeyPath string

	// FulcioURL is the Fulcio certificate authority that issues a short lived
	// signing certificate from an OIDC identity (keyless mode).
	FulcioURL string
	// RekorURL is the Rekor transparency log the signature is submitted to
	// (keyless mode, M6).
	RekorURL string
	// OIDCIssuerURL is the OIDC issuer that vouches for the signing identity
	// (keyless mode).
	OIDCIssuerURL string
	// IdentityToken is a raw OIDC token supplied when the caller already holds
	// one, rather than driving an interactive OIDC flow (keyless mode).
	IdentityToken string
}

// SignedBundle is the result of signing a statement: a serialized sigstore
// bundle plus the media type that identifies its schema. Callers persist Bundle
// verbatim and attach MediaType alongside it; neither is ever re-encoded.
type SignedBundle struct {
	// Bundle is the sigstore bundle serialized as JSON (protojson of the
	// sigstore-go protobuf bundle). It carries the DSSE envelope, the
	// signature, and the verification material.
	Bundle []byte
	// MediaType is sigstore-go's own bundle media type, read off the produced
	// bundle rather than written as a literal, so it tracks whatever bundle
	// schema version sigstore-go stamped.
	MediaType string
}

// Signer wraps canonical statement bytes in a DSSE envelope and signs it,
// returning a serialized sigstore bundle. The native implementation
// (//go:build !wasip1) does the real work through sigstore-go; the wasip1 stub
// fails closed with codes.SigningUnavailablePlatform, because sigstore-go does
// not compile for wasip1 (spec 2.1). NewSigner, declared per platform, returns
// whichever implementation the build selected.
type Signer interface {
	// SignStatement signs the given statement bytes. The statement becomes the
	// DSSE payload under payloadType DSSEPayloadType. opts selects key based or
	// keyless mode.
	SignStatement(ctx context.Context, statement []byte, opts SignOptions) (*SignedBundle, error)
}
