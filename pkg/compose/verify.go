package compose

import "time"

// Verifier checks a serialized sigstore bundle's DSSE signature against trust
// material and returns the enveloped statement bytes plus whether a Rekor
// transparency log inclusion was cryptographically verified. It is the
// verification counterpart of Signer: the native implementation
// (//go:build !wasip1) does the real work through sigstore libraries; the
// wasip1 stub fails closed with codes.SigningUnavailablePlatform, because the
// sigstore stack does not compile for wasip1 (spec 2.1). NewVerifier, declared
// per platform, returns whichever implementation the build selected, exactly as
// NewSigner does.
//
// pkg/core/verify declares its own SignatureVerifier interface with this same
// method shape and consumes it, so the pure core never imports this package;
// the CLI wires a Verifier from here into verify.Run. The two interfaces are
// structurally identical, so a compose.Verifier satisfies verify.SignatureVerifier
// without either package importing the other.
type Verifier interface {
	// VerifyBundle verifies bundle's single DSSE signature against trustMaterial
	// and returns the DSSE payload (the in-toto statement bytes) together with
	// whether a transparency log inclusion was cryptographically verified. now is
	// the injected verification clock. A verification failure is returned as an
	// error; empty or unsupported trustMaterial is a coded
	// codes.SigningConfigInvalid error.
	VerifyBundle(bundle, trustMaterial []byte, now time.Time) (statement []byte, rekorIncluded bool, err error)
}
