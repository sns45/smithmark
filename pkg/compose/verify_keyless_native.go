//go:build !wasip1

// This file holds the native keyless verification implementation, the v0.2.0
// counterpart of signKeyless: it verifies a Sigstore keyless bundle (a Fulcio
// certified ephemeral key with a Rekor transparency log inclusion) against the
// Sigstore trusted root and enforces the signing identity. It is compiled on
// every platform except wasip1, where verify_stub.go supplies a fail closed stub
// instead, because sigstore-go does not compile under GOOS=wasip1 (spec 2.1).
//
// All cryptography, certificate chain building, and Rekor inclusion checking go
// through sigstore-go (spec 2.2); this package hand rolls none of it. The verify
// shape mirrors assayward's nativeVerifier.Verify
// (pkg/core/verify/sigstore_native.go): resolve a trusted root (injected JSON
// else the public good live TUF root), parse the bundle, build a verifier that
// requires transparency log inclusion and an observer timestamp, verify, and
// extract the issuer and SAN from the verified certificate, failing closed when
// no certificate identity is produced. smithmark then additionally enforces that
// the extracted identity equals the caller's expected identity and issuer, which
// assayward leaves to a separate policy layer.

package compose

import (
	"errors"
	"fmt"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// liveTrustedRootConstructor creates the public good live trusted root. It is a
// package level variable so a test can substitute a fake, mirroring assayward's
// own seam; production uses the real sigstore-go constructor.
var liveTrustedRootConstructor = func(opts *tuf.Options) (root.TrustedMaterial, error) {
	return root.NewLiveTrustedRoot(opts)
}

// VerifyKeylessBundle verifies a Sigstore keyless bundle and enforces its
// signing identity, failing closed on any deviation. It is the verification
// counterpart of signKeyless. The steps, in order:
//
//  1. Reject a bundle that carries no Fulcio certificate (a key based bundle
//     handed to the keyless path) before any network work, so the wrong trust
//     mode fails closed offline rather than reaching for a live TUF root.
//  2. Resolve the trusted root: the injected sigstoreTrustRoot JSON when present
//     (the offline test path), else the public good live TUF root.
//  3. Parse the bundle and verify it, requiring Rekor transparency log inclusion
//     and an observer timestamp so the short lived Fulcio certificate validates.
//  4. Extract the issuer and SAN from the verified certificate, failing closed
//     when none is produced (mirrors assayward's guard).
//  5. Enforce that the SAN equals certificateIdentity and the issuer equals
//     certificateOIDCIssuer, failing closed on either mismatch.
//  6. Return the DSSE payload the bundle carries, now cryptographically
//     authenticated, and whether a transparency log inclusion was verified.
//
// A trusted root that cannot be resolved (an unparseable injected JSON, or an
// unreachable live root) is a coded codes.SigningConfigInvalid: verification
// could not be attempted at all, which the pure core treats the way it treats
// unusable key based trust material. Every other failure is an ordinary
// verification error the core records as a failed SIGNATURE_VALID.
func (nativeVerifier) VerifyKeylessBundle(bundleBytes, sigstoreTrustRoot []byte, certificateIdentity, certificateOIDCIssuer string, now time.Time) ([]byte, bool, error) {
	_ = now // certificate validity is checked against the bundle's own observer timestamp.

	// Reject a key based bundle up front, before any trusted root resolution, so
	// the wrong trust mode fails closed without a network round trip. A keyless
	// bundle carries a Fulcio certificate; a key based bundle carries a public
	// key identifier instead.
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundleBytes, &pb); err != nil {
		return nil, false, fmt.Errorf("bundle is not a valid sigstore bundle: %w", err)
	}
	vm := pb.GetVerificationMaterial()
	if vm == nil || (vm.GetCertificate() == nil && vm.GetX509CertificateChain() == nil) {
		return nil, false, errors.New("bundle carries no Fulcio signing certificate; it is not a keyless bundle (a key based bundle must be verified with --trust-root)")
	}

	// Resolve the trusted root: prefer the injected JSON (offline), else the
	// public good live TUF root. A failure here means verification could not be
	// attempted, so it is coded rather than recorded as a bad signature.
	trustedMaterial, err := resolveKeylessTrustedRoot(sigstoreTrustRoot)
	if err != nil {
		return nil, false, err
	}

	// Parse the bundle through sigstore-go's own bundle type for verification.
	b, err := sgbundle.NewBundle(&pb)
	if err != nil {
		return nil, false, fmt.Errorf("bundle is not a valid sigstore bundle: %w", err)
	}

	// Require transparency log inclusion (Rekor) and an observer timestamp so the
	// short lived Fulcio certificate can be validated at signing time.
	sev, err := sgverify.NewVerifier(
		root.TrustedMaterialCollection{trustedMaterial},
		sgverify.WithTransparencyLog(1),
		sgverify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, false, fmt.Errorf("building keyless verifier: %w", err)
	}

	// Verify the cryptographic chain and tlog inclusion without enforcing the
	// identity in sigstore-go's policy; the identity is extracted from the
	// verified certificate and enforced explicitly below, mirroring assayward's
	// extract then policy split so the fail closed identity guard is visible here.
	policy := sgverify.NewPolicy(
		sgverify.WithoutArtifactUnsafe(),
		sgverify.WithoutIdentitiesUnsafe(),
	)
	res, err := sev.Verify(b, policy)
	if err != nil {
		return nil, false, fmt.Errorf("keyless bundle did not verify: %w", err)
	}

	// Fail closed: a verification that produced no certificate identity is a
	// malformed or unexpected result and must not be treated as success.
	if res.Signature == nil || res.Signature.Certificate == nil {
		return nil, false, errors.New("verified keyless bundle carries no certificate identity")
	}
	cert := res.Signature.Certificate
	if err := enforceKeylessIdentity(cert.SubjectAlternativeName, cert.Extensions.Issuer, certificateIdentity, certificateOIDCIssuer); err != nil {
		return nil, false, err
	}

	// Rekor inclusion was required by WithTransparencyLog(1); a verified observer
	// timestamp confirms an inclusion was checked.
	rekorIncluded := len(res.VerifiedTimestamps) > 0
	if !rekorIncluded {
		return nil, false, errors.New("keyless bundle carries no verified Rekor transparency log inclusion")
	}

	// The DSSE payload the bundle carries is now cryptographically authenticated;
	// enforce the in-toto payloadType and hand back the statement bytes.
	statement, err := keylessStatement(&pb)
	if err != nil {
		return nil, false, err
	}
	return statement, true, nil
}

// resolveKeylessTrustedRoot returns the Sigstore trusted material for keyless
// verification: the injected JSON root when present (the offline test path), else
// the public good live TUF root. Either failure is coded
// codes.SigningConfigInvalid, since it means verification could not be attempted
// at all rather than that a signature was bad.
func resolveKeylessTrustedRoot(sigstoreTrustRoot []byte) (root.TrustedMaterial, error) {
	if len(sigstoreTrustRoot) > 0 {
		tr, err := root.NewTrustedRootFromJSON(sigstoreTrustRoot)
		if err != nil {
			return nil, codes.E(codes.SigningConfigInvalid,
				"injected Sigstore trust root is not a usable trusted root JSON: %v", err)
		}
		return tr, nil
	}
	ltr, err := liveTrustedRootConstructor(tuf.DefaultOptions())
	if err != nil {
		return nil, codes.E(codes.SigningConfigInvalid,
			"could not obtain the Sigstore public good trusted root for keyless verification: %v", err)
	}
	return ltr, nil
}

// enforceKeylessIdentity is the fail closed identity guard: it requires that the
// verified certificate's SubjectAlternativeName equals the expected identity and
// its OIDC issuer equals the expected issuer, both non empty. An empty expected
// value, or any mismatch, is a verification failure, never a pass: a keyless
// verification that does not pin the identity would be fail open. It is a pure
// string comparison so it is unit tested directly, without a live bundle.
func enforceKeylessIdentity(certSAN, certIssuer, wantIdentity, wantIssuer string) error {
	if wantIdentity == "" || wantIssuer == "" {
		return errors.New("keyless verification requires both an expected certificate identity and an expected OIDC issuer")
	}
	if certSAN != wantIdentity {
		return fmt.Errorf("certificate identity %q does not match the expected identity %q", certSAN, wantIdentity)
	}
	if certIssuer != wantIssuer {
		return fmt.Errorf("certificate OIDC issuer %q does not match the expected issuer %q", certIssuer, wantIssuer)
	}
	return nil
}

// keylessStatement extracts the DSSE payload from a verified keyless bundle and
// enforces the in-toto payloadType, the same contract the key based path checks.
// The signature over this payload was already verified by sigstore-go, so the
// bytes returned are authenticated.
func keylessStatement(pb *protobundle.Bundle) ([]byte, error) {
	env := pb.GetDsseEnvelope()
	if env == nil {
		return nil, errors.New("keyless bundle carries no DSSE envelope")
	}
	if pt := env.GetPayloadType(); pt != DSSEPayloadType {
		return nil, fmt.Errorf("unexpected DSSE payloadType %q, want %q", pt, DSSEPayloadType)
	}
	return env.GetPayload(), nil
}
