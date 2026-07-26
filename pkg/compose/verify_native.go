//go:build !wasip1

// This file holds the native verification implementation. It is compiled on
// every platform except wasip1, where verify_stub.go supplies a fail closed
// stub instead, because the sigstore stack does not compile under GOOS=wasip1
// (spec 2.1). All DSSE parsing and all cryptography go through the sigstore
// libraries; this package hand rolls no crypto (spec 2.2), and in particular it
// reconstructs the DSSE pre-authentication encoding with sigstore-go's own
// encoder so the bytes verified are exactly the bytes a Signer signed.

package compose

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// nativeVerifier is the real Verifier, backed by the sigstore signature
// libraries.
type nativeVerifier struct{}

// NewVerifier returns the native Verifier. The wasip1 build supplies a
// different NewVerifier from verify_stub.go that fails closed.
func NewVerifier() Verifier { return nativeVerifier{} }

// VerifyBundle parses bundle as a sigstore bundle, enforces the in-toto DSSE
// payloadType, and verifies its single DSSE signature against trustMaterial,
// which in v0.1 is a PEM encoded public key (the offline, key based path the CI
// exercises). On success it returns the DSSE payload, the in-toto statement
// bytes verification then parses, and whether a transparency log inclusion was
// cryptographically verified.
//
// rekorIncluded is false on this key based path and never an error when absent:
// key based offline bundles carry no transparency entry at all, and verifying an
// inclusion proof offline needs the log's public key from the Sigstore trust
// root. Keyless bundles are verified by VerifyKeylessBundle instead, which does
// consult the trust root and does require a Rekor inclusion. Even a bundle that
// did carry a tlog entry could not be cryptographically checked here without
// that key, so this build reports rekorIncluded false rather than trusting an
// unverified claim.
func (nativeVerifier) VerifyBundle(bundle, trustMaterial []byte, now time.Time) ([]byte, bool, error) {
	_ = now // no certificate validity window to check on the key based path.

	if len(trustMaterial) == 0 {
		return nil, false, codes.E(codes.SigningConfigInvalid,
			"no trust material provided; key based verification requires a PEM public key")
	}
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(trustMaterial)
	if err != nil {
		return nil, false, codes.E(codes.SigningConfigInvalid,
			"trust material is not a usable PEM public key: %v", err)
	}

	var pb protobundle.Bundle
	if err := protojson.Unmarshal(bundle, &pb); err != nil {
		return nil, false, fmt.Errorf("bundle is not a valid sigstore bundle: %w", err)
	}
	env := pb.GetDsseEnvelope()
	if env == nil {
		return nil, false, errors.New("bundle carries no DSSE envelope")
	}
	if pt := env.GetPayloadType(); pt != DSSEPayloadType {
		return nil, false, fmt.Errorf("unexpected DSSE payloadType %q, want %q", pt, DSSEPayloadType)
	}
	sigs := env.GetSignatures()
	if len(sigs) != 1 {
		return nil, false, fmt.Errorf("DSSE envelope carries %d signatures, want exactly 1", len(sigs))
	}

	verifier, err := sigsig.LoadDefaultVerifier(pub)
	if err != nil {
		return nil, false, codes.E(codes.SigningConfigInvalid,
			"loading a verifier for the trust material: %v", err)
	}
	pae := (&sign.DSSEData{Data: env.GetPayload(), PayloadType: env.GetPayloadType()}).PreAuthEncoding()
	if err := verifier.VerifySignature(bytes.NewReader(sigs[0].GetSig()), bytes.NewReader(pae)); err != nil {
		return nil, false, fmt.Errorf("DSSE signature did not verify against the trust material: %w", err)
	}

	return env.GetPayload(), false, nil
}
