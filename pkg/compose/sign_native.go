//go:build !wasip1

// This file holds the native signing implementation. It is compiled on every
// platform except wasip1, where sign_stub.go supplies a fail closed stub
// instead, because sigstore-go does not compile under GOOS=wasip1 (spec 2.1).
// All DSSE enveloping and all cryptography go through sigstore-go and the
// sigstore signing libraries; this package hand rolls no crypto (spec 2.2).

package compose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// nativeSigner is the real Signer, backed by sigstore-go.
type nativeSigner struct{}

// NewSigner returns the native Signer. The wasip1 build supplies a different
// NewSigner from sign_stub.go that fails closed.
func NewSigner() Signer { return nativeSigner{} }

// SignStatement wraps statement in a DSSE envelope with payloadType
// DSSEPayloadType and signs it with sigstore-go. A non empty opts.KeyPath
// selects offline key based signing (the CI covered path); a complete set of
// keyless inputs selects Fulcio OIDC signing (exercised live in CI). When
// neither is configured it fails closed with codes.SigningConfigInvalid.
func (nativeSigner) SignStatement(ctx context.Context, statement []byte, opts SignOptions) (*SignedBundle, error) {
	content := &sign.DSSEData{Data: statement, PayloadType: DSSEPayloadType}

	switch {
	case opts.KeyPath != "":
		return signWithKey(ctx, content, opts.KeyPath)
	case keylessConfigured(opts):
		return signKeyless(ctx, content, opts)
	default:
		return nil, codes.E(codes.SigningConfigInvalid,
			"no usable signing configuration: set KeyPath for key based signing, or provide Fulcio, Rekor, an OIDC issuer, and an identity token for keyless signing")
	}
}

// keylessConfigured reports whether every input keyless signing needs is
// present. The identity token carries the OIDC issuer in its claims, which
// Fulcio validates; the issuer URL is required here so a misconfigured release
// job fails closed rather than reaching Fulcio with a mismatched identity.
func keylessConfigured(opts SignOptions) bool {
	return opts.FulcioURL != "" &&
		opts.RekorURL != "" &&
		opts.OIDCIssuerURL != "" &&
		opts.IdentityToken != ""
}

// signWithKey signs offline with a supplied PEM key. It passes no Rekor,
// timestamp authority, certificate provider, or trusted root, so sign.Bundle
// stores public key verification material and never touches the network: the
// only mode a hermetic CI can exercise. Keyless signing adds the Rekor
// transparency log on top of this same DSSE flow.
func signWithKey(ctx context.Context, content *sign.DSSEData, keyPath string) (*SignedBundle, error) {
	keypair, err := newFileKeypair(keyPath)
	if err != nil {
		return nil, err
	}
	pb, err := sign.Bundle(content, keypair, sign.BundleOptions{Context: ctx})
	if err != nil {
		return nil, fmt.Errorf("signing statement with key %s: %w", keyPath, err)
	}
	return serializeBundle(pb)
}

// signKeyless signs with an ephemeral key certified by Fulcio and records the
// signature in Rekor. It contacts the network and is exercised live in CI
// release runs; no offline test drives it.
func signKeyless(ctx context.Context, content *sign.DSSEData, opts SignOptions) (*SignedBundle, error) {
	keypair, err := sign.NewEphemeralKeypair(nil)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral keyless signing key: %w", err)
	}
	fulcio := sign.NewFulcio(&sign.FulcioOptions{BaseURL: opts.FulcioURL})
	rekor := sign.NewRekor(&sign.RekorOptions{BaseURL: opts.RekorURL})
	pb, err := sign.Bundle(content, keypair, sign.BundleOptions{
		Context:                    ctx,
		CertificateProvider:        fulcio,
		CertificateProviderOptions: &sign.CertificateProviderOptions{IDToken: opts.IdentityToken},
		TransparencyLogs:           []sign.Transparency{rekor},
	})
	if err != nil {
		return nil, fmt.Errorf("keyless signing statement: %w", err)
	}
	return serializeBundle(pb)
}

// serializeBundle renders the sigstore bundle to JSON and reads its media type
// off the bundle itself, so MediaType tracks whatever schema version sigstore-go
// stamped rather than a literal restated here.
func serializeBundle(pb *protobundle.Bundle) (*SignedBundle, error) {
	raw, err := protojson.Marshal(pb)
	if err != nil {
		return nil, fmt.Errorf("serializing sigstore bundle: %w", err)
	}
	return &SignedBundle{Bundle: raw, MediaType: pb.GetMediaType()}, nil
}

// fileKeypair adapts a PEM loaded private key to sigstore-go's sign.Keypair
// interface, mirroring sigstore-go's own EphemeralKeypair: the signing itself
// is the standard library crypto.Signer, and the algorithm and hash choices come
// from the sigstore signature algorithm registry. No ECDSA math is written here.
type fileKeypair struct {
	signer     crypto.Signer
	algDetails sigsig.AlgorithmDetails
	hint       []byte
}

// newFileKeypair loads a PEM encoded private key (PKCS8, SEC1 EC, or PKCS1) via
// the sigstore cryptoutils loader and derives its signing algorithm from the
// sigstore algorithm registry.
func newFileKeypair(path string) (*fileKeypair, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, codes.E(codes.SigningConfigInvalid, "reading signing key %s: %v", path, err)
	}
	priv, err := cryptoutils.UnmarshalPEMToPrivateKey(pemBytes, cryptoutils.SkipPassword)
	if err != nil {
		return nil, codes.E(codes.SigningConfigInvalid, "parsing signing key %s: %v", path, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return nil, codes.E(codes.SigningConfigInvalid, "signing key %s does not implement crypto.Signer", path)
	}
	algDetails, err := sigsig.GetDefaultAlgorithmDetails(signer.Public())
	if err != nil {
		return nil, codes.E(codes.SigningConfigInvalid, "unsupported signing key in %s: %v", path, err)
	}
	hint, err := keyHint(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("fingerprinting signing key %s: %w", path, err)
	}
	return &fileKeypair{signer: signer, algDetails: algDetails, hint: hint}, nil
}

// keyHint fingerprints a public key the same way EphemeralKeypair does: the
// base64 of the SHA-256 of its PKIX encoding.
func keyHint(pub crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(pubBytes)
	return []byte(base64.StdEncoding.EncodeToString(sum[:])), nil
}

func (k *fileKeypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algDetails.GetProtoHashType()
}

func (k *fileKeypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algDetails.GetSignatureAlgorithm()
}

func (k *fileKeypair) GetHint() []byte { return k.hint }

func (k *fileKeypair) GetKeyAlgorithm() string {
	switch k.signer.Public().(type) {
	case *ecdsa.PublicKey:
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "ED25519"
	default:
		return ""
	}
}

func (k *fileKeypair) GetPublicKey() crypto.PublicKey { return k.signer.Public() }

func (k *fileKeypair) GetPublicKeyPem() (string, error) {
	pemBytes, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	if err != nil {
		return "", err
	}
	return string(pemBytes), nil
}

// SignData signs data with the loaded key, mirroring EphemeralKeypair.SignData:
// hash the pre-auth encoding with the algorithm's hash, then sign the digest
// through the standard library crypto.Signer. It returns the signature and the
// digest that was signed.
func (k *fileKeypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.algDetails.GetHashType()
	dataToSign := data
	if hf != crypto.Hash(0) {
		hasher := hf.New()
		hasher.Write(data)
		dataToSign = hasher.Sum(nil)
	}
	sig, err := k.signer.Sign(rand.Reader, dataToSign, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, dataToSign, nil
}
