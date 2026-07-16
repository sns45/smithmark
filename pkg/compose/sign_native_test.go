//go:build !wasip1

package compose

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	"github.com/sigstore/sigstore-go/pkg/sign"
	sigsig "github.com/sigstore/sigstore/pkg/signature"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// writeEphemeralECDSAKey generates a fresh ECDSA P-256 key and writes it as a
// PKCS8 PEM into t.TempDir, returning the path and the public key for later
// verification. crypto/ecdsa generates the key per the task; PEM writing is
// plain encoding, and all signing and verification stay in sigstore libraries.
func writeEphemeralECDSAKey(t *testing.T) (string, *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating ephemeral ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalling PKCS8 key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "signing-key.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing key PEM: %v", err)
	}
	return path, &priv.PublicKey
}

// TestNativeSignerContract runs the shared platform independent contract
// against the real sigstore-go backed signer in key based mode.
func TestNativeSignerContract(t *testing.T) {
	keyPath, _ := writeEphemeralECDSAKey(t)
	s := NewSigner()

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pkg:npm/example@1.0.0"}]}`)
	sb, err := s.SignStatement(context.Background(), statement, SignOptions{KeyPath: keyPath})
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}
	if !strings.Contains(sb.MediaType, "sigstore.bundle") {
		t.Errorf("MediaType = %q, want a sigstore bundle media type", sb.MediaType)
	}

	env := dsseEnvelopeFromBundle(t, sb.Bundle)
	if got := env.GetPayloadType(); got != DSSEPayloadType {
		t.Errorf("payloadType = %q, want %q", got, DSSEPayloadType)
	}
	if got := env.GetPayload(); !bytes.Equal(got, statement) {
		t.Errorf("payload round trip mismatch:\n got %q\nwant %q", got, statement)
	}
}

// TestNativeKeySignRoundTrip is the key based signing round trip: sign a fixed
// statement with an ephemeral key, then verify the DSSE signature against that
// key's public half using sigstore's own verification primitive over the DSSE
// pre-auth encoding, not a hand rolled ecdsa.Verify.
func TestNativeKeySignRoundTrip(t *testing.T) {
	keyPath, pub := writeEphemeralECDSAKey(t)

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://in8.sh/attestation/agent-capability/v1","subject":[{"name":"widget","digest":{"sha256":"aa"}}]}`)
	sb, err := NewSigner().SignStatement(context.Background(), statement, SignOptions{KeyPath: keyPath})
	if err != nil {
		t.Fatalf("SignStatement: %v", err)
	}

	env := dsseEnvelopeFromBundle(t, sb.Bundle)
	sigs := env.GetSignatures()
	if len(sigs) != 1 {
		t.Fatalf("envelope carries %d signatures, want 1", len(sigs))
	}

	// Reconstruct the DSSE pre-auth encoding with sigstore-go's own encoder so
	// the bytes verified are exactly the bytes signed.
	pae := (&sign.DSSEData{Data: env.GetPayload(), PayloadType: env.GetPayloadType()}).PreAuthEncoding()

	verifier, err := sigsig.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		t.Fatalf("loading sigstore ECDSA verifier: %v", err)
	}
	if err := verifier.VerifySignature(bytes.NewReader(sigs[0].GetSig()), bytes.NewReader(pae)); err != nil {
		t.Fatalf("DSSE signature did not verify against the signing key: %v", err)
	}

	// A wrong key must be rejected, proving the check is real.
	_, otherPub := writeEphemeralECDSAKey(t)
	otherVerifier, err := sigsig.LoadVerifier(otherPub, crypto.SHA256)
	if err != nil {
		t.Fatalf("loading second verifier: %v", err)
	}
	if err := otherVerifier.VerifySignature(bytes.NewReader(sigs[0].GetSig()), bytes.NewReader(pae)); err == nil {
		t.Error("signature verified against an unrelated key; verification is not sound")
	}
}

// TestNativeNoConfigFailsClosed proves the native signer fails closed with the
// operational SIGNING_CONFIG_INVALID code, not SIGNING_UNAVAILABLE_PLATFORM,
// when handed neither a key path nor a complete keyless configuration.
func TestNativeNoConfigFailsClosed(t *testing.T) {
	_, err := NewSigner().SignStatement(context.Background(), []byte(`{}`), SignOptions{})
	if err == nil {
		t.Fatal("SignStatement with no configuration returned no error")
	}
	var coded *codes.Error
	if !errors.As(err, &coded) {
		t.Fatalf("error is not a coded *codes.Error: %v", err)
	}
	if coded.Code != codes.SigningConfigInvalid {
		t.Errorf("code = %q, want %q", coded.Code, codes.SigningConfigInvalid)
	}
}

// TestNativeBadKeyFailsCoded proves that key loading failures are coded
// SIGNING_CONFIG_INVALID rather than surfaced as an uncoded error: an
// unreadable path and an unparsable key file both fail closed with the code,
// so the CLI's machine readable stderr contract carries it.
func TestNativeBadKeyFailsCoded(t *testing.T) {
	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"x"}]}`)

	t.Run("unreadable key path", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "does-not-exist.pem")
		_, err := NewSigner().SignStatement(context.Background(), statement, SignOptions{KeyPath: missing})
		assertCode(t, err, codes.SigningConfigInvalid)
	})

	t.Run("unparsable key file", func(t *testing.T) {
		garbage := filepath.Join(t.TempDir(), "garbage.pem")
		if err := os.WriteFile(garbage, []byte("not a pem key at all"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := NewSigner().SignStatement(context.Background(), statement, SignOptions{KeyPath: garbage})
		assertCode(t, err, codes.SigningConfigInvalid)
	})
}

// dsseEnvelopeFromBundle parses a serialized sigstore bundle and returns its
// DSSE envelope, failing the test if the bundle is not a DSSE bundle.
func dsseEnvelopeFromBundle(t *testing.T, raw []byte) *protodsse.Envelope {
	t.Helper()
	var pb protobundle.Bundle
	if err := protojson.Unmarshal(raw, &pb); err != nil {
		t.Fatalf("bundle is not valid protojson: %v", err)
	}
	env := pb.GetDsseEnvelope()
	if env == nil {
		t.Fatal("bundle carries no DSSE envelope")
	}
	return env
}
