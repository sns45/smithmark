package compose

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// fakeSigner is an in package Signer that builds the DSSE envelope by hand,
// without sigstore-go or any crypto, so this contract test runs on every
// platform (it carries no build tag). It pins the contract every real Signer
// must honour: the statement bytes are wrapped in a DSSE envelope whose
// payloadType is application/vnd.in-toto+json and whose payload base64 decodes
// back to exactly the input statement.
type fakeSigner struct{}

// fakeEnvelope mirrors the DSSE envelope fields a sigstore bundle carries under
// its dsseEnvelope key, encoded the same way (payload and sig are base64).
type fakeEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []fakeSignature `json:"signatures"`
}

type fakeSignature struct {
	Sig string `json:"sig"`
}

func (fakeSigner) SignStatement(_ context.Context, statement []byte, _ SignOptions) (*SignedBundle, error) {
	env := fakeEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(statement),
		Signatures:  []fakeSignature{{Sig: base64.StdEncoding.EncodeToString([]byte("fake-signature"))}},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return &SignedBundle{Bundle: raw, MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json"}, nil
}

// signerContract runs the platform independent contract against any Signer.
func signerContract(t *testing.T, s Signer) {
	t.Helper()

	statement := []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"pkg:npm/example@1.0.0"}]}`)

	sb, err := s.SignStatement(context.Background(), statement, SignOptions{})
	if err != nil {
		t.Fatalf("SignStatement returned error: %v", err)
	}
	if sb == nil {
		t.Fatal("SignStatement returned a nil bundle with no error")
	}
	if sb.MediaType == "" {
		t.Error("SignedBundle.MediaType is empty; it must carry sigstore-go's bundle media type")
	}
	if len(sb.Bundle) == 0 {
		t.Fatal("SignedBundle.Bundle is empty")
	}

	var env fakeEnvelope
	if err := json.Unmarshal(sb.Bundle, &env); err != nil {
		t.Fatalf("bundle is not a JSON DSSE envelope: %v", err)
	}
	if env.PayloadType != DSSEPayloadType {
		t.Errorf("payloadType = %q, want %q", env.PayloadType, DSSEPayloadType)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("payload is not valid base64: %v", err)
	}
	if string(payload) != string(statement) {
		t.Errorf("payload round trip mismatch:\n got %q\nwant %q", payload, statement)
	}
}

func TestSignerContractFake(t *testing.T) {
	signerContract(t, fakeSigner{})
}

// TestDSSEPayloadTypeConstant guards the in-toto DSSE payloadType against an
// accidental edit: verification (M3) and every producer must agree on it.
func TestDSSEPayloadTypeConstant(t *testing.T) {
	if DSSEPayloadType != "application/vnd.in-toto+json" {
		t.Errorf("DSSEPayloadType = %q, want application/vnd.in-toto+json", DSSEPayloadType)
	}
}
