//go:build !wasip1

package compose

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// keyBasedBundleFixture is the committed, key based (public key, no Fulcio
// certificate, no Rekor entry) skill bundle. The keyless path must reject it,
// since it is not a keyless bundle. The path is relative to pkg/compose, two
// directories below the repo root.
const keyBasedBundleFixture = "../../testdata/signature/skill/valid.sigstore.json"

// TestEnforceKeylessIdentity is the direct, offline proof of the fail closed
// identity guard, the security critical comparison at the heart of keyless
// verification. A live keyless bundle is not needed to prove that a mismatched
// or half specified identity is refused: the guard is a pure string comparison,
// so it is exercised here with fabricated certificate values. A bug that made
// any of the error cases return nil would be fail open.
func TestEnforceKeylessIdentity(t *testing.T) {
	const (
		san    = "https://github.com/sns45/smithmark/.github/workflows/release.yml@refs/tags/v0.2.0"
		issuer = "https://token.actions.githubusercontent.com"
	)
	cases := []struct {
		name                     string
		certSAN, certIssuer      string
		wantIdentity, wantIssuer string
		wantErr                  bool
	}{
		{"exact match", san, issuer, san, issuer, false},
		{"san mismatch", "https://evil.example/attacker", issuer, san, issuer, true},
		{"issuer mismatch", san, "https://accounts.google.com", san, issuer, true},
		{"both mismatch", "https://evil.example/x", "https://evil.example/i", san, issuer, true},
		{"empty expected identity", san, issuer, "", issuer, true},
		{"empty expected issuer", san, issuer, san, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := enforceKeylessIdentity(c.certSAN, c.certIssuer, c.wantIdentity, c.wantIssuer)
			if c.wantErr && err == nil {
				t.Fatalf("enforceKeylessIdentity(%q,%q,%q,%q) = nil, want a fail closed error",
					c.certSAN, c.certIssuer, c.wantIdentity, c.wantIssuer)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("enforceKeylessIdentity(matching identity) = %v, want nil", err)
			}
		})
	}
}

// TestVerifyKeylessRejectsKeyBasedBundle proves a key based bundle handed to the
// keyless verifier fails closed before any network work, with a plain (not
// config coded) error so the pure core records it as a failed SIGNATURE_VALID
// (exit 1) rather than an operational could-not-attempt (exit 3). No trust root
// is injected and none is fetched: the missing Fulcio certificate is detected
// first.
func TestVerifyKeylessRejectsKeyBasedBundle(t *testing.T) {
	bundleBytes, err := os.ReadFile(keyBasedBundleFixture)
	if err != nil {
		t.Fatalf("reading key based bundle fixture: %v", err)
	}
	stmt, rekor, verr := nativeVerifier{}.VerifyKeylessBundle(bundleBytes, nil, "ci@example.com", "https://token.actions.githubusercontent.com", time.Now())
	if verr == nil {
		t.Fatal("VerifyKeylessBundle accepted a key based bundle; it must fail closed")
	}
	if stmt != nil || rekor {
		t.Errorf("failed keyless verification returned statement=%v rekor=%v, want nil/false", stmt, rekor)
	}
	var coded *codes.Error
	if errors.As(verr, &coded) && coded.Code == codes.SigningConfigInvalid {
		t.Errorf("key based bundle rejection is coded %s (exit 3); it must be an ordinary verification failure (exit 1)", coded.Code)
	}
}

// TestVerifyKeylessRejectsMalformedBundle proves a malformed bundle fails closed
// at the parse step with a plain verification error, never a panic and never a
// pass.
func TestVerifyKeylessRejectsMalformedBundle(t *testing.T) {
	stmt, rekor, verr := nativeVerifier{}.VerifyKeylessBundle([]byte("{not a bundle"), nil, "ci@example.com", "https://token.actions.githubusercontent.com", time.Now())
	if verr == nil {
		t.Fatal("VerifyKeylessBundle accepted malformed bytes; it must fail closed")
	}
	if stmt != nil || rekor {
		t.Errorf("failed keyless verification returned statement=%v rekor=%v, want nil/false", stmt, rekor)
	}
}

// TestResolveKeylessTrustedRootRejectsBadJSON proves an unparseable injected
// trusted root is a config coded error (verification could not be attempted),
// mirroring the key based path's treatment of unusable trust material.
func TestResolveKeylessTrustedRootRejectsBadJSON(t *testing.T) {
	_, err := resolveKeylessTrustedRoot([]byte("not a trusted root"))
	if err == nil {
		t.Fatal("resolveKeylessTrustedRoot accepted garbage JSON; it must fail closed")
	}
	var coded *codes.Error
	if !errors.As(err, &coded) || coded.Code != codes.SigningConfigInvalid {
		t.Errorf("err = %v, want a %s coded error", err, codes.SigningConfigInvalid)
	}
}
