//go:build wasip1

package compose

import (
	"time"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// stubVerifier is the wasip1 implementation. The sigstore stack does not
// compile under GOOS=wasip1 (spec 2.1), so the entire verification layer is
// behind this build tag interface and the wasip1 build gets a fail closed stub
// instead of the native verifier, mirroring the signing stub. There is no
// fallback and no silent skip: the call returns a coded error so a caller can
// detect, with errors.As, that verification was refused because of the platform
// rather than a bad signature or bad trust material.
type stubVerifier struct{}

// NewVerifier returns the wasip1 stub Verifier. The native build supplies a
// different NewVerifier from verify_native.go.
func NewVerifier() Verifier { return stubVerifier{} }

// VerifyBundle always fails closed with codes.SigningUnavailablePlatform. It
// does not log, does not fall back, and never returns a statement.
func (stubVerifier) VerifyBundle(_, _ []byte, _ time.Time) ([]byte, bool, error) {
	return nil, false, codes.E(codes.SigningUnavailablePlatform,
		"signature operations are unavailable on this platform; native builds only")
}
