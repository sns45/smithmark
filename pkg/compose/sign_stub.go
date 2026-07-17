//go:build wasip1

package compose

import (
	"context"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// stubSigner is the wasip1 implementation. sigstore-go does not compile under
// GOOS=wasip1 (spec 2.1), so the entire signing layer is behind this build tag
// interface and the wasip1 build gets a fail closed stub instead of the native
// signer. There is no fallback and no silent skip: every call returns a coded
// error so a caller can detect, with errors.As, that signing was refused
// because of the platform rather than a configuration or crypto failure.
type stubSigner struct{}

// NewSigner returns the wasip1 stub Signer. The native build supplies a
// different NewSigner from sign_native.go.
func NewSigner() Signer { return stubSigner{} }

// SignStatement always fails closed with codes.SigningUnavailablePlatform. It
// does not log, does not fall back, and never returns a bundle.
func (stubSigner) SignStatement(_ context.Context, _ []byte, _ SignOptions) (*SignedBundle, error) {
	return nil, codes.E(codes.SigningUnavailablePlatform,
		"signature operations are unavailable on this platform; native builds only")
}
