package discover_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/discover"
)

// TestResolveAttestationBase pins all four outcomes of the D3 base resolution
// order in one table: the explicit flag wins, then the environment variable,
// then a package.json key, else a coded ATTESTATION_BASE_UNKNOWN error. Each
// case sets the environment variable explicitly (empty when it must not
// contribute) so a value inherited from the runner cannot skew the result.
func TestResolveAttestationBase(t *testing.T) {
	const envVar = "SMITHMARK_ATTESTATION_BASE"

	t.Run("flag wins over env and package.json", func(t *testing.T) {
		root := t.TempDir()
		writePackageJSON(t, root, `{"smithmark":{"attestationBase":"pkg.example.com/attest"}}`)
		t.Setenv(envVar, "env.example.com/attest")
		got, err := discover.ResolveAttestationBase("flag.example.com/attest", root)
		if err != nil {
			t.Fatalf("ResolveAttestationBase: %v", err)
		}
		if got != "flag.example.com/attest" {
			t.Errorf("base = %q, want the flag value", got)
		}
	})

	t.Run("env wins over package.json when no flag", func(t *testing.T) {
		root := t.TempDir()
		writePackageJSON(t, root, `{"smithmark":{"attestationBase":"pkg.example.com/attest"}}`)
		t.Setenv(envVar, "env.example.com/attest")
		got, err := discover.ResolveAttestationBase("", root)
		if err != nil {
			t.Fatalf("ResolveAttestationBase: %v", err)
		}
		if got != "env.example.com/attest" {
			t.Errorf("base = %q, want the environment value", got)
		}
	})

	t.Run("package.json when no flag or env", func(t *testing.T) {
		root := t.TempDir()
		writePackageJSON(t, root, `{"smithmark":{"attestationBase":"pkg.example.com/attest"}}`)
		t.Setenv(envVar, "")
		got, err := discover.ResolveAttestationBase("", root)
		if err != nil {
			t.Fatalf("ResolveAttestationBase: %v", err)
		}
		if got != "pkg.example.com/attest" {
			t.Errorf("base = %q, want the package.json value", got)
		}
	})

	t.Run("unknown when nothing supplies a base", func(t *testing.T) {
		root := t.TempDir() // no package.json here
		t.Setenv(envVar, "")
		_, err := discover.ResolveAttestationBase("", root)
		var cerr *codes.Error
		if !errors.As(err, &cerr) {
			t.Fatalf("err = %v, want a *codes.Error carrying %s", err, codes.AttestationBaseUnknown)
		}
		if cerr.Code != codes.AttestationBaseUnknown {
			t.Fatalf("code = %s, want %s", cerr.Code, codes.AttestationBaseUnknown)
		}
	})
}

func writePackageJSON(t *testing.T, root, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
