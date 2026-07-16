package discover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// attestationBaseEnvVar is the environment variable consulted second in the
// D3 base resolution order, after the explicit flag value and before the
// package.json fallback.
const attestationBaseEnvVar = "SMITHMARK_ATTESTATION_BASE"

// ResolveAttestationBase is the single implementation of decision D3's base
// resolution order: the explicit value (the --attestation-base flag) wins,
// then the SMITHMARK_ATTESTATION_BASE environment variable, then a
// smithmark.attestationBase key in the artifact's package.json; absent all
// three it returns a coded ATTESTATION_BASE_UNKNOWN error. Phase 3's Resolve
// must call this rather than reimplement the order, so the resolution can
// never fork into two subtly different copies.
func ResolveAttestationBase(explicit, artifactRoot string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv(attestationBaseEnvVar); env != "" {
		return env, nil
	}
	base, ok, err := attestationBaseFromPackageJSON(artifactRoot)
	if err != nil {
		return "", err
	}
	if ok {
		return base, nil
	}
	return "", codes.E(codes.AttestationBaseUnknown,
		"no attestation base; set --attestation-base, %s, or a smithmark.attestationBase key in package.json", attestationBaseEnvVar)
}

// attestationBaseFromPackageJSON reads the smithmark.attestationBase discovery
// key from the artifact's package.json (D3). A missing package.json, or one
// without the key, is not an error here: it simply means this resolution step
// did not supply a base. package.json carries only this discovery metadata,
// never capability declarations (U1).
func attestationBaseFromPackageJSON(root string) (string, bool, error) {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("reading package.json: %w", err)
	}
	var pkg struct {
		Smithmark struct {
			AttestationBase string `json:"attestationBase"`
		} `json:"smithmark"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", false, fmt.Errorf("parsing package.json: %w", err)
	}
	if pkg.Smithmark.AttestationBase == "" {
		return "", false, nil
	}
	return pkg.Smithmark.AttestationBase, true, nil
}
