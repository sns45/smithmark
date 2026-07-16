package discover

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// packageJSONPath is the fixed path every npm tarball entry roots its package
// manifest at: npm packs the package directory under a top level "package/".
const packageJSONPath = "package/package.json"

// TarballDigest resolves the npm tarball that identifies an mcp-server subject
// and returns its path, its sha512 digest set (the algorithm npm's own
// integrity string uses), and the name and version read out of the tarball's
// own package/package.json. An explicit path wins; otherwise exactly one *.tgz
// in root is autodetected, and zero or several fail closed with
// ATTEST_SUBJECT_UNRESOLVED rather than guessing which tarball to attest.
//
// The returned name and version let the caller cross check the tarball's own
// identity against the declaration where that declaration lives; the identity
// comparison itself is deliberately not done here. A tarball that carries no
// readable package/package.json is not an npm package tarball at all, so it
// also fails ATTEST_SUBJECT_UNRESOLVED: an npm tarball always carries one.
func TarballDigest(root, explicit string) (path string, digest manifest.DigestSet, name, version string, err error) {
	tarball, err := resolveTarballPath(root, explicit)
	if err != nil {
		return "", nil, "", "", err
	}
	digest, err = sha512DigestFile(tarball)
	if err != nil {
		return "", nil, "", "", err
	}
	name, version, err = readTarballPackageIdentity(tarball)
	if err != nil {
		return "", nil, "", "", err
	}
	return tarball, digest, name, version, nil
}

// resolveTarballPath returns the explicit path when set, else the sole *.tgz
// in root, failing closed with ATTEST_SUBJECT_UNRESOLVED when zero or several
// candidates make the subject ambiguous.
func resolveTarballPath(root, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	matches, err := filepath.Glob(filepath.Join(root, "*.tgz"))
	if err != nil {
		return "", fmt.Errorf("scanning %s for a tarball: %w", root, err)
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", codes.E(codes.AttestSubjectUnresolved,
			"no *.tgz tarball found in %s; pass --tarball to name the subject", root)
	default:
		return "", codes.E(codes.AttestSubjectUnresolved,
			"found %d *.tgz tarballs in %s; pass --tarball to select the subject", len(matches), root)
	}
}

// sha512DigestFile streams the raw tarball bytes through sha512, matching the
// npm integrity convention of digesting the tgz file itself.
func sha512DigestFile(path string) (manifest.DigestSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening tarball %s: %w", path, err)
	}
	defer f.Close()
	h := sha512.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, fmt.Errorf("hashing tarball %s: %w", path, err)
	}
	return manifest.DigestSet{"sha512": hex.EncodeToString(h.Sum(nil))}, nil
}

// readTarballPackageIdentity opens the tarball a second time, walks its gzip
// then tar stream to package/package.json, and decodes only the name and
// version fields. Unknown package.json fields are ignored deliberately: this
// is a foreign format the maker owns, and this function reads only the two
// identity fields it cross checks, not the whole document. A tarball that is
// not a gzip stream, cannot be read as a tar, or carries no
// package/package.json all fail with ATTEST_SUBJECT_UNRESOLVED.
func readTarballPackageIdentity(path string) (name, version string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", fmt.Errorf("opening tarball %s: %w", path, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", "", codes.E(codes.AttestSubjectUnresolved,
			"tarball %s is not a gzip stream, so it is not an npm package tarball: %v", path, err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", codes.E(codes.AttestSubjectUnresolved,
				"reading tarball %s as a tar stream failed, so it is not an npm package tarball: %v", path, err)
		}
		if strings.TrimPrefix(hdr.Name, "./") != packageJSONPath {
			continue
		}
		var pkg struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if err := json.NewDecoder(tr).Decode(&pkg); err != nil {
			return "", "", codes.E(codes.AttestSubjectUnresolved,
				"tarball %s carries an unreadable %s: %v", path, packageJSONPath, err)
		}
		return pkg.Name, pkg.Version, nil
	}
	return "", "", codes.E(codes.AttestSubjectUnresolved,
		"tarball %s carries no %s, so it is not an npm package tarball", path, packageJSONPath)
}
