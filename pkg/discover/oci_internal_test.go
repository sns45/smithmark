package discover

import "testing"

// TestLooksLikeOCIRef pins the shape detection controller resolution 3
// describes: a slash plus a colon beyond any scheme prefix, or a slash plus
// an "@algo:hex" digest suffix, marks arg as an OCI reference rather than an
// npm "name@version" argument. Scoped npm arguments deliberately share the
// slash-plus-"@" shape but never carry a colon or a digest suffix, so they
// must not be misclassified.
func TestLooksLikeOCIRef(t *testing.T) {
	cases := []struct {
		arg  string
		want bool
	}{
		{"ghcr.io/org/repo:latest", true},
		{"registry.example.com/attest/npm/example:sha512-abc.att", true},
		{"myregistry.io:5000/repo:tag", true},
		{"ghcr.io/org/repo@sha256:" + fortyByteHex, true},
		{"https://ghcr.io/org/repo:latest", true},
		{"left-pad@1.0.0", false},
		{"@modelcontextprotocol/server-filesystem@2026.7.10", false},
		{"no-slash-or-colon", false},
		{"just/a/path", false},
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			if got := looksLikeOCIRef(tc.arg); got != tc.want {
				t.Errorf("looksLikeOCIRef(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		})
	}
}

// fortyByteHex stands in for a plausible sha256 hex digest in test cases
// above; its exact value does not matter, only that it is hex.
const fortyByteHex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// TestOCIReferenceExtractsTrailingTagOrDigest asserts ociReference pulls out
// just the tag or digest portion a Target scoped to a single repository
// expects (mirroring pkg/compose.PushAttestation's repo/tag split), not the
// full reference string.
func TestOCIReferenceExtractsTrailingTagOrDigest(t *testing.T) {
	cases := []struct {
		arg  string
		want string
	}{
		{"ghcr.io/org/repo:latest", "latest"},
		{"myregistry.io:5000/repo:tag", "tag"},
		{"ghcr.io/org/repo@sha256:" + fortyByteHex, "sha256:" + fortyByteHex},
		{"https://ghcr.io/org/repo:latest", "latest"},
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			if got := ociReference(tc.arg); got != tc.want {
				t.Errorf("ociReference(%q) = %q, want %q", tc.arg, got, tc.want)
			}
		})
	}
}
