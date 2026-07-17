package discover

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
)

// recordingTransport is a minimal internal http.RoundTripper for the tests in
// this file (package discover, so they reach the unexported fetchers directly,
// unlike resolve_test.go's external fixtureTransport). It captures the last
// requested URL path (for asserting on the escaped path a hostile name builds)
// and serves one canned response (for the response size cap and provenance
// family selection tests). It never touches a real socket.
type recordingTransport struct {
	status   int
	body     []byte
	lastPath string
}

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// EscapedPath is the on the wire path (percent encoded), the form that
	// actually reaches the server; URL.Path would report a decoded value and
	// hide whether a reserved character was escaped or left to truncate the path.
	r.lastPath = req.URL.EscapedPath()
	return &http.Response{
		StatusCode: r.status,
		Status:     fmt.Sprintf("%d %s", r.status, http.StatusText(r.status)),
		Body:       io.NopCloser(bytes.NewReader(r.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestResponseBodySizeCapRejectsOversizedBody exercises the shared response size
// cap at all three read sites: a body one byte past maxRegistryResponseBytes is
// a DISCOVERY_FAILED failure naming the cap, never silently truncated into a
// different, attacker chosen shape.
func TestResponseBodySizeCapRejectsOversizedBody(t *testing.T) {
	big := bytes.Repeat([]byte("a"), maxRegistryResponseBytes+1)
	opts := ResolveOptions{Transport: &recordingTransport{status: http.StatusOK, body: big}}
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"packument", func() error { _, err := fetchPackument(ctx, opts, "example"); return err }},
		{"provenance", func() error { _, _, err := fetchNPMProvenance(ctx, opts, "example", "1.0.0"); return err }},
		{"registry", func() error { _, err := FetchRegistryEntry(ctx, "example", opts); return err }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("expected an error for an oversized body, got nil")
			}
			if !strings.Contains(err.Error(), codes.DiscoveryFailed) {
				t.Errorf("err = %v, want it to carry %s", err, codes.DiscoveryFailed)
			}
			if !strings.Contains(err.Error(), "cap") {
				t.Errorf("err = %v, want it to name the response size cap", err)
			}
		})
	}
}

// TestFetchPackumentEscapesHostileName proves a package name carrying a reserved
// character (a question mark) is percent encoded into the request path, never
// left to truncate the path into a query string. The scope separator slash is
// kept literal so the packument endpoint still routes.
func TestFetchPackumentEscapesHostileName(t *testing.T) {
	tr := &recordingTransport{status: http.StatusOK, body: []byte(`{"name":"x","versions":{}}`)}
	_, _ = fetchPackument(context.Background(), ResolveOptions{Transport: tr}, "evil?pkg")
	if !strings.Contains(tr.lastPath, "evil%3Fpkg") {
		t.Errorf("requested path = %q, want it to carry the escaped name evil%%3Fpkg, never a truncated one", tr.lastPath)
	}
	if strings.Contains(tr.lastPath, "evil?") {
		t.Errorf("requested path = %q leaks an unescaped question mark; the name must not truncate the path", tr.lastPath)
	}
}

// TestFetchPackumentKeepsScopedNameRouting proves the per segment escaping keeps
// a real scoped name's path byte identical to what the packument endpoint
// expects (a literal @ and a literal scope separator slash), so escaping does
// not break the common case.
func TestFetchPackumentKeepsScopedNameRouting(t *testing.T) {
	tr := &recordingTransport{status: http.StatusOK, body: []byte(`{"name":"x","versions":{}}`)}
	_, _ = fetchPackument(context.Background(), ResolveOptions{Transport: tr}, "@modelcontextprotocol/server-filesystem")
	if tr.lastPath != "/@modelcontextprotocol/server-filesystem" {
		t.Errorf("requested path = %q, want /@modelcontextprotocol/server-filesystem", tr.lastPath)
	}
}

// TestFetchNPMProvenanceSelectsByFamilyPrefix proves provenance selection keys
// off the SLSA provenance family prefix (the same prefix the verify core uses),
// not an exact v1 string: a v2 provenance entry must still be selected.
func TestFetchNPMProvenanceSelectsByFamilyPrefix(t *testing.T) {
	body := []byte(`{"attestations":[` +
		`{"predicateType":"https://github.com/npm/attestation/tree/main/specs/publish/v0.1","bundle":{"publish":true}},` +
		`{"predicateType":"https://slsa.dev/provenance/v2","bundle":{"prov":"v2"}}` +
		`]}`)
	tr := &recordingTransport{status: http.StatusOK, body: body}
	prov, _, err := fetchNPMProvenance(context.Background(), ResolveOptions{Transport: tr}, "example", "1.0.0")
	if err != nil {
		t.Fatalf("fetchNPMProvenance: %v", err)
	}
	if prov == nil {
		t.Fatal("no provenance selected; a v2 SLSA provenance entry must be selected by family prefix")
	}
	if !bytes.Contains(prov, []byte(`"prov":"v2"`)) {
		t.Errorf("selected the wrong bundle: %s", prov)
	}
}

// TestNPMIntegrityToHexPinnedVector pins one known conversion (U6): the
// dist.integrity value committed in testdata/npm/packument.json for
// @modelcontextprotocol/server-filesystem 2026.7.10, converted to hex by hand
// (base64 decode the value after the "sha512-" prefix, hex encode the
// resulting 64 bytes) outside this package, so this test cannot pass by
// merely echoing back whatever the implementation happens to compute.
func TestNPMIntegrityToHexPinnedVector(t *testing.T) {
	const integrity = "sha512-Mmjg4anFBD5OzbPnGJOA0jPPN8645ERhQk38HQLpSenx1ox9bfdPkmAzUnNjeQtqQGFLtKe13J20RtLBmUKMZA=="
	const wantHex = "3268e0e1a9c5043e4ecdb3e7189380d233cf37ceb8e44461424dfc1d02e949e9f1d68c7d6df74f926033527363790b6a40614bb4a7b5dc9db446d2c199428c64"

	got, err := npmIntegrityToHex(integrity)
	if err != nil {
		t.Fatalf("npmIntegrityToHex: %v", err)
	}
	if got != wantHex {
		t.Errorf("npmIntegrityToHex(%q) = %q, want %q", integrity, got, wantHex)
	}
	if len(got) != npmDigestHexLen {
		t.Errorf("hex length = %d, want %d", len(got), npmDigestHexLen)
	}
}

func TestNPMIntegrityToHexRejectsWrongAlgorithm(t *testing.T) {
	_, err := npmIntegrityToHex("sha256-Mmjg4anFBD5OzbPnGJOA0jPPN8645ERhQk38HQLpSenx1ox9bfdA==")
	assertDiscoveryFailed(t, err)
}

func TestNPMIntegrityToHexRejectsBadBase64(t *testing.T) {
	_, err := npmIntegrityToHex("sha512-not-valid-base64!!!")
	assertDiscoveryFailed(t, err)
}

func TestNPMIntegrityToHexRejectsWrongLength(t *testing.T) {
	// Valid base64, but decodes to far fewer than 64 bytes.
	_, err := npmIntegrityToHex("sha512-YWJj")
	assertDiscoveryFailed(t, err)
}

// assertDiscoveryFailed fails t unless err is a *codes.Error carrying
// codes.DiscoveryFailed.
func assertDiscoveryFailed(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), codes.DiscoveryFailed) {
		t.Fatalf("err = %v, want it to carry %s", err, codes.DiscoveryFailed)
	}
}

// TestResolveVersionKeyDirectHit asserts a version present verbatim in the
// versions map is used as is, with no dist-tags lookup.
func TestResolveVersionKeyDirectHit(t *testing.T) {
	pkg := &packument{
		Versions: map[string]packumentVersion{
			"1.2.3": {},
		},
	}
	got, ok := resolveVersionKey(pkg, "1.2.3")
	if !ok || got != "1.2.3" {
		t.Errorf("resolveVersionKey = (%q, %v), want (1.2.3, true)", got, ok)
	}
}

// TestResolveVersionKeyDistTagAlias asserts a dist-tag alias such as "latest"
// resolves through DistTags to the concrete version it names.
func TestResolveVersionKeyDistTagAlias(t *testing.T) {
	pkg := &packument{
		DistTags: map[string]string{"latest": "2.0.0"},
		Versions: map[string]packumentVersion{
			"2.0.0": {},
		},
	}
	got, ok := resolveVersionKey(pkg, "latest")
	if !ok || got != "2.0.0" {
		t.Errorf("resolveVersionKey = (%q, %v), want (2.0.0, true)", got, ok)
	}
}

func TestResolveVersionKeyMissing(t *testing.T) {
	pkg := &packument{Versions: map[string]packumentVersion{"1.0.0": {}}}
	if _, ok := resolveVersionKey(pkg, "9.9.9"); ok {
		t.Error("resolveVersionKey found a version that does not exist")
	}
}

// TestParseNPMArg covers the "name@version" argument form, including scoped
// package names which themselves contain an "@" as the scope marker, so the
// version separator must be the *last* "@", not the first.
func TestParseNPMArg(t *testing.T) {
	cases := []struct {
		arg         string
		wantName    string
		wantVersion string
		wantOK      bool
	}{
		{"left-pad@1.0.0", "left-pad", "1.0.0", true},
		{"@modelcontextprotocol/server-filesystem@2026.7.10", "@modelcontextprotocol/server-filesystem", "2026.7.10", true},
		{"@scope/name", "", "", false},   // no version separator
		{"no-at-sign", "", "", false},    // no "@" at all
		{"@leading-only", "", "", false}, // "@" at index 0 with nothing after it that looks like name@version
	}
	for _, tc := range cases {
		t.Run(tc.arg, func(t *testing.T) {
			name, version, ok := parseNPMArg(tc.arg)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if name != tc.wantName || version != tc.wantVersion {
				t.Errorf("parseNPMArg(%q) = (%q, %q), want (%q, %q)", tc.arg, name, version, tc.wantName, tc.wantVersion)
			}
		})
	}
}
