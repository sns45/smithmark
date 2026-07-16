package discover

import (
	"strings"
	"testing"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// assertValidOCITag fails t if tag does not match the OCI distribution spec
// tag grammar. Production tags are built from a fixed constant prefix plus
// lowercase hex plus ".att", so the shape is provably safe by construction
// and AttestationRef itself does not need a runtime check (Task 2.6
// resolution); this test asserts that guarantee holds, reusing the same
// ValidOCITag helper (Task 2.7) that pkg/compose's push path calls as its own
// last line of defense against a hand built tag.
func assertValidOCITag(t *testing.T, tag string) {
	t.Helper()
	if !ValidOCITag(tag) {
		t.Errorf("tag %q does not match the OCI tag grammar", tag)
	}
}

const testBase = "registry.example.com/attest"

func TestAttestationRef(t *testing.T) {
	npmSHA512 := strings.Repeat("a1", 64)    // 128 hex chars
	scopedSHA512 := strings.Repeat("b2", 64) // 128 hex chars
	pypiSHA256 := strings.Repeat("c3", 32)   // 64 hex chars
	skillDigest := strings.Repeat("d4", 32)  // 64 hex chars

	cases := []struct {
		name     string
		base     string
		ref      manifest.ArtifactRef
		wantRepo string
		wantTag  string
		wantCode string // empty means no error expected
	}{
		{
			name: "unscoped npm",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "better-call-claude",
				Source: manifest.SourceNPM,
				Digest: manifest.DigestSet{"sha512": npmSHA512},
			},
			wantRepo: testBase + "/npm/better-call-claude",
			wantTag:  "sha512-" + npmSHA512[:64] + ".att",
		},
		{
			name: "scoped npm lowercased",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "@Acme/Tool",
				Source: manifest.SourceNPM,
				Digest: manifest.DigestSet{"sha512": scopedSHA512},
			},
			wantRepo: testBase + "/npm/acme/tool",
			wantTag:  "sha512-" + scopedSHA512[:64] + ".att",
		},
		{
			name: "pypi PEP 503 normalization",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "Foo._-Bar",
				Source: manifest.SourcePyPI,
				Digest: manifest.DigestSet{"sha256": pypiSHA256},
			},
			wantRepo: testBase + "/pypi/foo-bar",
			wantTag:  "sha256-" + pypiSHA256 + ".att",
		},
		{
			name: "skill bundle digest",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindSkill,
				Name:   "hello-skill",
				Source: manifest.SourceLocal,
				Digest: manifest.DigestSet{"smithmark-bundle-v1": skillDigest},
			},
			wantRepo: testBase + "/skill/hello-skill",
			wantTag:  "bundle-v1-" + skillDigest + ".att",
		},
		{
			name: "skill kind uses skill mapping regardless of source",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindSkill,
				Name:   "hello-skill",
				Source: manifest.SourceMCPRegistry,
				Digest: manifest.DigestSet{"smithmark-bundle-v1": skillDigest},
			},
			wantRepo: testBase + "/skill/hello-skill",
			wantTag:  "bundle-v1-" + skillDigest + ".att",
		},
		{
			name:     "empty base",
			base:     "",
			ref:      npmRefFixture(npmSHA512),
			wantCode: codes.AttestationBaseUnknown,
		},
		{
			name:     "whitespace only base",
			base:     "   ",
			ref:      npmRefFixture(npmSHA512),
			wantCode: codes.AttestationBaseUnknown,
		},
		{
			name:     "base with trailing slash is stripped",
			base:     testBase + "/",
			ref:      npmRefFixture(npmSHA512),
			wantRepo: testBase + "/npm/better-call-claude",
			wantTag:  "sha512-" + npmSHA512[:64] + ".att",
		},
		{
			name: "oci source errors toward native referrers",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "my-image",
				Source: manifest.SourceOCI,
				Digest: manifest.DigestSet{"sha256": strings.Repeat("e5", 32)},
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "local mcp-server has no canonical attestation home",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "my-server",
				Source: manifest.SourceLocal,
				Digest: manifest.DigestSet{"sha256": strings.Repeat("f6", 32)},
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "mcp-registry mcp-server has no canonical attestation home",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "my-server",
				Source: manifest.SourceMCPRegistry,
				Digest: manifest.DigestSet{"sha256": strings.Repeat("07", 32)},
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "skill name with uppercase rejected, no coercion",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindSkill,
				Name:   "Hello-Skill",
				Source: manifest.SourceLocal,
				Digest: manifest.DigestSet{"smithmark-bundle-v1": skillDigest},
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "missing digest key",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "better-call-claude",
				Source: manifest.SourceNPM,
				Digest: manifest.DigestSet{},
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "npm digest value not exactly 128 hex chars, too short",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "better-call-claude",
				Source: manifest.SourceNPM,
				Digest: manifest.DigestSet{"sha512": strings.Repeat("aa", 31)}, // 62 chars
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "npm digest value of exactly 64 hex chars is rejected, not truncated",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindMCPServer,
				Name:   "better-call-claude",
				Source: manifest.SourceNPM,
				Digest: manifest.DigestSet{"sha512": strings.Repeat("aa", 32)}, // 64 chars, not 128
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name: "skill digest value of 128 hex chars is rejected, not truncated",
			base: testBase,
			ref: manifest.ArtifactRef{
				Kind:   manifest.KindSkill,
				Name:   "hello-skill",
				Source: manifest.SourceLocal,
				Digest: manifest.DigestSet{"smithmark-bundle-v1": strings.Repeat("d4", 64)}, // 128 chars, not 64
			},
			wantCode: codes.RefUnmappable,
		},
		{
			name:     "base path segment violates the OCI grammar",
			base:     testBase + "/BadSegment",
			ref:      npmRefFixture(npmSHA512),
			wantCode: codes.RefUnmappable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo, tag, err := AttestationRef(tc.base, tc.ref)
			if tc.wantCode != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantCode) {
					t.Fatalf("expected error mentioning %s, got repo=%q tag=%q err=%v", tc.wantCode, repo, tag, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if repo != tc.wantRepo {
				t.Errorf("repo = %q, want %q", repo, tc.wantRepo)
			}
			if tag != tc.wantTag {
				t.Errorf("tag = %q, want %q", tag, tc.wantTag)
			}
			assertValidOCITag(t, tag)
		})
	}
}

// npmRefFixture builds a plain unscoped npm ArtifactRef carrying digest as its
// sha512 value, reused by cases whose focus is base handling rather than name
// or digest handling.
func npmRefFixture(digest string) manifest.ArtifactRef {
	return manifest.ArtifactRef{
		Kind:   manifest.KindMCPServer,
		Name:   "better-call-claude",
		Source: manifest.SourceNPM,
		Digest: manifest.DigestSet{"sha512": digest},
	}
}
