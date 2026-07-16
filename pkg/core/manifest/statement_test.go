package manifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/sns45/smithmark/internal/golden"
	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
)

// mcpRef is the ArtifactRef counterpart to validManifest(): same kind, name,
// version, and source, plus the digest that PredicateArtifact deliberately
// omits.
func mcpRef() ArtifactRef {
	return ArtifactRef{
		Kind:    KindMCPServer,
		Name:    "better-call-claude",
		Version: "1.4.2",
		Source:  SourceNPM,
		Digest:  DigestSet{"sha512": strings.Repeat("13", 64)},
	}
}

// scopedManifest is validManifest() with a scoped npm artifact name, used to
// exercise purl percent encoding of the leading @scope.
func scopedManifest() *CapabilityManifest {
	m := validManifest()
	m.Artifact = PredicateArtifact{Kind: KindMCPServer, Name: "@acme/tool", Version: "1.0.0", Source: SourceNPM}
	return m
}

func scopedNPMRef() ArtifactRef {
	return ArtifactRef{
		Kind:    KindMCPServer,
		Name:    "@acme/tool",
		Version: "1.0.0",
		Source:  SourceNPM,
		Digest:  DigestSet{"sha512": strings.Repeat("24", 64)},
	}
}

// validSkillManifest mirrors the "version optional for skill" fixture in
// validate_test.go: a skill artifact with an empty scripts list.
func validSkillManifest() *CapabilityManifest {
	m := validManifest()
	m.Artifact = PredicateArtifact{Kind: KindSkill, Name: "dear-claude-notes", Source: SourceLocal}
	m.MCP = nil
	m.Skill = &SkillSurface{
		EntryDigest:  DigestSet{"sha256": strings.Repeat("ab", 32)},
		Scripts:      []FileRef{},
		InvokesTools: []string{},
	}
	return m
}

// skillRef builds the ArtifactRef counterpart to validSkillManifest() by
// running a real bundle through bundle.Digest and converting the prefixed
// result with SubjectDigestFromBundle, so the fixture exercises the full
// bundle to subject pipeline rather than a hand written digest.
func skillRef(t *testing.T) ArtifactRef {
	t.Helper()
	prefixed, err := bundle.Digest([]bundle.File{
		{Path: "SKILL.md", Mode: bundle.ModeRegular, SHA256: strings.Repeat("aa", 32)},
	})
	if err != nil {
		t.Fatalf("bundle.Digest: %v", err)
	}
	digest, err := SubjectDigestFromBundle(prefixed)
	if err != nil {
		t.Fatalf("SubjectDigestFromBundle: %v", err)
	}
	return ArtifactRef{
		Kind:   KindSkill,
		Name:   "dear-claude-notes",
		Source: SourceLocal,
		Digest: digest,
	}
}

// (a) NewStatement rejects a ref that disagrees with the predicate artifact
// block: a kind disagreement keeps the surface mismatch code, while name,
// version, and source disagreements use the statement subject mismatch code.
func TestNewStatementRejectsRefManifestMismatch(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *ArtifactRef)
		want   string
	}{
		{"kind mismatch", func(r *ArtifactRef) { r.Kind = KindSkill }, codes.ManifestKindSurfaceMismatch},
		{"name mismatch", func(r *ArtifactRef) { r.Name = "some-other-server" }, codes.StatementSubjectMismatch},
		{"version mismatch", func(r *ArtifactRef) { r.Version = "9.9.9" }, codes.StatementSubjectMismatch},
		{"source mismatch", func(r *ArtifactRef) { r.Source = SourcePyPI }, codes.StatementSubjectMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := mcpRef()
			tc.mutate(&ref)
			if _, err := NewStatement(ref, validManifest()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("expected error mentioning %s, got %v", tc.want, err)
			}
		})
	}
}

// NewStatement refuses a ref whose digest set is nil, empty, or malformed.
func TestNewStatementRejectsBadRefDigest(t *testing.T) {
	cases := []struct {
		name   string
		digest DigestSet
	}{
		{"nil digest", nil},
		{"empty digest", DigestSet{}},
		{"uppercase hex", DigestSet{"sha512": "AB"}},
		{"odd length", DigestSet{"sha512": "abc"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ref := mcpRef()
			ref.Digest = tc.digest
			if _, err := NewStatement(ref, validManifest()); err == nil || !strings.Contains(err.Error(), codes.DigestInvalid) {
				t.Errorf("expected error mentioning %s, got %v", codes.DigestInvalid, err)
			}
		})
	}
}

// NewStatement also refuses to build a statement for an invalid manifest,
// surfacing the first Validate issue's code.
func TestNewStatementRejectsInvalidManifest(t *testing.T) {
	m := validManifest()
	m.SchemaVersion = "9.9.9"
	if _, err := NewStatement(mcpRef(), m); err == nil || !strings.Contains(err.Error(), codes.ManifestSchemaVersionUnsupported) {
		t.Errorf("expected error mentioning %s, got %v", codes.ManifestSchemaVersionUnsupported, err)
	}
}

// (b) npm and scoped npm subject names are purls with @scope percent encoded.
func TestNewStatementSubjectNameNPM(t *testing.T) {
	s, err := NewStatement(mcpRef(), validManifest())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := s.Subject[0].Name, "pkg:npm/better-call-claude@1.4.2"; got != want {
		t.Errorf("subject name = %q, want %q", got, want)
	}

	scoped, err := NewStatement(scopedNPMRef(), scopedManifest())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := scoped.Subject[0].Name, "pkg:npm/%40acme/tool@1.0.0"; got != want {
		t.Errorf("scoped subject name = %q, want %q", got, want)
	}
}

// (c) skill subject digest key is exactly "smithmark-bundle-v1".
func TestNewStatementSkillSubjectDigestKey(t *testing.T) {
	ref := skillRef(t)
	s, err := NewStatement(ref, validSkillManifest())
	if err != nil {
		t.Fatal(err)
	}
	digest := s.Subject[0].Digest
	if len(digest) != 1 {
		t.Fatalf("expected exactly one digest key, got %+v", digest)
	}
	if _, ok := digest["smithmark-bundle-v1"]; !ok {
		t.Errorf("expected digest key %q, got %+v", "smithmark-bundle-v1", digest)
	}
}

// (d) ParseStatement rejects unknown _type, unknown predicateType, and
// unknown fields at any nesting level, plus an empty subject or nil
// predicate.
func TestParseStatementStrict(t *testing.T) {
	s, err := NewStatement(mcpRef(), validManifest())
	if err != nil {
		t.Fatal(err)
	}
	good, err := s.Canonical()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseStatement(good); err != nil {
		t.Fatalf("valid statement rejected: %v", err)
	}

	cases := map[string]string{
		"unknown _type": strings.Replace(string(good),
			`"https://in-toto.io/Statement/v1"`, `"https://bogus.example/Statement/v1"`, 1),
		"unknown predicateType": strings.Replace(string(good),
			PredicateType, "https://bogus.example/predicate/v1", 1),
		"unknown top level field": strings.Replace(string(good),
			`"_type"`, `"extra":1,"_type"`, 1),
		"unknown nested field": strings.Replace(string(good),
			`"env":[]`, `"env":[],"sneaky":true`, 1),
		"empty subject digest": strings.Replace(string(good),
			`"digest":{"sha512":"`+strings.Repeat("13", 64)+`"}`, `"digest":{}`, 1),
		"non hex subject digest": strings.Replace(string(good),
			strings.Repeat("13", 64), "NOT HEX", 1),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseStatement([]byte(doc)); err == nil {
				t.Errorf("%s: accepted; ParseStatement must reject it", name)
			}
		})
	}
}

func TestParseStatementRejectsEmptySubjectAndNilPredicate(t *testing.T) {
	s, err := NewStatement(mcpRef(), validManifest())
	if err != nil {
		t.Fatal(err)
	}

	noSubject := *s
	noSubject.Subject = nil
	data, err := json.Marshal(&noSubject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatement(data); err == nil {
		t.Error("empty subject accepted; ParseStatement must reject it")
	}

	noPredicate := *s
	noPredicate.Predicate = nil
	data, err = json.Marshal(&noPredicate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseStatement(data); err == nil {
		t.Error("nil predicate accepted; ParseStatement must reject it")
	}
}

func TestParseStatementRejectsEmptyInput(t *testing.T) {
	if _, err := ParseStatement(nil); err == nil {
		t.Error("empty input accepted; ParseStatement must return an error")
	}
}

// (e) golden snapshots for the canonical encoding of one mcp-server statement
// and one skill statement.
func TestStatementGolden(t *testing.T) {
	t.Run("mcp", func(t *testing.T) {
		s, err := NewStatement(mcpRef(), validManifest())
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		golden.Assert(t, got, "testdata/golden/statement_mcp.json")
	})
	t.Run("skill", func(t *testing.T) {
		s, err := NewStatement(skillRef(t), validSkillManifest())
		if err != nil {
			t.Fatal(err)
		}
		got, err := s.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		golden.Assert(t, got, "testdata/golden/statement_skill.json")
	})
}

// SubjectDigestFromBundle converts a bundle.Digest output into a subject
// DigestSet, strict about the expected prefix.
func TestSubjectDigestFromBundle(t *testing.T) {
	prefixed, err := bundle.Digest([]bundle.File{
		{Path: "a", Mode: bundle.ModeRegular, SHA256: strings.Repeat("11", 32)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := SubjectDigestFromBundle(prefixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 1 {
		t.Fatalf("expected exactly one key, got %+v", ds)
	}
	hex, ok := ds["smithmark-bundle-v1"]
	if !ok {
		t.Fatalf("expected key %q, got %+v", "smithmark-bundle-v1", ds)
	}
	if strings.Contains(hex, ":") {
		t.Errorf("digest value retained the prefix: %q", hex)
	}
}

func TestSubjectDigestFromBundleRejectsWrongPrefix(t *testing.T) {
	if _, err := SubjectDigestFromBundle("sha256:" + strings.Repeat("aa", 32)); err == nil {
		t.Error("wrong prefix accepted; SubjectDigestFromBundle must reject it")
	}
}

// After the prefix check the remainder must be exactly sixty four lowercase
// hex characters.
func TestSubjectDigestFromBundleRejectsMalformedRemainder(t *testing.T) {
	cases := map[string]string{
		"non hex remainder": "smithmark-bundle-v1:nothex!!",
		"short remainder":   "smithmark-bundle-v1:" + strings.Repeat("aa", 16),
		"uppercase hex":     "smithmark-bundle-v1:" + strings.Repeat("AA", 32),
		"empty remainder":   "smithmark-bundle-v1:",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := SubjectDigestFromBundle(in); err == nil || !strings.Contains(err.Error(), codes.DigestInvalid) {
				t.Errorf("expected error mentioning %s, got %v", codes.DigestInvalid, err)
			}
		})
	}
}

// TestStatementRoundTrip proves that Canonical and ParseStatement compose to
// the identity: the parsed value equals the original, and canonicalizing the
// parsed value reproduces the first canonical bytes exactly.
func TestStatementRoundTrip(t *testing.T) {
	original, err := NewStatement(mcpRef(), validManifest())
	if err != nil {
		t.Fatal(err)
	}
	first, err := original.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseStatement(first)
	if err != nil {
		t.Fatalf("ParseStatement on canonical bytes: %v", err)
	}
	if !reflect.DeepEqual(parsed, original) {
		t.Errorf("round trip changed the statement\n got: %+v\nwant: %+v", parsed, original)
	}
	second, err := parsed.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Errorf("re canonicalizing the parsed statement is not byte identical\n got: %s\nwant: %s", second, first)
	}
}
