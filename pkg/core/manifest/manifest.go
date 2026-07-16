// Package manifest defines the capability manifest domain types and their
// strict JSON parsing and RFC 8785 canonical encoding (spec 3, decisions D6
// and U6). This is the pure core: every later task that builds, verifies, or
// signs a manifest depends on these exact type names and signatures.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
)

// ArtifactKind identifies the kind of artifact a manifest describes.
type ArtifactKind string

const (
	KindMCPServer ArtifactKind = "mcp-server"
	KindSkill     ArtifactKind = "skill"
)

// SourceKind identifies where an artifact was obtained from.
type SourceKind string

const (
	SourceNPM         SourceKind = "npm"
	SourceOCI         SourceKind = "oci"
	SourcePyPI        SourceKind = "pypi"
	SourceLocal       SourceKind = "local"
	SourceMCPRegistry SourceKind = "mcp-registry"
)

// DigestSet maps a digest algorithm name to its lowercase hex encoded value
// (spec U6). A manifest may carry more than one algorithm for the same
// content, for example both sha256 and sha512.
type DigestSet map[string]string

// ArtifactRef identifies an artifact together with its digest (spec 3). It is
// used by verify and by reports, and carries the digest that PredicateArtifact
// deliberately omits.
type ArtifactRef struct {
	Kind    ArtifactKind `json:"kind"`
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"` // optional for skills (U4)
	Digest  DigestSet    `json:"digest"`
	Source  SourceKind   `json:"source"`
}

// PredicateArtifact is the digestless artifact block inside the predicate
// (D6). The digest is intentionally left out of the predicate body; it lives
// alongside the predicate in the surrounding statement instead.
type PredicateArtifact struct {
	Kind    ArtifactKind `json:"kind"`
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	Source  SourceKind   `json:"source"`
}

// ToolDecl declares a single tool exposed by an MCP server.
type ToolDecl struct {
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	InputSchemaDigest DigestSet `json:"inputSchemaDigest"`
}

// MCPSurface describes everything an MCP server exposes to a caller.
type MCPSurface struct {
	Tools      []ToolDecl `json:"tools"`
	Resources  []string   `json:"resources"`
	Prompts    []string   `json:"prompts"`
	Transports []string   `json:"transports"` // stdio | http | sse
}

// FileRef identifies a single file within a skill bundle by its path, digest,
// and access mode.
type FileRef struct {
	Path   string    `json:"path"`
	Digest DigestSet `json:"digest"`
	Mode   string    `json:"mode"` // regular | executable
}

// SkillSurface describes everything a skill bundle exposes.
type SkillSurface struct {
	EntryDigest  DigestSet `json:"entryDigest"`
	Scripts      []FileRef `json:"scripts"`
	InvokesTools []string  `json:"invokesTools"`
}

// EgressRule declares one permitted network egress destination.
type EgressRule struct {
	Host   string `json:"host"`
	Ports  []int  `json:"ports,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// FSRule declares one permitted filesystem access.
type FSRule struct {
	Path   string `json:"path"`
	Access string `json:"access"` // read | write | readwrite
	Reason string `json:"reason,omitempty"`
}

// ExecRule declares one permitted binary invocation.
type ExecRule struct {
	Binary string `json:"binary"`
	Reason string `json:"reason,omitempty"`
}

// CapabilitySet is the declared capability surface of an artifact. All five
// keys are REQUIRED in the JSON encoding; an empty array means the artifact
// declared none, as distinct from the field being absent (D6).
type CapabilitySet struct {
	NetworkEgress []EgressRule `json:"networkEgress"`
	Filesystem    []FSRule     `json:"filesystem"`
	Exec          []ExecRule   `json:"exec"`
	Env           []string     `json:"env"`
	Secrets       []string     `json:"secrets"`
}

// SBOMRef points to a software bill of materials for an artifact's
// dependencies.
type SBOMRef struct {
	SBOMDigest DigestSet `json:"sbomDigest"`
	SBOMFormat string    `json:"sbomFormat"`
	Locator    string    `json:"locator,omitempty"`
}

// GeneratorInfo identifies the tool that produced a manifest.
type GeneratorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CapabilityManifest is the predicate body described in spec 3 and decision
// D6. Exactly one of MCP or Skill is expected to be set, matching Artifact.Kind.
type CapabilityManifest struct {
	SchemaVersion string            `json:"schemaVersion"`
	Artifact      PredicateArtifact `json:"artifact"`
	MCP           *MCPSurface       `json:"mcp,omitempty"`
	Skill         *SkillSurface     `json:"skill,omitempty"`
	Capabilities  CapabilitySet     `json:"capabilities"`
	Dependencies  *SBOMRef          `json:"dependencies,omitempty"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	Generator     GeneratorInfo     `json:"generator"`
}

// Parse decodes a capability manifest strictly. Unknown fields are errors
// at every nesting level (spec 2.2).
func Parse(data []byte) (*CapabilityManifest, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m CapabilityManifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest parse: trailing data after JSON document")
	}
	return &m, nil
}

// canonicalJSON marshals v and returns its RFC 8785 canonical form. Both
// Canonical methods delegate here so a manifest and a statement share one
// serialization path.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
}

// Canonical returns the RFC 8785 canonical JSON encoding. All signing and
// digesting of manifests operates on these bytes and only these bytes.
func (m *CapabilityManifest) Canonical() ([]byte, error) {
	return canonicalJSON(m)
}

// SchemaDigest computes the sha256 digest of the RFC 8785 canonical encoding
// of an MCP tool's inputSchema (decision U2). It delegates to canonicalJSON,
// the same helper Canonical and Statement.Canonical use, so canonicalization
// never lives in two places: a change here and a change to manifest encoding
// can never silently diverge. schema must be non empty.
//
// SchemaDigest is pure and does no I/O, unlike pkg/discover.ExtractTools,
// which executes an MCP server to obtain the schema in the first place;
// smithmark verify and smithmark lint may call SchemaDigest freely, but must
// never call ExtractTools (U2).
func SchemaDigest(schema json.RawMessage) (DigestSet, error) {
	if len(schema) == 0 {
		return nil, errors.New("SchemaDigest: schema must not be empty")
	}
	canon, err := canonicalJSON(schema)
	if err != nil {
		return nil, fmt.Errorf("SchemaDigest: %w", err)
	}
	sum := sha256.Sum256(canon)
	return DigestSet{"sha256": hex.EncodeToString(sum[:])}, nil
}

// Issue is one semantic validation failure, identified by a stable machine
// readable code (spec 3; codes are documented in pkg/core/codes).
type Issue struct {
	Code   string `json:"code"` // stable, from pkg/core/codes
	Path   string `json:"path"` // JSON pointerish location, e.g. capabilities.networkEgress[0].host
	Detail string `json:"detail"`
}

const schemaVersion1 = "1.0.0"

// Validate checks a parsed manifest against the semantic rules of spec 3 and
// decision D1, beyond what strict JSON parsing already enforces. The result
// is sorted by (Code, Path) for determinism; a non nil empty slice means the
// manifest is valid, so a JSON encoding renders [] rather than null.
func (m *CapabilityManifest) Validate() []Issue {
	issues := []Issue{}
	add := func(code, path, detail string) {
		issues = append(issues, Issue{Code: code, Path: path, Detail: detail})
	}

	if m.SchemaVersion != schemaVersion1 {
		add(codes.ManifestSchemaVersionUnsupported, "schemaVersion",
			fmt.Sprintf("schemaVersion must be %q, got %q", schemaVersion1, m.SchemaVersion))
	}

	switch m.Artifact.Kind {
	case KindMCPServer:
		if m.MCP == nil {
			add(codes.ManifestKindSurfaceMismatch, "mcp", "kind mcp-server requires mcp to be set")
		}
		if m.Skill != nil {
			add(codes.ManifestKindSurfaceMismatch, "skill", "kind mcp-server requires skill to be nil")
		}
	case KindSkill:
		if m.Skill == nil {
			add(codes.ManifestKindSurfaceMismatch, "skill", "kind skill requires skill to be set")
		}
		if m.MCP != nil {
			add(codes.ManifestKindSurfaceMismatch, "mcp", "kind skill requires mcp to be nil")
		}
	default:
		add(codes.ManifestEnumInvalid, "artifact.kind", fmt.Sprintf("unknown artifact kind %q", m.Artifact.Kind))
	}

	switch m.Artifact.Source {
	case SourceNPM, SourceOCI, SourcePyPI, SourceLocal, SourceMCPRegistry:
	default:
		add(codes.ManifestEnumInvalid, "artifact.source", fmt.Sprintf("unknown source kind %q", m.Artifact.Source))
	}

	// U4: version is required unless the artifact is a skill.
	if m.Artifact.Kind != KindSkill && m.Artifact.Version == "" {
		add(codes.ManifestVersionRequired, "artifact.version", "version is required unless kind is skill")
	}

	// F6: required identity strings that other stages key off must be present.
	if m.Artifact.Name == "" {
		add(codes.ManifestFieldRequired, "artifact.name", "artifact.name must not be empty")
	}
	if m.Generator.Name == "" {
		add(codes.ManifestFieldRequired, "generator.name", "generator.name must not be empty")
	}
	if m.Generator.Version == "" {
		add(codes.ManifestFieldRequired, "generator.version", "generator.version must not be empty")
	}

	// F5: generatedAt must be a non zero UTC timestamp with no sub second
	// precision.
	if m.GeneratedAt.IsZero() {
		add(codes.GeneratedAtInvalid, "generatedAt", "generatedAt must be a non zero timestamp")
	}
	if _, offset := m.GeneratedAt.Zone(); offset != 0 {
		add(codes.GeneratedAtInvalid, "generatedAt", "generatedAt must be in UTC with a zero zone offset")
	}
	if m.GeneratedAt.Nanosecond() != 0 {
		add(codes.GeneratedAtInvalid, "generatedAt", "generatedAt must not carry sub second precision")
	}

	if m.Capabilities.NetworkEgress == nil {
		add(codes.ManifestCapabilitiesKeyMissing, "capabilities.networkEgress", "capabilities.networkEgress key is absent; declare it as an empty array if none apply")
	}
	if m.Capabilities.Filesystem == nil {
		add(codes.ManifestCapabilitiesKeyMissing, "capabilities.filesystem", "capabilities.filesystem key is absent; declare it as an empty array if none apply")
	}
	if m.Capabilities.Exec == nil {
		add(codes.ManifestCapabilitiesKeyMissing, "capabilities.exec", "capabilities.exec key is absent; declare it as an empty array if none apply")
	}
	if m.Capabilities.Env == nil {
		add(codes.ManifestCapabilitiesKeyMissing, "capabilities.env", "capabilities.env key is absent; declare it as an empty array if none apply")
	}
	if m.Capabilities.Secrets == nil {
		add(codes.ManifestCapabilitiesKeyMissing, "capabilities.secrets", "capabilities.secrets key is absent; declare it as an empty array if none apply")
	}

	for i, r := range m.Capabilities.NetworkEgress {
		if !validHost(r.Host) {
			add(codes.EgressHostInvalid, fmt.Sprintf("capabilities.networkEgress[%d].host", i),
				fmt.Sprintf("host %q does not match the egress host grammar (D1)", r.Host))
		}
		for j, p := range r.Ports {
			if p < 1 || p > 65535 {
				add(codes.EgressPortInvalid, fmt.Sprintf("capabilities.networkEgress[%d].ports[%d]", i, j),
					fmt.Sprintf("port %d is out of range 1 to 65535", p))
			}
		}
	}

	for i, r := range m.Capabilities.Filesystem {
		switch r.Access {
		case "read", "write", "readwrite":
		default:
			add(codes.FSAccessInvalid, fmt.Sprintf("capabilities.filesystem[%d].access", i),
				fmt.Sprintf("access %q must be read, write, or readwrite", r.Access))
		}
		if !validFSPath(r.Path) {
			add(codes.FSPathInvalid, fmt.Sprintf("capabilities.filesystem[%d].path", i),
				fmt.Sprintf("path %q does not match the filesystem path grammar (D1)", r.Path))
		}
	}

	for i, r := range m.Capabilities.Exec {
		if !validExecBinary(r.Binary) {
			add(codes.ExecBinaryInvalid, fmt.Sprintf("capabilities.exec[%d].binary", i),
				fmt.Sprintf("binary %q must be a non empty basename pattern with no slash or backslash (D1)", r.Binary))
		}
	}

	for i, e := range m.Capabilities.Env {
		if !validEnvName(e) {
			add(codes.EnvNameInvalid, fmt.Sprintf("capabilities.env[%d]", i),
				fmt.Sprintf("env entry %q does not match the env name grammar (D1)", e))
		}
	}

	for i, s := range m.Capabilities.Secrets {
		if !validSecret(s) {
			add(codes.SecretFormatInvalid, fmt.Sprintf("capabilities.secrets[%d]", i),
				fmt.Sprintf("secret %q is not a kind:provider pair (D1)", s))
		}
	}

	if m.MCP != nil {
		// F3: every mcp surface array key must be present (non nil), mirroring
		// the capabilities key rule; a nil slice means the JSON key was absent.
		if m.MCP.Tools == nil {
			add(codes.ManifestSurfaceKeyMissing, "mcp.tools", "mcp.tools key is absent; declare it as an empty array if none apply")
		}
		if m.MCP.Resources == nil {
			add(codes.ManifestSurfaceKeyMissing, "mcp.resources", "mcp.resources key is absent; declare it as an empty array if none apply")
		}
		if m.MCP.Prompts == nil {
			add(codes.ManifestSurfaceKeyMissing, "mcp.prompts", "mcp.prompts key is absent; declare it as an empty array if none apply")
		}
		if m.MCP.Transports == nil {
			add(codes.ManifestSurfaceKeyMissing, "mcp.transports", "mcp.transports key is absent; declare it as an empty array if none apply")
		}
		for i, tr := range m.MCP.Transports {
			switch tr {
			case "stdio", "http", "sse":
			default:
				add(codes.TransportInvalid, fmt.Sprintf("mcp.transports[%d]", i),
					fmt.Sprintf("transport %q must be stdio, http, or sse", tr))
			}
		}
		for i, tool := range m.MCP.Tools {
			if tool.Name == "" {
				add(codes.ManifestFieldRequired, fmt.Sprintf("mcp.tools[%d].name", i), "mcp tool name must not be empty")
			}
			if !validDigestSet(tool.InputSchemaDigest) {
				add(codes.DigestInvalid, fmt.Sprintf("mcp.tools[%d].inputSchemaDigest", i),
					"digest set must be non empty with non empty keys and lowercase hex values of even length")
			}
		}
	}

	if m.Skill != nil {
		// F3: skill surface array keys must be present (non nil).
		if m.Skill.Scripts == nil {
			add(codes.ManifestSurfaceKeyMissing, "skill.scripts", "skill.scripts key is absent; declare it as an empty array if none apply")
		}
		if m.Skill.InvokesTools == nil {
			add(codes.ManifestSurfaceKeyMissing, "skill.invokesTools", "skill.invokesTools key is absent; declare it as an empty array if none apply")
		}
		if !validDigestSet(m.Skill.EntryDigest) {
			add(codes.DigestInvalid, "skill.entryDigest",
				"digest set must be non empty with non empty keys and lowercase hex values of even length")
		}
		seenScript := make(map[string]bool)
		for i, f := range m.Skill.Scripts {
			// F12: reuse the bundle mode constants rather than string literals.
			switch f.Mode {
			case string(bundle.ModeRegular), string(bundle.ModeExecutable):
			default:
				add(codes.ModeInvalid, fmt.Sprintf("skill.scripts[%d].mode", i),
					fmt.Sprintf("mode %q must be regular or executable", f.Mode))
			}
			if !validDigestSet(f.Digest) {
				add(codes.DigestInvalid, fmt.Sprintf("skill.scripts[%d].digest", i),
					"digest set must be non empty with non empty keys and lowercase hex values of even length")
			}
			// F7: declared script paths reuse the bundle path validator and
			// must be unique within the skill surface.
			if !bundle.ValidPath(f.Path) {
				add(codes.SkillScriptPathInvalid, fmt.Sprintf("skill.scripts[%d].path", i),
					fmt.Sprintf("script path %q must be a clean relative path using forward slashes (spec 4)", f.Path))
			} else if seenScript[f.Path] {
				add(codes.SkillScriptPathInvalid, fmt.Sprintf("skill.scripts[%d].path", i),
					fmt.Sprintf("duplicate script path %q", f.Path))
			}
			seenScript[f.Path] = true
		}
	}

	if m.Dependencies != nil {
		// F6: when the dependencies block is present, its identity fields are
		// required. An empty digest is reported as missing, not malformed.
		if m.Dependencies.SBOMFormat == "" {
			add(codes.ManifestFieldRequired, "dependencies.sbomFormat", "dependencies.sbomFormat must not be empty")
		}
		if len(m.Dependencies.SBOMDigest) == 0 {
			add(codes.ManifestFieldRequired, "dependencies.sbomDigest", "dependencies.sbomDigest must not be empty")
		} else if !validDigestSet(m.Dependencies.SBOMDigest) {
			add(codes.DigestInvalid, "dependencies.sbomDigest",
				"digest set must be non empty with non empty keys and lowercase hex values of even length")
		}
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Code != issues[j].Code {
			return issues[i].Code < issues[j].Code
		}
		return issues[i].Path < issues[j].Path
	})
	return issues
}

// domainLabel matches one DNS label: lowercase alphanumeric, with interior
// hyphens allowed but not as the first or last character.
var domainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// validHost reports whether host matches the D1 egress host grammar: an
// exact DNS name, an IP literal, a single leftmost wildcard label
// (`*.example.com`), or the bare escape hatch `*`.
func validHost(host string) bool {
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		// F13: reject IPv6 zone literals such as fe80::1%eth0; a scoped
		// address is not a stable egress destination.
		return addr.Zone() == ""
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if i == 0 && label == "*" {
			continue
		}
		if !domainLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// fsPathTokens are the portability tokens a filesystem path may start with,
// in place of an absolute path (D1).
var fsPathTokens = []string{"${home}", "${tmp}", "${cwd}"}

// validFSPath reports whether path matches the D1 filesystem path grammar:
// it starts with a portability token followed by "/" (or is exactly the
// token), or it is relative (no leading "/", no drive letter); bare "*" or
// "**" are accepted as the escape hatch. A token immediately followed by any
// character other than "/" is malformed, for example "${home}x". Backslashes
// and any ".." segment are rejected outright (F4), including after a token.
func validFSPath(path string) bool {
	if path == "" {
		return false
	}
	if strings.Contains(path, `\`) {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return false
		}
	}
	if path == "*" || path == "**" {
		return true
	}
	for _, tok := range fsPathTokens {
		if !strings.HasPrefix(path, tok) {
			continue
		}
		rest := path[len(tok):]
		return rest == "" || strings.HasPrefix(rest, "/")
	}
	if strings.HasPrefix(path, "/") {
		return false
	}
	if hasDriveLetter(path) {
		return false
	}
	return true
}

// hasDriveLetter reports whether path starts with a Windows style drive
// letter such as "C:".
func hasDriveLetter(path string) bool {
	if len(path) < 2 || path[1] != ':' {
		return false
	}
	c := path[0]
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

// envName matches an env entry: [A-Z_][A-Z0-9_]* with an optional single
// trailing "*" prefix marker (D1).
var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*\*?$`)

// validEnvName reports whether name matches the D1 env name grammar.
func validEnvName(name string) bool {
	return envName.MatchString(name)
}

// validExecBinary reports whether b is a basename pattern (D1): non empty and
// free of "/" and "\\". Bare "*" and interior "*" are allowed, so "python*"
// and "*" both pass.
func validExecBinary(b string) bool {
	if b == "" {
		return false
	}
	return !strings.ContainsAny(b, `/\`)
}

// secretPart matches one side of a secret's kind:provider pair (D1).
var secretPart = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// validSecret reports whether s is a kind:provider pair matching the D1
// grammar on each side.
func validSecret(s string) bool {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return false
	}
	return secretPart.MatchString(parts[0]) && secretPart.MatchString(parts[1])
}

// hexDigest matches a lowercase hex string.
var hexDigest = regexp.MustCompile(`^[0-9a-f]+$`)

// validDigestSet reports whether d is non empty, has no empty keys, and has
// only lowercase hex values of even length.
func validDigestSet(d DigestSet) bool {
	if len(d) == 0 {
		return false
	}
	for k, v := range d {
		if k == "" {
			return false
		}
		if len(v)%2 != 0 || !hexDigest.MatchString(v) {
			return false
		}
	}
	return true
}

// PredicateType identifies the smithmark agent capability predicate (spec
// 2.3, decision D6). It ships verbatim in the TC54 CycloneDX draft, so this
// exact string is a compatibility promise.
const PredicateType = "https://in8.sh/attestation/agent-capability/v1"

// statementType is the in-toto Statement v1 envelope type URI (spec 2.3).
const statementType = "https://in-toto.io/Statement/v1"

// bundleDigestKey is the DigestSet key a skill subject's canonical bundle
// digest uses (decision U4). It is derived from bundle.Prefix rather than
// restated, so the two packages can never drift apart.
var bundleDigestKey = strings.TrimSuffix(bundle.Prefix, ":")

// Subject identifies one in-toto statement subject (spec 2.3): a name and a
// digest set. The digest set is the sole record of the subject's identity;
// it is never duplicated into the predicate (decision D6).
type Subject struct {
	Name   string    `json:"name"`
	Digest DigestSet `json:"digest"`
}

type Statement struct { // in-toto Statement v1 with a typed predicate.
	// Typed rather than in-toto-golang's structpb statement so that strict
	// parsing and canonical encoding hold end to end; DSSE enveloping and
	// all crypto stay in sigstore-go per spec 2.2.
	Type          string              `json:"_type"` // https://in-toto.io/Statement/v1
	Subject       []Subject           `json:"subject"`
	PredicateType string              `json:"predicateType"`
	Predicate     *CapabilityManifest `json:"predicate"`
}

// NewStatement validates m, checks ref/predicate consistency, and builds
// the subject: purl name for npm and pypi (pkg:npm/name@version with @scope
// encoded as %40scope), plain name for skills, image ref for oci. Skill
// subjects use the digest key "smithmark-bundle-v1" (U4).
//
// The returned Statement aliases the given manifest and digest set rather than
// copying them: Predicate points at m and the subject shares ref.Digest.
// Callers must not mutate m or ref.Digest after assembly, because Canonical
// serializes whatever state they hold at call time, and the validation done
// here would then be bypassed.
func NewStatement(ref ArtifactRef, m *CapabilityManifest) (*Statement, error) {
	if m == nil {
		return nil, errors.New("NewStatement: manifest must not be nil")
	}
	if issues := m.Validate(); len(issues) > 0 {
		first := issues[0]
		return nil, codes.E(first.Code, "manifest is invalid at %s: %s", first.Path, first.Detail)
	}

	if ref.Kind != m.Artifact.Kind {
		return nil, codes.E(codes.ManifestKindSurfaceMismatch,
			"ref kind %q does not match predicate artifact kind %q", ref.Kind, m.Artifact.Kind)
	}
	if ref.Name != m.Artifact.Name {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"ref name %q does not match predicate artifact name %q", ref.Name, m.Artifact.Name)
	}
	if ref.Version != m.Artifact.Version {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"ref version %q does not match predicate artifact version %q", ref.Version, m.Artifact.Version)
	}
	if ref.Source != m.Artifact.Source {
		return nil, codes.E(codes.StatementSubjectMismatch,
			"ref source %q does not match predicate artifact source %q", ref.Source, m.Artifact.Source)
	}
	if !validDigestSet(ref.Digest) {
		return nil, codes.E(codes.DigestInvalid,
			"ref digest must be a non empty digest set with non empty keys and lowercase hex values of even length")
	}

	return &Statement{
		Type:          statementType,
		Subject:       []Subject{{Name: subjectName(ref), Digest: ref.Digest}},
		PredicateType: PredicateType,
		Predicate:     m,
	}, nil
}

// subjectName builds the in-toto subject name for ref: a purl for npm and
// pypi packages, with a leading @scope percent encoded as %40scope; the
// plain artifact name for skills, and for every other source, which covers
// an oci image reference given verbatim in ref.Name (spec 2.3, decision D6).
// Plain name for the local and mcp-registry sources is a default chosen
// here, not a spec mandated case.
func subjectName(ref ArtifactRef) string {
	if ref.Kind == KindSkill {
		return ref.Name
	}
	switch ref.Source {
	case SourceNPM:
		return purlName("npm", ref.Name, ref.Version)
	case SourcePyPI:
		return purlName("pypi", ref.Name, ref.Version)
	default:
		return ref.Name
	}
}

// purlName builds a package URL of the form pkg:ecosystem/name@version. A
// leading @scope is percent encoded as %40scope, the only case where an npm
// or PyPI name contains "@".
func purlName(ecosystem, name, version string) string {
	encoded := strings.ReplaceAll(name, "@", "%40")
	return fmt.Sprintf("pkg:%s/%s@%s", ecosystem, encoded, version)
}

// Canonical returns the RFC 8785 canonical JSON encoding of the statement.
// DSSE envelopes wrap these bytes unchanged (spec 2.2); Phase 2 signs and
// Phase 3 verifies over them, exactly as CapabilityManifest.Canonical does
// for a bare predicate.
func (s *Statement) Canonical() ([]byte, error) {
	return canonicalJSON(s)
}

// ParseStatement decodes an in-toto statement strictly: unknown fields are
// errors at every nesting level, the envelope type must equal
// "https://in-toto.io/Statement/v1", the predicate type must equal
// PredicateType, there must be exactly one subject with a non empty name and a
// well formed digest, and the predicate must be present.
//
// ParseStatement is structural only. It deliberately does not run predicate
// semantic validation: a predicate whose schemaVersion is unsupported parses
// cleanly here. Semantic validation is a separate stage, Validate on the
// parsed predicate, run by verification (M3 reports it as MANIFEST_SCHEMA_VALID).
func ParseStatement(data []byte) (*Statement, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Statement
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("statement parse: %w", err)
	}
	if dec.More() {
		return nil, errors.New("statement parse: trailing data after JSON document")
	}
	if s.Type != statementType {
		return nil, fmt.Errorf("statement parse: unexpected _type %q, want %q", s.Type, statementType)
	}
	if s.PredicateType != PredicateType {
		return nil, fmt.Errorf("statement parse: unexpected predicateType %q, want %q", s.PredicateType, PredicateType)
	}
	if len(s.Subject) != 1 {
		return nil, codes.E(codes.StatementSubjectInvalid,
			"statement parse: expected exactly one subject, got %d", len(s.Subject))
	}
	if s.Subject[0].Name == "" {
		return nil, codes.E(codes.StatementSubjectInvalid, "statement parse: subject name must not be empty")
	}
	for i, sub := range s.Subject {
		if !validDigestSet(sub.Digest) {
			return nil, codes.E(codes.DigestInvalid,
				"statement parse: subject[%d] digest must be a non empty digest set with non empty keys and lowercase hex values of even length", i)
		}
	}
	if s.Predicate == nil {
		return nil, errors.New("statement parse: predicate must not be nil")
	}
	return &s, nil
}

// bundleDigestHexLen is the length of the hex remainder of a bundle digest:
// a sha256 sum encoded as lowercase hex.
const bundleDigestHexLen = 64

// SubjectDigestFromBundle converts the prefixed output of bundle.Digest into
// a DigestSet suitable for a statement subject: the key is
// "smithmark-bundle-v1" and the value is the bare lowercase hex digest with
// the prefix stripped, since a DigestSet value must be hex only (decisions
// D6 and U6). It is strict about the expected prefix and about the remainder
// being exactly sixty four lowercase hex characters.
func SubjectDigestFromBundle(prefixed string) (DigestSet, error) {
	if !strings.HasPrefix(prefixed, bundle.Prefix) {
		return nil, fmt.Errorf("SubjectDigestFromBundle: expected prefix %q, got %q", bundle.Prefix, prefixed)
	}
	digestHex := strings.TrimPrefix(prefixed, bundle.Prefix)
	if len(digestHex) != bundleDigestHexLen || !hexDigest.MatchString(digestHex) {
		return nil, codes.E(codes.DigestInvalid,
			"bundle digest value must be exactly %d lowercase hex characters, got %q", bundleDigestHexLen, digestHex)
	}
	return DigestSet{bundleDigestKey: digestHex}, nil
}
