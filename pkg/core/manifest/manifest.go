// Package manifest defines the capability manifest domain types and their
// strict JSON parsing and RFC 8785 canonical encoding (spec 3, decisions D6
// and U6). This is the pure core: every later task that builds, verifies, or
// signs a manifest depends on these exact type names and signatures.
package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"

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

// Canonical returns the RFC 8785 canonical JSON encoding. All signing and
// digesting of manifests operates on these bytes and only these bytes.
func (m *CapabilityManifest) Canonical() ([]byte, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return jsoncanonicalizer.Transform(raw)
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
// is sorted by (Code, Path) for determinism; a nil slice means the manifest
// is valid.
func (m *CapabilityManifest) Validate() []Issue {
	var issues []Issue
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
		for i, tr := range m.MCP.Transports {
			switch tr {
			case "stdio", "http", "sse":
			default:
				add(codes.TransportInvalid, fmt.Sprintf("mcp.transports[%d]", i),
					fmt.Sprintf("transport %q must be stdio, http, or sse", tr))
			}
		}
		for i, tool := range m.MCP.Tools {
			if !validDigestSet(tool.InputSchemaDigest) {
				add(codes.DigestInvalid, fmt.Sprintf("mcp.tools[%d].inputSchemaDigest", i),
					"digest set must be non empty with non empty keys and lowercase hex values of even length")
			}
		}
	}

	if m.Skill != nil {
		if !validDigestSet(m.Skill.EntryDigest) {
			add(codes.DigestInvalid, "skill.entryDigest",
				"digest set must be non empty with non empty keys and lowercase hex values of even length")
		}
		for i, f := range m.Skill.Scripts {
			switch f.Mode {
			case "regular", "executable":
			default:
				add(codes.ModeInvalid, fmt.Sprintf("skill.scripts[%d].mode", i),
					fmt.Sprintf("mode %q must be regular or executable", f.Mode))
			}
			if !validDigestSet(f.Digest) {
				add(codes.DigestInvalid, fmt.Sprintf("skill.scripts[%d].digest", i),
					"digest set must be non empty with non empty keys and lowercase hex values of even length")
			}
		}
	}

	if m.Dependencies != nil {
		if !validDigestSet(m.Dependencies.SBOMDigest) {
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
	if _, err := netip.ParseAddr(host); err == nil {
		return true
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
// character other than "/" is malformed, for example "${home}x".
func validFSPath(path string) bool {
	if path == "" {
		return false
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
