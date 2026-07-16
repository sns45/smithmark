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
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
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
