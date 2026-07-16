// Package discover holds the I/O adapters that read artifacts and their
// declarations: local files here, registries and running servers in later
// files. The pure core never touches the filesystem, network, or clock (spec
// 2.1); this package does that work and hands the results to pkg/core types.
package discover

import (
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// declSchemaVersion is the predicate schema version stamped on every loaded
// manifest. It must match the version pkg/core/manifest validates against.
const declSchemaVersion = "1.0.0"

// The yaml tagged structs below mirror smithmark.yaml (U1): artifact identity
// at the top level, exactly one declared surface block matching the kind, and
// all five capability keys. YAML is never decoded into the JSON tagged core
// types; decoding lands here and an explicit field for field mapping builds
// the manifest, so the two schemas cannot drift into each other silently.

type yamlDecl struct {
	Kind         string            `yaml:"kind"`
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Source       string            `yaml:"source"`
	MCP          *yamlMCPSurface   `yaml:"mcp"`
	Skill        *yamlSkillSurface `yaml:"skill"`
	Capabilities *yamlCapabilities `yaml:"capabilities"`
}

// yamlMCPSurface carries only transports: tools, resources, and prompts are
// extracted from the running server by attest (U2), never declared, so those
// keys are unknown fields here by construction.
type yamlMCPSurface struct {
	Transports []string `yaml:"transports"`
}

// yamlSkillSurface carries only invokesTools: the entry digest and script
// list come from the skill directory walker, never from the declaration.
type yamlSkillSurface struct {
	InvokesTools []string `yaml:"invokesTools"`
}

type yamlCapabilities struct {
	NetworkEgress []yamlEgressRule `yaml:"networkEgress"`
	Filesystem    []yamlFSRule     `yaml:"filesystem"`
	Exec          []yamlExecRule   `yaml:"exec"`
	Env           []string         `yaml:"env"`
	Secrets       []string         `yaml:"secrets"`
}

type yamlEgressRule struct {
	Host   string `yaml:"host"`
	Ports  []int  `yaml:"ports"`
	Reason string `yaml:"reason"`
}

type yamlFSRule struct {
	Path   string `yaml:"path"`
	Access string `yaml:"access"`
	Reason string `yaml:"reason"`
}

type yamlExecRule struct {
	Binary string `yaml:"binary"`
	Reason string `yaml:"reason"`
}

// LoadDeclared reads and strictly parses a smithmark.yaml declaration (U1)
// and returns a partially populated manifest: the artifact block, the five
// capability keys, and the declared surface fields. GeneratedAt, Generator,
// Dependencies, and the extraction owned surface fields (mcp tools,
// resources, prompts; skill entryDigest, scripts) are left unset for attest
// to complete, so the returned manifest does not pass Validate as is.
//
// Unknown YAML keys are errors at every nesting level: yaml.v3 applies
// KnownFields recursively wherever it decodes into a struct, including
// structs reached through pointers and sequence elements. Required keys at
// this authoring surface mirror D6: kind, name, source, and all five
// capability keys must be present (a null value counts as absent); version
// is required for kind mcp-server (U4); an mcp declaration must list its
// transports and a skill declaration must carry invokesTools, empty list
// allowed. Each absence is a typed error from pkg/core/codes. A missing file
// surfaces as a wrapped os.ErrNotExist.
func LoadDeclared(path string) (*manifest.CapabilityManifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("load declared config: %w", err)
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	var d yamlDecl
	if err := dec.Decode(&d); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("load declared config %s: document is empty", path)
		}
		return nil, fmt.Errorf("load declared config %s: %w", path, err)
	}
	// One declaration per file, mirroring the trailing data rule of
	// manifest.Parse: a second document is an error, not silently ignored.
	if err := dec.Decode(new(yamlDecl)); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("load declared config %s: more than one YAML document", path)
	}

	if d.Kind == "" {
		return nil, codes.E(codes.ManifestFieldRequired, "smithmark.yaml: kind must be present")
	}
	kind := manifest.ArtifactKind(d.Kind)
	if kind != manifest.KindMCPServer && kind != manifest.KindSkill {
		return nil, codes.E(codes.ManifestEnumInvalid, "smithmark.yaml: unknown kind %q", d.Kind)
	}
	if d.Name == "" {
		return nil, codes.E(codes.ManifestFieldRequired, "smithmark.yaml: name must be present")
	}
	if d.Source == "" {
		return nil, codes.E(codes.ManifestFieldRequired, "smithmark.yaml: source must be present")
	}
	if kind == manifest.KindMCPServer && d.Version == "" {
		return nil, codes.E(codes.ManifestVersionRequired, "smithmark.yaml: version is required for kind mcp-server (U4)")
	}

	if d.Capabilities == nil {
		return nil, codes.E(codes.ManifestCapabilitiesKeyMissing,
			"smithmark.yaml: capabilities block must be present with all five keys (D6)")
	}
	for _, k := range []struct {
		name   string
		absent bool
	}{
		{"networkEgress", d.Capabilities.NetworkEgress == nil},
		{"filesystem", d.Capabilities.Filesystem == nil},
		{"exec", d.Capabilities.Exec == nil},
		{"env", d.Capabilities.Env == nil},
		{"secrets", d.Capabilities.Secrets == nil},
	} {
		if k.absent {
			return nil, codes.E(codes.ManifestCapabilitiesKeyMissing,
				"smithmark.yaml: capabilities.%s is absent; declare it as an empty list if none apply (D6)", k.name)
		}
	}

	switch kind {
	case manifest.KindMCPServer:
		if d.Skill != nil {
			return nil, codes.E(codes.ManifestKindSurfaceMismatch,
				"smithmark.yaml: kind mcp-server must not declare a skill block")
		}
		if d.MCP == nil || d.MCP.Transports == nil {
			return nil, codes.E(codes.ManifestSurfaceKeyMissing,
				"smithmark.yaml: mcp.transports is absent; an mcp declaration must list its transports")
		}
	case manifest.KindSkill:
		if d.MCP != nil {
			return nil, codes.E(codes.ManifestKindSurfaceMismatch,
				"smithmark.yaml: kind skill must not declare an mcp block")
		}
		if d.Skill == nil || d.Skill.InvokesTools == nil {
			return nil, codes.E(codes.ManifestSurfaceKeyMissing,
				"smithmark.yaml: skill.invokesTools is absent; declare it as an empty list if none apply")
		}
	}

	// Field for field mapping into the core types. The make calls preserve
	// the declared but empty distinction: a declared empty list stays a non
	// nil empty slice, which Validate treats as declared none (D6).
	egress := make([]manifest.EgressRule, len(d.Capabilities.NetworkEgress))
	for i, r := range d.Capabilities.NetworkEgress {
		egress[i] = manifest.EgressRule{Host: r.Host, Ports: r.Ports, Reason: r.Reason}
	}
	fs := make([]manifest.FSRule, len(d.Capabilities.Filesystem))
	for i, r := range d.Capabilities.Filesystem {
		fs[i] = manifest.FSRule{Path: r.Path, Access: r.Access, Reason: r.Reason}
	}
	exec := make([]manifest.ExecRule, len(d.Capabilities.Exec))
	for i, r := range d.Capabilities.Exec {
		exec[i] = manifest.ExecRule{Binary: r.Binary, Reason: r.Reason}
	}

	m := &manifest.CapabilityManifest{
		SchemaVersion: declSchemaVersion,
		Artifact: manifest.PredicateArtifact{
			Kind:    kind,
			Name:    d.Name,
			Version: d.Version,
			Source:  manifest.SourceKind(d.Source),
		},
		Capabilities: manifest.CapabilitySet{
			NetworkEgress: egress,
			Filesystem:    fs,
			Exec:          exec,
			Env:           d.Capabilities.Env,
			Secrets:       d.Capabilities.Secrets,
		},
	}
	switch kind {
	case manifest.KindMCPServer:
		m.MCP = &manifest.MCPSurface{Transports: d.MCP.Transports}
	case manifest.KindSkill:
		m.Skill = &manifest.SkillSurface{InvokesTools: d.Skill.InvokesTools}
	}
	return m, nil
}
