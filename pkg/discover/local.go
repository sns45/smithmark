// Package discover holds the I/O adapters that read artifacts and their
// declarations: local files here, registries and running servers in later
// files. The pure core never touches the filesystem, network, or clock (spec
// 2.1); this package does that work and hands the results to pkg/core types.
package discover

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sns45/smithmark/pkg/core/bundle"
	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// declSchemaVersion is the predicate schema version stamped on every loaded
// manifest. It references the single exported manifest.SchemaVersion constant
// that Validate checks against, so the loader and the validator can never
// drift onto two different literals.
const declSchemaVersion = manifest.SchemaVersion

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

// yamlMCPSurface carries the declared transports and, optionally, the launch
// command attest uses to extract the tool listing. Tools, resources, and
// prompts are extracted from the running server by attest (U2), never
// declared, so those keys stay unknown fields here by construction. command is
// the maker's authoritative statement of how to start the stdio server for
// extraction (controller resolution 3, Task 2.8); it lives inside this struct
// rather than as a top level field so it is valid only where an mcp block is
// valid at all. A skill declaration cannot reach it: a skill may not carry an
// mcp block, so a command smuggled onto a skill trips the same kind versus
// surface mismatch a stray mcp block already does, and a command placed
// anywhere else is an unknown field.
type yamlMCPSurface struct {
	Transports []string `yaml:"transports"`
	Command    []string `yaml:"command"`
}

// yamlSkillSurface carries invokesTools and the optional executables list.
// The entry digest and script list themselves still come from the skill
// directory walker, never from the declaration. executables (Task 2.2) is
// the maker's authoritative statement of which script paths are executable:
// listing them here makes the walker's mode rule, and therefore the bundle
// digest, independent of any platform specific executable bit, which
// Windows does not have. executables lives inside this struct rather than
// as a top level yamlDecl field, so it is valid only where a skill block is
// valid at all; declaring it on an mcp-server document trips the same kind
// versus surface mismatch check that any skill block on an mcp kind already
// does.
type yamlSkillSurface struct {
	InvokesTools []string `yaml:"invokesTools"`
	Executables  []string `yaml:"executables"`
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

// Declaration is everything LoadDeclared reads out of a smithmark.yaml
// authoring file: the partially populated manifest, plus, for a skill
// declaration only, the executables list (Task 2.2). Executables is nil for
// an mcp-server declaration and nil for a skill declaration that omits the
// optional executables key; it is a non nil empty or populated slice only
// when the key was present. This wraps LoadDeclared's original single
// manifest return so the executables list, which the manifest type itself
// has no field for, can travel alongside it to the caller that drives
// WalkSkill (a sanctioned API change over the Task 2.1 signature).
type Declaration struct {
	Manifest    *manifest.CapabilityManifest
	Executables []string // skill only; nil otherwise
	// Command is the optional launch command an mcp-server declaration carries
	// under its mcp block, for attest to extract the tool listing from the
	// running server (U2). It is nil for a skill declaration and nil for an
	// mcp-server declaration that omits the optional command key; it is a non
	// nil slice only when the key was present.
	Command []string
}

// LoadDeclared reads and strictly parses a smithmark.yaml declaration (U1)
// and returns a Declaration wrapping a partially populated manifest: the
// artifact block, the five capability keys, and the declared surface
// fields. GeneratedAt, Generator, Dependencies, and the extraction owned
// surface fields (mcp tools, resources, prompts; skill entryDigest,
// scripts) are left unset for attest to complete, so the returned manifest
// does not pass Validate as is.
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
func LoadDeclared(path string) (*Declaration, error) {
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
	var executables []string
	var command []string
	switch kind {
	case manifest.KindMCPServer:
		m.MCP = &manifest.MCPSurface{Transports: d.MCP.Transports}
		command = d.MCP.Command
	case manifest.KindSkill:
		m.Skill = &manifest.SkillSurface{InvokesTools: d.Skill.InvokesTools}
		executables = d.Skill.Executables
	}
	return &Declaration{Manifest: m, Executables: executables, Command: command}, nil
}

// SkillInfo carries the frontmatter identity read from a skill's SKILL.md:
// its name and version, used elsewhere to cross check the smithmark.yaml
// declaration against what the skill itself claims to be.
type SkillInfo struct {
	Name    string
	Version string // empty when frontmatter has no version (U4)
}

// WalkSkill walks a skill directory rooted at root and returns the three
// things spec 4's I/O half owes the pure core and the manifest: the
// normalized file set bundle.Digest consumes, the skill surface (entry
// digest and scripts; InvokesTools is always left nil, since the
// declaration in smithmark.yaml owns that key, never the walker), and the
// identity read from SKILL.md's frontmatter.
//
// Mode rule: when declaredExecutables is non nil (the skill's smithmark.yaml
// carries the executables key, loaded separately by LoadDeclared and passed
// in here), that list is exhaustive. A file is ModeExecutable exactly when
// its root relative, forward slash path appears in the list, and the on disk
// unix executable bit is ignored entirely for every path, on every operating
// system. This is precisely the condition under which the resulting bundle
// digest is platform independent: a maker lists a script once, and the digest
// is identical on Linux, macOS, and Windows, none of which agree on what "the
// executable bit" even means on the other two (Windows has none). When
// declaredExecutables is nil (no key was declared), the mode falls back to
// the file's unix executable bit, which is always false on Windows. Any
// declared path that matches no walked file is a codes.SkillScriptPathInvalid
// error naming the path, so a separator or case typo in the executables list
// fails loudly rather than silently doing nothing.
//
// WalkSkill rejects every symlink found anywhere under root, including root
// itself, with a codes.BundleSymlinkRejected error naming the offending
// path; it never follows one. Empty directories produce no entries and are
// otherwise ignored, matching spec 4's exclusion of directories from the
// digest. SKILL.md must exist directly under root; its absence is a
// codes.ManifestFieldRequired error naming SKILL.md. Every regular file
// under root, including smithmark.yaml itself, becomes part of the returned
// file set and thus part of the digest: the declaration ships inside the
// bundle by design (bundle.ValidPath imposes no exclusion for it). Every
// file except SKILL.md also becomes a manifest.FileRef in the returned
// skill surface, sorted by path; SKILL.md's own sha256 becomes EntryDigest
// instead of a Scripts entry.
func WalkSkill(root string, declaredExecutables []string) ([]bundle.File, *manifest.SkillSurface, SkillInfo, error) {
	// A nil declaredExecutables means the executables key was absent, which
	// selects the unix disk bit fallback; a non nil slice (even empty) means
	// the key was declared, which makes that list the exhaustive source of
	// truth for executable mode.
	declaredPresent := declaredExecutables != nil
	declared := make(map[string]bool, len(declaredExecutables))
	for _, p := range declaredExecutables {
		declared[p] = true
	}
	matched := make(map[string]bool, len(declaredExecutables))

	var files []bundle.File
	var skillMD []byte
	var skillMDHex string
	haveSkillMD := false

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk skill %s: %w", root, err)
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return codes.E(codes.BundleSymlinkRejected, "symlink rejected while walking skill root %s: %s", root, path)
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("walk skill %s: %w", root, err)
		}
		relSlash := filepath.ToSlash(rel)

		// Mode: when the executables key is present the declaration is
		// exhaustive and the disk bit is ignored outright; when it is absent
		// the unix executable bit is the fallback (always false on Windows).
		mode := bundle.ModeRegular
		if declaredPresent {
			if declared[relSlash] {
				mode = bundle.ModeExecutable
				matched[relSlash] = true
			}
		} else {
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("walk skill %s: stat %s: %w", root, relSlash, err)
			}
			if info.Mode()&0o111 != 0 {
				mode = bundle.ModeExecutable
			}
		}

		// SKILL.md is read fully once because its bytes feed frontmatter
		// parsing; every other file is hashed by streaming its handle into
		// sha256, so a large script is never held in memory just to digest it.
		var hexSum string
		if relSlash == "SKILL.md" {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("walk skill %s: reading %s: %w", root, relSlash, err)
			}
			sum := sha256.Sum256(data)
			hexSum = hex.EncodeToString(sum[:])
			skillMD = data
			skillMDHex = hexSum
			haveSkillMD = true
		} else {
			hexSum, err = hashFileStreaming(path)
			if err != nil {
				return fmt.Errorf("walk skill %s: reading %s: %w", root, relSlash, err)
			}
		}
		files = append(files, bundle.File{Path: relSlash, Mode: mode, SHA256: hexSum})
		return nil
	})
	if walkErr != nil {
		return nil, nil, SkillInfo{}, walkErr
	}
	// A declared executable that matched no walked file is a typo in the
	// executables list, surfaced loudly rather than silently ignored.
	if declaredPresent {
		for _, p := range declaredExecutables {
			if !matched[p] {
				return nil, nil, SkillInfo{}, codes.E(codes.SkillScriptPathInvalid,
					"skill root %s: declared executable %q matches no file in the bundle", root, p)
			}
		}
	}
	if !haveSkillMD {
		return nil, nil, SkillInfo{}, codes.E(codes.ManifestFieldRequired,
			"skill root %s: SKILL.md is required", root)
	}

	scripts := make([]manifest.FileRef, 0, len(files))
	for _, f := range files {
		if f.Path == "SKILL.md" {
			continue
		}
		scripts = append(scripts, manifest.FileRef{
			Path:   f.Path,
			Digest: manifest.DigestSet{"sha256": f.SHA256},
			Mode:   string(f.Mode),
		})
	}
	sort.Slice(scripts, func(i, j int) bool { return scripts[i].Path < scripts[j].Path })

	surface := &manifest.SkillSurface{
		EntryDigest:  manifest.DigestSet{"sha256": skillMDHex},
		Scripts:      scripts,
		InvokesTools: nil,
	}

	return files, surface, parseSkillFrontmatter(skillMD), nil
}

// hashFileStreaming returns the lowercase hex sha256 of the file at path,
// computed by copying the open handle into the hasher rather than reading the
// whole file into memory first. The digest is byte identical to hashing the
// full contents, so the pinned fixture bundle vector is unaffected.
func hashFileStreaming(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// frontmatterDelim is the line, ignoring surrounding whitespace, that opens
// and closes a SKILL.md frontmatter block.
const frontmatterDelim = "---"

// parseSkillFrontmatter extracts the name and version keys from SKILL.md's
// optional YAML frontmatter block, delimited by lines containing only three
// dashes. This is the one lenient, non KnownFields YAML parse in this
// package: SKILL.md is a foreign, community owned format, not a smithmark
// authoring surface, so a frontmatter key this package does not know about
// belongs to the skill author, not to an error. A SKILL.md with no
// frontmatter block, or with an unparsable one, yields a zero SkillInfo
// rather than failing the walk.
func parseSkillFrontmatter(data []byte) SkillInfo {
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != frontmatterDelim {
		return SkillInfo{}
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != frontmatterDelim {
			continue
		}
		var fm struct {
			Name    string `yaml:"name"`
			Version string `yaml:"version"`
		}
		if err := yaml.Unmarshal([]byte(strings.Join(lines[1:i], "\n")), &fm); err != nil {
			return SkillInfo{}
		}
		return SkillInfo{Name: fm.Name, Version: fm.Version}
	}
	return SkillInfo{}
}
