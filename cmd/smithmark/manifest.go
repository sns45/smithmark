package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/sns45/smithmark/pkg/core/codes"
	"github.com/sns45/smithmark/pkg/core/manifest"
)

// newManifestCmd groups the manifest authoring subcommands. Only init exists
// in v0.1.
func newManifestCmd(d *deps) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Author and scaffold smithmark.yaml capability manifests",
	}
	cmd.AddCommand(newManifestInitCmd(d))
	return cmd
}

// initOptions holds the parsed manifest init flag surface. The repeatable
// flags accumulate into slices; each capability flag encodes one rule in a
// compact string form parsed by buildInitDoc.
type initOptions struct {
	kind         string
	name         string
	source       string
	version      string
	transports   []string
	egress       []string
	fs           []string
	exec         []string
	env          []string
	secrets      []string
	invokesTools []string
	out          string
	force        bool
}

// newManifestInitCmd builds the manifest init command: a flag driven scaffold
// that writes a valid smithmark.yaml LoadDeclared round trips. v0.1 is flag
// driven only; the spec's interactive mode is deferred.
func newManifestInitCmd(d *deps) *cobra.Command {
	o := &initOptions{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Scaffold a smithmark.yaml capability manifest from flags",
		Long: "Write a smithmark.yaml capability manifest from flags. v0.1 is flag " +
			"driven only; an interactive mode that prompts on a TTY is deferred to a " +
			"later release. --kind, --name, and --source are always required, and " +
			"--version is additionally required for kind mcp-server.",
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runManifestInit(d, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.kind, "kind", "", "artifact kind: skill or mcp-server (required)")
	f.StringVar(&o.name, "name", "", "artifact name (required)")
	f.StringVar(&o.source, "source", "", "artifact source: npm, oci, pypi, local, or mcp-registry (required)")
	f.StringVar(&o.version, "version", "", "artifact version (required for mcp-server)")
	f.StringArrayVar(&o.transports, "transport", nil, "declared MCP transport: stdio, http, or sse (repeatable, mcp-server only)")
	f.StringArrayVar(&o.egress, "egress", nil, "network egress rule host[:port] (repeatable)")
	f.StringArrayVar(&o.fs, "fs", nil, "filesystem rule path:access (repeatable)")
	f.StringArrayVar(&o.exec, "exec", nil, "exec rule binary (repeatable)")
	f.StringArrayVar(&o.env, "env", nil, "declared environment variable name (repeatable)")
	f.StringArrayVar(&o.secrets, "secret", nil, "secret rule kind:provider (repeatable)")
	f.StringArrayVar(&o.invokesTools, "invokes-tool", nil, "tool this skill invokes (repeatable, skill only)")
	f.StringVar(&o.out, "out", declFileName, "path to write the declaration to")
	f.BoolVar(&o.force, "force", false, "overwrite an existing file")
	return cmd
}

// runManifestInit validates the flag set, builds the declaration document,
// and writes it, refusing to clobber an existing file without --force.
func runManifestInit(d *deps, o *initOptions) error {
	if err := validateInitFlags(o); err != nil {
		return err
	}

	doc, err := buildInitDoc(o)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("manifest init: encoding %s: %w", o.out, err)
	}

	if !o.force {
		if _, statErr := os.Stat(o.out); statErr == nil {
			return fmt.Errorf("manifest init: %s already exists; pass --force to overwrite", o.out)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("manifest init: checking %s: %w", o.out, statErr)
		}
	}
	if err := os.WriteFile(o.out, data, 0o644); err != nil {
		return fmt.Errorf("manifest init: writing %s: %w", o.out, err)
	}
	fmt.Fprintf(d.Stdout, "wrote %s\n", o.out)
	return nil
}

// validateInitFlags reports every missing required flag in a single error, so
// a maker fixes them all at once rather than one round trip at a time, and
// rejects a kind mismatched surface flag before anything is written.
func validateInitFlags(o *initOptions) error {
	var missing []string
	if o.kind == "" {
		missing = append(missing, "--kind")
	}
	if o.name == "" {
		missing = append(missing, "--name")
	}
	if o.source == "" {
		missing = append(missing, "--source")
	}
	if o.kind == string(manifest.KindMCPServer) && o.version == "" {
		missing = append(missing, "--version")
	}
	if len(missing) > 0 {
		return fmt.Errorf("manifest init: missing required flags: %s", strings.Join(missing, ", "))
	}

	switch o.kind {
	case string(manifest.KindSkill):
		if len(o.transports) > 0 {
			return fmt.Errorf("manifest init: --transport is only valid for kind mcp-server")
		}
	case string(manifest.KindMCPServer):
		if len(o.invokesTools) > 0 {
			return fmt.Errorf("manifest init: --invokes-tool is only valid for kind skill")
		}
	default:
		return codes.E(codes.ManifestEnumInvalid,
			"manifest init: unknown kind %q; want skill or mcp-server", o.kind)
	}
	return nil
}

// initDoc mirrors the smithmark.yaml authoring schema (U1). It is a distinct
// type from the loader's own yaml structs by design: the writer and the reader
// each own their mapping, so neither can silently reshape the file format for
// the other. All five capability keys are always emitted, as empty lists when
// no rule was supplied, because LoadDeclared treats an absent key as an error
// but an empty list as a valid "none declared".
type initDoc struct {
	Kind         string           `yaml:"kind"`
	Name         string           `yaml:"name"`
	Version      string           `yaml:"version,omitempty"`
	Source       string           `yaml:"source"`
	MCP          *initMCP         `yaml:"mcp,omitempty"`
	Skill        *initSkill       `yaml:"skill,omitempty"`
	Capabilities initCapabilities `yaml:"capabilities"`
}

type initMCP struct {
	Transports []string `yaml:"transports"`
}

type initSkill struct {
	InvokesTools []string `yaml:"invokesTools"`
}

type initCapabilities struct {
	NetworkEgress []initEgress `yaml:"networkEgress"`
	Filesystem    []initFS     `yaml:"filesystem"`
	Exec          []initExec   `yaml:"exec"`
	Env           []string     `yaml:"env"`
	Secrets       []string     `yaml:"secrets"`
}

type initEgress struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports,omitempty"`
}

type initFS struct {
	Path   string `yaml:"path"`
	Access string `yaml:"access"`
}

type initExec struct {
	Binary string `yaml:"binary"`
}

// buildInitDoc turns the flag set into a declaration document. Every
// capability slice is initialized non nil so it marshals as an empty list
// rather than being omitted; the surface block (mcp or skill) matches the
// kind. This function does not itself validate the rule grammars: it writes
// what the maker asked for, and LoadDeclared plus Validate are the authority
// on whether the result is a valid manifest.
func buildInitDoc(o *initOptions) (*initDoc, error) {
	caps := initCapabilities{
		NetworkEgress: []initEgress{},
		Filesystem:    []initFS{},
		Exec:          []initExec{},
		Env:           append([]string{}, o.env...),
		Secrets:       append([]string{}, o.secrets...),
	}
	for _, e := range o.egress {
		host, ports := parseEgress(e)
		caps.NetworkEgress = append(caps.NetworkEgress, initEgress{Host: host, Ports: ports})
	}
	for _, rule := range o.fs {
		path, access, err := parseFS(rule)
		if err != nil {
			return nil, err
		}
		caps.Filesystem = append(caps.Filesystem, initFS{Path: path, Access: access})
	}
	for _, b := range o.exec {
		caps.Exec = append(caps.Exec, initExec{Binary: b})
	}

	doc := &initDoc{
		Kind:         o.kind,
		Name:         o.name,
		Version:      o.version,
		Source:       o.source,
		Capabilities: caps,
	}
	switch o.kind {
	case string(manifest.KindMCPServer):
		doc.MCP = &initMCP{Transports: append([]string{}, o.transports...)}
	case string(manifest.KindSkill):
		doc.Skill = &initSkill{InvokesTools: append([]string{}, o.invokesTools...)}
	}
	return doc, nil
}

// parseEgress splits a host[:port] egress flag while leaving IPv6 literals
// intact. A bracketed literal carries any port after the closing bracket
// ([::1]:443 yields host ::1 port 443, with the brackets stripped from the
// host). An unbracketed value treats the suffix after the last colon as a
// port only when the part before that colon carries no other colon, so a bare
// IPv6 literal such as fe80::1, which is all colons and no port, is preserved
// whole. Deeper grammar checks belong to the loader and Validate, not to this
// scaffold.
func parseEgress(s string) (host string, ports []int) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return s, nil // unbalanced bracket: leave it for Validate to reject
		}
		inner := s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return inner, nil
		}
		if strings.HasPrefix(rest, ":") {
			if p, err := strconv.Atoi(rest[1:]); err == nil && p >= 1 && p <= 65535 {
				return inner, []int{p}
			}
		}
		return s, nil // bracketed but no clean trailing port: preserve whole
	}
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s[:i], ":") {
		if p, err := strconv.Atoi(s[i+1:]); err == nil && p >= 1 && p <= 65535 {
			return s[:i], []int{p}
		}
	}
	return s, nil
}

// parseFS splits a path:access filesystem flag on its last colon, so a path
// that itself contains a colon keeps it. The access token is written as given;
// Validate is the authority on whether it is read, write, or readwrite.
func parseFS(s string) (path, access string, err error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", "", fmt.Errorf("manifest init: --fs %q must be path:access", s)
	}
	return s[:i], s[i+1:], nil
}
