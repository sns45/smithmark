# smithmark v0.1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship smithmark v0.1: a generator, signer, publisher, and verifier of capability attestations for MCP servers and SKILL.md bundles, with two submission ready standards proposals.

**Architecture:** Pure deterministic core (`pkg/core`) with all I/O in adapters (`pkg/discover`, `pkg/compose`, `cmd`); in-toto DSSE envelopes with the custom predicate `https://in8.sh/attestation/agent-capability/v1`; Sigstore for signing; OCI as the universal attestation store with a deterministic ref mapping.

**Tech Stack:** Go 1.25, cobra, `sigstore/sigstore-go`, `in-toto/in-toto-golang`, `CycloneDX/cyclonedx-go`, `cyberphone/json-canonicalization` (RFC 8785), `oras-project/oras-go`, `gopkg.in/yaml.v3`, goreleaser.

**Normative inputs:** `requirements.md` (the spec; section references below are to it) and `docs/decisions.md` (approved decisions D1 to D6, U1 to U7). Where this plan and those documents disagree, the spec wins, then decisions, then this plan.

## Global Constraints

- Module path `github.com/sns45/smithmark`; Apache 2.0 license; Go 1.25.
- `pkg/core` is pure and deterministic: no network, no filesystem walks, no clock except injected. Same evidence and same injected time produce byte identical output (spec §2.1). Enforced by an import guard test that fails the build if `pkg/core` gains I/O imports.
- Signature operations are native only, behind a build tag interface. Non native builds get a fail closed stub returning code `SIGNING_UNAVAILABLE_PLATFORM`. No Wasm target in v0.1 (spec §2.1).
- Strict schema parsing everywhere: unknown fields are errors, JSON via `DisallowUnknownFields`, YAML via `KnownFields(true)` (spec §2.2).
- Every check and lint finding has a stable machine readable code. Codes are API: documented in `docs/codes.md`, never repurposed (spec §3). A doc sync test asserts every code constant appears in `docs/codes.md`.
- Reuse, never re-implement: no hand rolled crypto, JWT, envelope parsing, or canonical JSON (spec §2.2). RFC 8785 comes from `cyberphone/json-canonicalization`.
- Real fixtures committed to `testdata/`; no network in CI (spec §9).
- Golden file snapshots support a `-update` flag (spec §9).
- Single comprehensive files preferred over fragmented structures (family convention; overrides any instinct to split small).
- Prose in docs, comments, and commit messages avoids hyphens and dashes (maintainer style rule); code identifiers, flags, and paths are exempt.
- Exit codes are API (decision D4): 0 pass, 1 verification failure, 2 strict lint gate, 3 operational error.

## Milestone Workflow (applies to every phase)

1. Build happens in a git worktree (use superpowers:using-git-worktrees at execution start).
2. One PR per milestone; run the code-review skill before each merge.
3. **STOP at every phase boundary.** Summarize what shipped against the spec §10 deliverable table and wait for maintainer review. Batch questions per milestone.
4. Fresh subagent per task. Each subagent reads only: the spec sections named by its task, the relevant `docs/decisions.md` entries, and its own plan entry. Two stage review per task: spec compliance first, then code quality.
5. Strict TDD everywhere: failing test first (RED), minimal implementation (GREEN), refactor. Every task's steps encode this cycle.
6. **Phase 0 is a hard gate.** No Go code exists in the repo until the maintainer says go after reading the whitespace sweep. If the §1.2 claim is falsified, the maintainer re-scopes before a single line of Go is written.

## File Structure (final state)

```
smithmark/
├── cmd/smithmark/            main.go plus one file per command (attest.go,
│                             verify.go, lint.go, registry.go, manifest.go)
├── pkg/core/
│   ├── manifest/manifest.go  domain types, strict parse, validation,
│   │                         statement assembly, canonical serialization
│   ├── bundle/bundle.go      canonical skill bundle digest (spec §4)
│   ├── verify/verify.go      verification stages, check codes, report,
│   │                         assayward Evidence emission
│   └── lint/lint.go          JS/TS and Python heuristics, gap engine,
│                             finding codes
├── pkg/discover/
│   ├── refmap.go             pure deterministic OCI ref mapping (D3)
│   ├── local.go              smithmark.yaml loader, skill dir walker
│   ├── npm.go                npm packument and provenance fetch
│   ├── oci.go                referrers and tag discovery
│   ├── mcptools.go           stdio tools/list extraction (U2)
│   └── registry.go           MCP Registry API client
├── pkg/compose/
│   ├── forgeseal.go          exec adapter for dependency SBOMs (D2)
│   ├── sign.go               Signer/Verifier interfaces
│   ├── sign_native.go        sigstore-go implementation (build tag native)
│   ├── sign_stub.go          fail closed stub (build tag !native)
│   └── push.go               ORAS push/attach
├── internal/golden/          golden file test harness with -update
├── surfaces/claude-code-hook/
├── action/
├── policies/
├── proposals/
│   ├── cyclonedx-agent-capability/
│   └── mcp-registry-provenance/
├── docs/codes.md             the code registry (API)
├── docs/research/whitespace-sweep.md
└── testdata/
```

---

# Phase 0 (M0): Whitespace Sweep — HARD GATE

Implements: spec whitespace status block, §1.2, §10 row M0. No code tasks in this phase.

### Task 0.1: Adversarial prior art sweep

**Files:**
- Create: `docs/research/notes/` working notes (one file per competitor, deleted or kept at maintainer discretion after 0.2)

**Interfaces:**
- Produces: per competitor evidence notes consumed by Task 0.2. Each note records: what it is, what it does, what it does not do, citations (URL plus access date), and its bearing on the §1.2 claim.

- [ ] **Step 1: Sweep the five named prior art items (spec whitespace block)**

For each of the following, fetch primary sources (project README, docs, papers, release notes), not just marketing pages:

1. **Invariant Labs `mcp-scan`** — establish: scanner or attestation producer? Does it sign anything? Does it emit policy consumable output? Sources: github.com/invariantlabs-ai/mcp-scan, invariantlabs.ai docs.
2. **Stacklok ToolHive** — establish: registry/runtime gateway or attestation framework? What does its "verified" state mean and who signs it? Sources: github.com/stacklok/toolhive, docs.stacklok.com.
3. **ETDI paper** (Enhanced Tool Definition Interface, arXiv 2506.01333 or successor) — closest prior art on paper: signed tool definitions with OAuth. Establish: paper only or implementation? Tool definitions versus capability manifests (egress/fs/exec/env/secrets)? Any SLSA/Sigstore/SBOM composition? Any registry to admission loop?
4. **MCP Registry moderation and verification** — read the actual registry docs and `server.json` schema at github.com/modelcontextprotocol/registry: what do namespace verification and moderation attest, cryptographically or otherwise? Is there any attestation reference field today (this also feeds the RFC gap statement)?
5. **npm provenance coverage of MCP packages** — what npm provenance proves (build origin) versus what it does not (capabilities); spot check whether popular MCP server packages ship provenance at all (check 5 to 10 popular ones via the npm registry API and record the ratio).

- [ ] **Step 2: Discovery sweep for unnamed prior art**

Search for anything material the spec missed. Minimum queries (web plus arXiv plus GitHub topic search): "MCP server attestation", "MCP capability manifest", "signed tool definition LLM agent", "agent tool provenance", "skill manifest signing", "MCP tool poisoning defense", "Docker MCP catalog signing", "AI agent supply chain security". Record every hit that either signs artifacts, declares capabilities, or gates admission; explicitly note ones that look adjacent but are not (and why).

- [ ] **Step 3: Verify claims adversarially**

For each competitor, attempt to REFUTE the §1.2 whitespace claim with its documentation: find the strongest sentence in their docs that sounds like "signed capability declaration consumable by policy". Quote it verbatim in the note with a citation, then assess whether it actually is that. The sweep fails review if any note lacks primary source citations.

**Verification:** every note names its sources with URLs and access dates; the five named items all have notes; the discovery sweep lists its queries and their disposition.

### Task 0.2: Write `docs/research/whitespace-sweep.md`

**Files:**
- Create: `docs/research/whitespace-sweep.md`

**Interfaces:**
- Consumes: Task 0.1 notes.
- Produces: the go/no-go input document for the maintainer, and positioning language reused in `proposals/` (spec §1.4) and the README.

- [ ] **Step 1: Write the landscape table**

Columns: project, category (scanner, registry/gateway, provenance system, paper, attestation framework), signs artifacts?, declares capabilities?, policy consumable output?, verifies at admission?, composes Sigstore/SLSA/CycloneDX?. One row per swept item, every cell backed by a 0.1 citation.

- [ ] **Step 2: Write the verdict**

An explicit section titled "Verdict on §1.2" answering, in order: (a) does any prior art treat capability declarations as signed, policy consumable artifacts for MCP servers or skills; (b) does the claim survive as written, survive with narrowing, or fail; (c) if narrowing is needed, the exact replacement sentence for §1.2. ETDI must be addressed by name in the verdict regardless of outcome (it is the nearest neighbor).

- [ ] **Step 3: Write positioning language**

Recommended positioning paragraphs with named prior art and documented failure modes, per the EB-1A standard: novelty demonstrated, never asserted. Each failure mode names the competitor and cites where its approach stops short (for example, scanning inspects one install at a time and produces no portable evidence; curation centralizes trust without cryptographic binding to the artifact).

- [ ] **Step 4: Commit**

```bash
git add docs/research/
git commit -m "Add whitespace sweep: prior art landscape, verdict on the novelty claim, positioning"
```

**Verification:** the document contains the table, an explicit verdict section, and positioning prose; every factual claim carries a citation; ETDI is addressed by name.

### Task 0.3: STOP — maintainer go/no-go

Present the verdict and the deliverable summary against spec §10 row M0. **Do not proceed to Phase 1 without an explicit go.** If the claim is falsified or narrowed, the maintainer re-scopes; Phase 1 onward may be rewritten.

# Phase 1 (M1): Core Model

Implements: spec §3, §4, §10 row M1; decisions D1, D6, U4, U6. Everything in this phase is pure Go under `pkg/core` plus scaffolding.

### Task 1.1: Module scaffold, purity guard, golden harness

**Files:**
- Create: `go.mod`, `LICENSE` (Apache 2.0 text), `.gitignore`, `.github/workflows/ci.yml`, `internal/arch/arch_test.go`, `internal/golden/golden.go`

**Interfaces:**
- Produces: `golden.Assert(t *testing.T, got []byte, path string)` used by every later golden test; a CI matrix (ubuntu, macos, windows) that every later determinism test relies on; a purity guard that constrains every later `pkg/core` change.

- [ ] **Step 1: Initialize the module**

```bash
go mod init github.com/sns45/smithmark
```

Add `LICENSE` with the Apache 2.0 text (SPDX Apache-2.0) and `.gitignore` containing `dist/`, `bin/`, `*.out`.

- [ ] **Step 2: Write the failing purity guard test**

`internal/arch/arch_test.go`. It fails right now because `pkg/core` does not exist yet; that is the RED state.

```go
package arch_test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// Spec §2.1: pkg/core is pure. Direct imports of any pkg/core package must
// never include I/O packages. This test is the enforcement mechanism the
// spec calls the lint/test guard.
var forbidden = []string{"os", "os/exec", "io/fs", "path/filepath", "syscall", "net"}

type pkgInfo struct {
	ImportPath string
	Imports    []string
	GoFiles    []string
	Dir        string
}

func corePackages(t *testing.T) []pkgInfo {
	t.Helper()
	out, err := exec.Command("go", "list", "-json", "./pkg/core/...").Output()
	if err != nil {
		t.Fatalf("go list ./pkg/core/...: %v", err)
	}
	var pkgs []pkgInfo
	dec := json.NewDecoder(strings.NewReader(string(out)))
	for dec.More() {
		var p pkgInfo
		if err := dec.Decode(&p); err != nil {
			t.Fatalf("decoding go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	if len(pkgs) == 0 {
		t.Fatal("no packages under pkg/core; the core must exist")
	}
	return pkgs
}

func TestCoreImportsArePure(t *testing.T) {
	for _, p := range corePackages(t) {
		for _, imp := range p.Imports {
			for _, f := range forbidden {
				if imp == f || strings.HasPrefix(imp, f+"/") ||
					(f == "net" && strings.HasPrefix(imp, "net")) {
					t.Errorf("%s imports %s; pkg/core must stay pure (spec 2.1)", p.ImportPath, imp)
				}
			}
		}
	}
}

func TestCoreNeverReadsTheClock(t *testing.T) {
	out, err := exec.Command("grep", "-rn", "time.Now", "pkg/core").CombinedOutput()
	if err == nil {
		t.Errorf("time.Now found in pkg/core; the clock must be injected (spec 2.1):\n%s", out)
	}
}
```

Note: `grep` exits nonzero on no match, which is the passing case. Run from the repo root; the test file sets no working directory so add `cmd.Dir` handling only if `go test ./internal/...` runs it from the package dir. Fix: both commands must run with `Dir` set to the repo root. Compute it once:

```go
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("finding repo root: %v", err)
	}
	return strings.TrimSpace(string(out))
}
```

Set `cmd.Dir = repoRoot(t)` on both exec calls.

- [ ] **Step 3: Run to verify RED**

Run: `go test ./internal/arch/`
Expected: FAIL with "no packages under pkg/core".

- [ ] **Step 4: Write the golden harness**

`internal/golden/golden.go`:

```go
// Package golden implements golden file assertions with a -update flag
// (spec 9: golden file snapshots with -update).
package golden

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files with observed output")

// Assert compares got against the golden file at path, rewriting it when
// tests run with -update.
func Assert(t *testing.T, got []byte, path string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("creating golden dir: %v", err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("writing golden file: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading golden file %s (run with -update to create): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n got: %s\nwant: %s", path, got, want)
	}
}
```

- [ ] **Step 5: Write the CI workflow**

`.github/workflows/ci.yml`: jobs `test` with matrix `os: [ubuntu-latest, macos-latest, windows-latest]`, steps: checkout, setup-go with `go-version: "1.25"`, `gofmt -l . | tee /dev/stderr | wc -l | grep -q '^0$'` (ubuntu only), `go vet ./...`, `go test ./...`. No network access assumptions beyond module downloads.

- [ ] **Step 6: Create the minimal core so the guard goes GREEN**

The guard needs a package under `pkg/core`. Task 1.2 creates `pkg/core/manifest`; if executing tasks in order, defer GREEN to 1.2 and mark this step done when 1.2 lands. If this task must stand alone, create `pkg/core/codes/codes.go` from Task 1.5 early with just the package clause and one constant.

- [ ] **Step 7: Commit**

```bash
git add go.mod LICENSE .gitignore .github/ internal/
git commit -m "Scaffold module, purity guard, golden harness, CI matrix"
```

**Verification:** `go test ./internal/...` passes once a core package exists; CI file parses (`actionlint` if available, else review).

### Task 1.2: Domain types and strict parsing (`pkg/core/manifest`)

Implements spec §3 and decision D6 (predicate shape), U6 (DigestSet).

**Files:**
- Create: `pkg/core/manifest/manifest.go`
- Test: `pkg/core/manifest/manifest_test.go`

**Interfaces:**
- Produces (exact, later tasks depend on these):

```go
type ArtifactKind string   // KindMCPServer = "mcp-server", KindSkill = "skill"
type SourceKind string     // SourceNPM, SourceOCI, SourcePyPI, SourceLocal, SourceMCPRegistry
type DigestSet map[string]string // algorithm name to lowercase hex (U6)

type ArtifactRef struct {  // spec 3; used by verify and reports, carries the digest
	Kind    ArtifactKind `json:"kind"`
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"` // optional for skills (U4)
	Digest  DigestSet    `json:"digest"`
	Source  SourceKind   `json:"source"`
}

type PredicateArtifact struct { // digestless artifact block inside the predicate (D6)
	Kind    ArtifactKind `json:"kind"`
	Name    string       `json:"name"`
	Version string       `json:"version,omitempty"`
	Source  SourceKind   `json:"source"`
}

type ToolDecl struct {
	Name              string    `json:"name"`
	Description       string    `json:"description,omitempty"`
	InputSchemaDigest DigestSet `json:"inputSchemaDigest"`
}

type MCPSurface struct {
	Tools      []ToolDecl `json:"tools"`
	Resources  []string   `json:"resources"`
	Prompts    []string   `json:"prompts"`
	Transports []string   `json:"transports"` // stdio | http | sse
}

type FileRef struct {
	Path   string    `json:"path"`
	Digest DigestSet `json:"digest"`
	Mode   string    `json:"mode"` // regular | executable
}

type SkillSurface struct {
	EntryDigest  DigestSet `json:"entryDigest"`
	Scripts      []FileRef `json:"scripts"`
	InvokesTools []string  `json:"invokesTools"`
}

type EgressRule struct {
	Host   string `json:"host"`
	Ports  []int  `json:"ports,omitempty"`
	Reason string `json:"reason,omitempty"`
}
type FSRule struct {
	Path   string `json:"path"`
	Access string `json:"access"` // read | write | readwrite
	Reason string `json:"reason,omitempty"`
}
type ExecRule struct {
	Binary string `json:"binary"`
	Reason string `json:"reason,omitempty"`
}

type CapabilitySet struct { // all five keys REQUIRED in JSON; empty array means declared none (D6)
	NetworkEgress []EgressRule `json:"networkEgress"`
	Filesystem    []FSRule     `json:"filesystem"`
	Exec          []ExecRule   `json:"exec"`
	Env           []string     `json:"env"`
	Secrets       []string     `json:"secrets"`
}

type SBOMRef struct {
	SBOMDigest DigestSet `json:"sbomDigest"`
	SBOMFormat string    `json:"sbomFormat"`
	Locator    string    `json:"locator,omitempty"`
}

type GeneratorInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CapabilityManifest struct { // the predicate body, spec 3 and D6
	SchemaVersion string            `json:"schemaVersion"`
	Artifact      PredicateArtifact `json:"artifact"`
	MCP           *MCPSurface       `json:"mcp,omitempty"`
	Skill         *SkillSurface     `json:"skill,omitempty"`
	Capabilities  CapabilitySet     `json:"capabilities"`
	Dependencies  *SBOMRef          `json:"dependencies,omitempty"`
	GeneratedAt   time.Time         `json:"generatedAt"`
	Generator     GeneratorInfo     `json:"generator"`
}

func Parse(data []byte) (*CapabilityManifest, error)      // strict: unknown fields are errors
func (m *CapabilityManifest) Canonical() ([]byte, error)  // RFC 8785 canonical JSON
```

- [ ] **Step 1: Write the failing tests**

`pkg/core/manifest/manifest_test.go`. Test cases:

```go
package manifest

import (
	"strings"
	"testing"
)

const validMCP = `{
  "schemaVersion": "1.0.0",
  "artifact": {"kind": "mcp-server", "name": "better-call-claude", "version": "1.4.2", "source": "npm"},
  "mcp": {"transports": ["stdio"], "tools": [{"name": "initiate_call", "inputSchemaDigest": {"sha256": "ab"}}], "resources": [], "prompts": []},
  "capabilities": {"networkEgress": [], "filesystem": [], "exec": [], "env": [], "secrets": []},
  "generatedAt": "2026-07-16T00:00:00Z",
  "generator": {"name": "smithmark", "version": "0.1.0"}
}`

func TestParseValid(t *testing.T) {
	m, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if m.Artifact.Kind != KindMCPServer || m.MCP == nil || m.Skill != nil {
		t.Errorf("unexpected parse result: %+v", m)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	for name, doc := range map[string]string{
		"top level": strings.Replace(validMCP, `"schemaVersion"`, `"extra": 1, "schemaVersion"`, 1),
		"nested":    strings.Replace(validMCP, `"env": []`, `"env": [], "sneaky": true`, 1),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: unknown field accepted; strict parsing required (spec 2.2)", name)
		}
	}
}

func TestCanonicalIsDeterministicAndSorted(t *testing.T) {
	m, err := Parse([]byte(validMCP))
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.Canonical()
	if string(a) != string(b) {
		t.Error("Canonical is not deterministic")
	}
	if strings.Contains(string(a), "\n") || strings.Contains(string(a), ": ") {
		t.Error("Canonical output contains insignificant whitespace")
	}
}
```

- [ ] **Step 2: Run to verify RED**

Run: `go test ./pkg/core/manifest/`
Expected: FAIL, package does not compile (types undefined).

- [ ] **Step 3: Implement**

Write `manifest.go` with the exact types from the Interfaces block above, plus:

```go
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
```

Import `webpki.org/jsoncanonicalizer` from module `github.com/cyberphone/json-canonicalization/go`; run `go get github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer` and check the module's documented import path via pkg.go.dev before committing (the module layout is unusual; verify rather than assume).

- [ ] **Step 4: Run to verify GREEN**

Run: `go test ./pkg/core/manifest/ ./internal/arch/`
Expected: PASS (the purity guard now also passes: this package imports only bytes, encoding/json, errors, fmt, time, and the canonicalizer).

- [ ] **Step 5: Commit**

```bash
git add pkg/core/manifest/ go.mod go.sum
git commit -m "Add capability manifest domain types with strict parsing and canonical encoding"
```

### Task 1.3: Semantic validation with machine readable codes

Implements spec §3 rules and decision D1 grammars.

**Files:**
- Modify: `pkg/core/manifest/manifest.go` (append validation section)
- Test: `pkg/core/manifest/validate_test.go`

**Interfaces:**
- Produces:

```go
type Issue struct {
	Code   string `json:"code"`   // stable, from pkg/core/codes
	Path   string `json:"path"`   // JSON pointerish location, e.g. capabilities.networkEgress[0].host
	Detail string `json:"detail"`
}
// Validate returns semantic issues sorted by (Code, Path) for determinism.
// An empty slice means the manifest is valid.
func (m *CapabilityManifest) Validate() []Issue
```

- Consumes: code constants from Task 1.5 (`pkg/core/codes`). If executing in order 1.3 before 1.5, define the constants in 1.5's file now with just the ones needed; 1.5 completes the registry.

Validation rules (each row is a test case in the table driven test; each failure produces the named code):

| Rule | Code |
|------|------|
| schemaVersion must be exactly `1.0.0` | `MANIFEST_SCHEMA_VERSION_UNSUPPORTED` |
| kind `mcp-server` requires `mcp` set and `skill` nil; kind `skill` the reverse | `MANIFEST_KIND_SURFACE_MISMATCH` |
| kind must be a known ArtifactKind, source a known SourceKind | `MANIFEST_ENUM_INVALID` |
| version required unless kind is skill (U4) | `MANIFEST_VERSION_REQUIRED` |
| all five capabilities keys present (nil slice means the key was absent) | `MANIFEST_CAPABILITIES_KEY_MISSING` |
| egress host: exact DNS name, IP literal, single leftmost `*.` wildcard, or bare `*` (D1) | `EGRESS_HOST_INVALID` |
| egress ports each in 1..65535 | `EGRESS_PORT_INVALID` |
| fs access in read/write/readwrite | `FS_ACCESS_INVALID` |
| fs path starts with `${home}`, `${tmp}`, `${cwd}`, or is relative (no leading `/`, no drive letter); bare `*` or `**` allowed as escape (D1) | `FS_PATH_INVALID` |
| env entries match `[A-Z_][A-Z0-9_]*` with optional single trailing `*` (D1) | `ENV_NAME_INVALID` |
| secrets match `kind:provider` where each side matches `[a-z0-9][a-z0-9-]*` (D1) | `SECRET_FORMAT_INVALID` |
| transports each in stdio/http/sse | `TRANSPORT_INVALID` |
| FileRef and bundle modes in regular/executable | `MODE_INVALID` |
| DigestSet non empty; keys non empty; values lowercase hex of even length | `DIGEST_INVALID` |

- [ ] **Step 1: Write the failing table driven test**

`validate_test.go` builds a valid manifest via a helper `func validManifest() *CapabilityManifest` (construct the struct literal matching `validMCP`), then each case mutates one field and asserts exactly the expected code appears:

```go
func TestValidateTable(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(m *CapabilityManifest)
		want   string // expected code, empty means valid
	}{
		{"valid", func(m *CapabilityManifest) {}, ""},
		{"bad schema version", func(m *CapabilityManifest) { m.SchemaVersion = "2.0.0" }, codes.ManifestSchemaVersionUnsupported},
		{"skill surface on mcp kind", func(m *CapabilityManifest) { m.Skill = &SkillSurface{} }, codes.ManifestKindSurfaceMismatch},
		{"missing capabilities key", func(m *CapabilityManifest) { m.Capabilities.Env = nil }, codes.ManifestCapabilitiesKeyMissing},
		{"wildcard host ok", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "*.googleapis.com"}}
		}, ""},
		{"double wildcard host", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "*.*.googleapis.com"}}
		}, codes.EgressHostInvalid},
		{"port out of range", func(m *CapabilityManifest) {
			m.Capabilities.NetworkEgress = []EgressRule{{Host: "example.com", Ports: []int{70000}}}
		}, codes.EgressPortInvalid},
		{"absolute fs path", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "/etc/passwd", Access: "read"}}
		}, codes.FSPathInvalid},
		{"token fs path ok", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "${home}/.config/x/**", Access: "readwrite"}}
		}, ""},
		{"bad access", func(m *CapabilityManifest) {
			m.Capabilities.Filesystem = []FSRule{{Path: "data/**", Access: "execute"}}
		}, codes.FSAccessInvalid},
		{"env prefix ok", func(m *CapabilityManifest) { m.Capabilities.Env = []string{"AWS_*"} }, ""},
		{"env lowercase", func(m *CapabilityManifest) { m.Capabilities.Env = []string{"aws_key"} }, codes.EnvNameInvalid},
		{"secret format", func(m *CapabilityManifest) { m.Capabilities.Secrets = []string{"google oauth"} }, codes.SecretFormatInvalid},
		{"secret ok", func(m *CapabilityManifest) { m.Capabilities.Secrets = []string{"oauth:google"} }, ""},
		{"bad transport", func(m *CapabilityManifest) { m.MCP.Transports = []string{"websocket"} }, codes.TransportInvalid},
		{"version optional for skill", func(m *CapabilityManifest) {
			m.Artifact = PredicateArtifact{Kind: KindSkill, Name: "dear-claude-notes", Source: SourceLocal}
			m.MCP = nil
			m.Skill = &SkillSurface{EntryDigest: DigestSet{"sha256": strings.Repeat("ab", 32)}, Scripts: []FileRef{}, InvokesTools: []string{}}
		}, ""},
		{"version required for mcp", func(m *CapabilityManifest) { m.Artifact.Version = "" }, codes.ManifestVersionRequired},
		{"uppercase digest hex", func(m *CapabilityManifest) {
			m.MCP.Tools[0].InputSchemaDigest = DigestSet{"sha256": "AB"}
		}, codes.DigestInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validManifest()
			tc.mutate(m)
			issues := m.Validate()
			if tc.want == "" && len(issues) != 0 {
				t.Fatalf("expected valid, got %+v", issues)
			}
			if tc.want != "" {
				found := false
				for _, is := range issues {
					if is.Code == tc.want {
						found = true
					}
				}
				if !found {
					t.Fatalf("expected code %s, got %+v", tc.want, issues)
				}
			}
		})
	}
}

func TestValidateIsDeterministicallySorted(t *testing.T) {
	m := validManifest()
	m.SchemaVersion = "9"
	m.Capabilities.Env = []string{"bad", "also bad"}
	a := m.Validate()
	b := m.Validate()
	if !reflect.DeepEqual(a, b) {
		t.Error("Validate output is not deterministic")
	}
	if !sort.SliceIsSorted(a, func(i, j int) bool {
		if a[i].Code != a[j].Code {
			return a[i].Code < a[j].Code
		}
		return a[i].Path < a[j].Path
	}) {
		t.Errorf("issues not sorted by (Code, Path): %+v", a)
	}
}
```

- [ ] **Step 2: Run to verify RED** — `go test ./pkg/core/manifest/` fails: `Validate` undefined.

- [ ] **Step 3: Implement `Validate`**

Append to `manifest.go`: one exported `Validate` plus small unexported helpers `validHost`, `validFSPath`, `validEnvName`, `validSecret`, `validDigestSet`, each a direct transcription of the D1 grammar rows above. Host grammar: split on `.`; a leading label of `*` is allowed only once and only leftmost; remaining labels match `[a-z0-9]([a-z0-9-]*[a-z0-9])?`; accept IPv4 dotted quads and bracketless IPv6 via `net/netip.ParseAddr` — netip is pure (it is in `net/netip`, no sockets; the purity guard forbids `net` prefix, so add an explicit allowance for `net/netip` in the guard's forbidden check in `internal/arch/arch_test.go`: skip when `imp == "net/netip"`). Sort issues with `sort.Slice` before returning.

- [ ] **Step 4: Run to verify GREEN** — `go test ./pkg/core/... ./internal/...` PASS.

- [ ] **Step 5: Commit**

```bash
git add pkg/core/manifest/ internal/arch/
git commit -m "Add semantic validation with stable issue codes"
```

### Task 1.4: Canonical skill bundle digest (`pkg/core/bundle`)

Implements spec §4 verbatim. **This algorithm is normative and its stability is a compatibility promise**; the golden vector committed here must never change for v1.

**Files:**
- Create: `pkg/core/bundle/bundle.go`
- Test: `pkg/core/bundle/bundle_test.go`

**Interfaces:**
- Produces:

```go
const Prefix = "smithmark-bundle-v1:"

type Mode string // ModeRegular = "regular", ModeExecutable = "executable"

type File struct { // one already read file; core never touches the filesystem
	Path   string `json:"path"`   // relative, forward slashes
	Mode   Mode   `json:"mode"`
	SHA256 string `json:"sha256"` // lowercase hex of content
}

// Digest computes the canonical bundle digest (spec 4). The I/O layer walks
// the skill root, rejects symlinks with codes.BundleSymlinkRejected, and
// hands the already read set here.
func Digest(files []File) (string, error)
```

- Consumed by: Task 2.2 (walker), Task 2.5 (statement subject), verify recomputation in Phase 3.

- [ ] **Step 1: Write the failing tests**

```go
package bundle

import (
	"strings"
	"testing"
)

func sampleFiles() []File {
	return []File{
		{Path: "scripts/fetch.py", Mode: ModeExecutable, SHA256: strings.Repeat("bb", 32)},
		{Path: "SKILL.md", Mode: ModeRegular, SHA256: strings.Repeat("aa", 32)},
		{Path: "references/notes.md", Mode: ModeRegular, SHA256: strings.Repeat("cc", 32)},
	}
}

// The pinned vector: computed once at implementation time, then frozen.
// Recompute by hand only if you believe the implementation is wrong, never
// to make a failing test pass.
const pinnedDigest = "smithmark-bundle-v1:REPLACE_AT_GREEN_STEP"

func TestDigestMatchesPinnedVector(t *testing.T) {
	got, err := Digest(sampleFiles())
	if err != nil {
		t.Fatal(err)
	}
	if got != pinnedDigest {
		t.Errorf("digest drifted from the normative vector\n got: %s\nwant: %s", got, pinnedDigest)
	}
}

func TestDigestIsOrderIndependent(t *testing.T) {
	files := sampleFiles()
	reversed := []File{files[2], files[0], files[1]}
	a, _ := Digest(files)
	b, _ := Digest(reversed)
	if a != b {
		t.Error("input order changed the digest; entries must be sorted bytewise by path")
	}
}

func TestDigestIsModeSensitive(t *testing.T) {
	files := sampleFiles()
	a, _ := Digest(files)
	files[0].Mode = ModeRegular
	b, _ := Digest(files)
	if a == b {
		t.Error("mode change did not change the digest")
	}
}

func TestDigestRejectsBadInput(t *testing.T) {
	h := strings.Repeat("aa", 32)
	cases := []struct {
		name  string
		files []File
	}{
		{"empty set", nil},
		{"backslash path", []File{{Path: `scripts\x.py`, Mode: ModeRegular, SHA256: h}}},
		{"absolute path", []File{{Path: "/etc/x", Mode: ModeRegular, SHA256: h}}},
		{"dotdot segment", []File{{Path: "a/../b", Mode: ModeRegular, SHA256: h}}},
		{"duplicate path", []File{{Path: "a", Mode: ModeRegular, SHA256: h}, {Path: "a", Mode: ModeExecutable, SHA256: h}}},
		{"bad mode", []File{{Path: "a", Mode: "setuid", SHA256: h}}},
		{"short hash", []File{{Path: "a", Mode: ModeRegular, SHA256: "abcd"}}},
		{"uppercase hash", []File{{Path: "a", Mode: ModeRegular, SHA256: strings.ToUpper(h)}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Digest(tc.files); err == nil {
				t.Error("expected error, got none")
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify RED** — `go test ./pkg/core/bundle/` fails to compile.

- [ ] **Step 3: Implement**

`bundle.go`: validate every entry (rules exactly the failing cases above), copy and sort with `sort.Slice` comparing `Path` with `<` (Go string comparison is bytewise, satisfying the spec's "sort entries bytewise by path"), reject adjacent duplicates after sorting, `json.Marshal` the sorted `[]File`, canonicalize with `jsoncanonicalizer.Transform`, `sha256.Sum256`, return `Prefix + hex.EncodeToString(...)`. Errors wrap codes from `pkg/core/codes`: `BundleEmpty`, `BundlePathInvalid`, `BundleDuplicatePath`, `BundleModeInvalid`, `BundleDigestInvalid`.

- [ ] **Step 4: Pin the vector**

Run the test once, copy the observed digest into `pinnedDigest`, rerun.

Run: `go test ./pkg/core/bundle/ -v`
Expected: PASS all four tests. The pinned value is now normative; CI's three OS matrix (Task 1.1) proves cross OS byte identity on every push (spec §4 and §9 determinism requirement).

- [ ] **Step 5: Commit**

```bash
git add pkg/core/bundle/
git commit -m "Add canonical skill bundle digest with pinned normative vector"
```

### Task 1.5: Code registry and `docs/codes.md`

Implements spec §3 ("codes are API; document and never repurpose").

**Files:**
- Create: `pkg/core/codes/codes.go`, `docs/codes.md`
- Test: `pkg/core/codes/codes_test.go`

**Interfaces:**
- Produces: every machine readable code in the system as a Go constant, plus `func All() []string`. Later phases add constants here and rows to `docs/codes.md`; the sync test forces both or neither.

- [ ] **Step 1: Write the failing sync test**

```go
package codes

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEveryCodeIsDocumented(t *testing.T) {
	_, self, _, _ := runtime.Caller(0)
	doc, err := os.ReadFile(filepath.Join(filepath.Dir(self), "..", "..", "..", "docs", "codes.md"))
	if err != nil {
		t.Fatalf("reading docs/codes.md: %v", err)
	}
	for _, c := range All() {
		if !strings.Contains(string(doc), "`"+c+"`") {
			t.Errorf("code %s is not documented in docs/codes.md", c)
		}
	}
	if len(All()) == 0 {
		t.Fatal("code registry is empty")
	}
}

func TestCodesAreUniqueAndShaped(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range All() {
		if seen[c] {
			t.Errorf("duplicate code %s", c)
		}
		seen[c] = true
		for _, r := range c {
			if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
				t.Errorf("code %s is not SCREAMING_SNAKE", c)
			}
		}
	}
}
```

- [ ] **Step 2: Run to verify RED** — `go test ./pkg/core/codes/` fails to compile.

- [ ] **Step 3: Implement the registry**

`codes.go` with a constant per code and `All()` returning every constant. Initial population (later tasks append; the constant name is the Go side, the string is the API):

Manifest validation (Task 1.3): `MANIFEST_SCHEMA_VERSION_UNSUPPORTED`, `MANIFEST_KIND_SURFACE_MISMATCH`, `MANIFEST_ENUM_INVALID`, `MANIFEST_VERSION_REQUIRED`, `MANIFEST_CAPABILITIES_KEY_MISSING`, `EGRESS_HOST_INVALID`, `EGRESS_PORT_INVALID`, `FS_ACCESS_INVALID`, `FS_PATH_INVALID`, `ENV_NAME_INVALID`, `SECRET_FORMAT_INVALID`, `TRANSPORT_INVALID`, `MODE_INVALID`, `DIGEST_INVALID`.

Bundle (Task 1.4): `BUNDLE_EMPTY`, `BUNDLE_PATH_INVALID`, `BUNDLE_DUPLICATE_PATH`, `BUNDLE_MODE_INVALID`, `BUNDLE_DIGEST_INVALID`, `BUNDLE_SYMLINK_REJECTED`.

Verification checks (Phase 3 consumes; reserve now): `SIGNATURE_VALID`, `REKOR_INCLUSION_VALID`, `SUBJECT_DIGEST_MATCH`, `MANIFEST_SCHEMA_VALID`, `PROVENANCE_PRESENT`, `NPM_PROVENANCE_VERIFIED`, `ATTESTATION_MISSING`, `DEPENDENCY_SBOM_MISSING`, `PREDICATE_VERSION_UNSUPPORTED`, `HOSTED_ENDPOINT_UNSUPPORTED`.

Lint findings (Phase 4): `UNDECLARED_NETWORK_EGRESS`, `UNDECLARED_FILESYSTEM`, `UNDECLARED_EXEC`, `UNDECLARED_ENV`, `TOOL_LISTING_MISMATCH`.

Operational (Phases 2 and 3): `SIGNING_UNAVAILABLE_PLATFORM`, `SBOM_FORGESEAL_MISSING`, `SBOM_FORGESEAL_VERSION_UNSUPPORTED`, `REF_UNMAPPABLE`, `ATTESTATION_BASE_UNKNOWN`.

- [ ] **Step 4: Write `docs/codes.md`**

One table with columns: code (backticked), kind (validation, check, finding, operational), meaning (one sentence), introduced (milestone). Every constant from step 3 gets a row.

- [ ] **Step 5: Run to verify GREEN** — `go test ./pkg/core/codes/` PASS. Also rerun `go test ./pkg/core/manifest/` after switching Task 1.3's literals to these constants if 1.3 predated this task.

- [ ] **Step 6: Commit**

```bash
git add pkg/core/codes/ docs/codes.md pkg/core/manifest/ pkg/core/bundle/
git commit -m "Add machine readable code registry with documentation sync test"
```

### Task 1.6: in-toto statement assembly and golden snapshots

Implements spec §2.3 and decision D6 binding rules; golden files per spec §9.

**Files:**
- Modify: `pkg/core/manifest/manifest.go` (append statement section)
- Test: `pkg/core/manifest/statement_test.go`
- Create: `pkg/core/manifest/testdata/golden/statement_mcp.json`, `statement_skill.json` (via `-update`)

**Interfaces:**
- Produces:

```go
const PredicateType = "https://in8.sh/attestation/agent-capability/v1"

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
func NewStatement(ref ArtifactRef, m *CapabilityManifest) (*Statement, error)
func (s *Statement) Canonical() ([]byte, error)
func ParseStatement(data []byte) (*Statement, error) // strict, verifies _type and predicateType
```

- [ ] **Step 1: Write the failing tests**

`statement_test.go`: build the `validManifest()` fixture plus a skill variant; assert (a) `NewStatement` rejects a ref whose kind or name disagrees with the predicate artifact block (expect error mentioning `MANIFEST_KIND_SURFACE_MISMATCH`), (b) npm subject name is `pkg:npm/better-call-claude@1.4.2` and a scoped fixture yields `pkg:npm/%40acme/tool@1.0.0`, (c) skill subject digest key is exactly `smithmark-bundle-v1`, (d) `ParseStatement` rejects unknown `_type`, unknown `predicateType`, and unknown fields, (e) `golden.Assert(t, canonicalBytes, "testdata/golden/statement_mcp.json")` and the skill twin. Fixed `GeneratedAt` of `2026-07-16T00:00:00Z` keeps goldens stable.

- [ ] **Step 2: RED** — `go test ./pkg/core/manifest/` fails: `NewStatement` undefined.

- [ ] **Step 3: Implement, then create goldens**

Implement per the interface block. Then:

Run: `go test ./pkg/core/manifest/ -run TestStatementGolden -update`
Run: `go test ./pkg/core/...`
Expected: PASS; two golden files exist and are committed.

- [ ] **Step 4: Commit**

```bash
git add pkg/core/manifest/
git commit -m "Add in-toto statement assembly with golden snapshots"
```

### Task 1.7: CHECKPOINT — Milestone M1 review

Compare shipped artifacts against spec §10 row M1 (manifest schema plus strict validation, canonical bundle digest, finding and check codes, golden tests). Open the M1 PR from the worktree branch, run the code-review skill, present the summary, and STOP for maintainer review. Batch any questions discovered during Phase 1.

---

# Phase 2 (M2): Attest

Implements: spec §5 (`smithmark attest`, `manifest init`), §2.2, §2.3, §6 (publish side), §10 row M2; decisions D2, D3, U1, U2. From here on, tasks specify exact contracts, fixtures, test matrices, and verification commands; function bodies follow TDD against those contracts, and library facing code must be checked against current upstream docs (context7 or pkg.go.dev) rather than assumed.

### Task 2.1: Declared config loader (`smithmark.yaml`)

Implements U1. **Files:** create `pkg/discover/local.go`, test `pkg/discover/local_test.go`, fixture `testdata/declared/smithmark.yaml` (a realistic declaration for a fake MCP server: one egress rule with ports and reason, one fs rule with tokens, env, secrets).

**Interfaces:**
- Produces: `func LoadDeclared(path string) (*manifest.CapabilityManifest, error)` returning a partially populated manifest (artifact block, capabilities, declared surfaces; no GeneratedAt, no Dependencies). YAML decoded with `yaml.v3` and `KnownFields(true)`; decode into dedicated yaml tagged structs then map to manifest types, never into the JSON structs directly.

**Steps:** RED with three tests (valid fixture loads and `Validate()` is clean; unknown YAML key errors; missing file returns a wrapped `os.ErrNotExist`); GREEN; commit `"Add strict smithmark.yaml loader"`.

### Task 2.2: Skill directory walker

Implements spec §4 I/O half. **Files:** create walker in `pkg/discover/local.go`, fixture skill at `testdata/skills/hello-skill/` (SKILL.md with name and version frontmatter, one executable script, one nested reference file), test in `local_test.go`.

**Interfaces:**
- Produces: `func WalkSkill(root string) ([]bundle.File, *manifest.SkillSurface, error)`. Rejects symlinks with an error wrapping `codes.BundleSymlinkRejected` (create the symlink inside the test with `os.Symlink`, skip on Windows via `t.Skip` if symlink creation fails for privilege reasons); captures the executable bit as ModeExecutable on unix and defaults ModeRegular on Windows unless the path is listed executable in `smithmark.yaml` (document this Windows rule in the walker comment; the cross OS CI matrix proves the fixture digest is identical on all three OSes because the fixture script's mode comes from git's tracked mode).

**Steps:** RED (golden digest of the fixture via `bundle.Digest(WalkSkill(...))`, symlink rejection, frontmatter extraction of name and version); GREEN; commit.

### Task 2.3: MCP tool listing extraction over stdio

Implements U2 and spec §5 attest bullet. **Files:** create `pkg/discover/mcptools.go`, test `mcptools_test.go`, fixture `testdata/fakemcp/main.go` (a tiny Go program speaking just enough JSON RPC over stdio: answers `initialize` and `tools/list` with two tools and fixed input schemas; the test launches it with `go run`).

**Interfaces:**
- Produces: `func ExtractTools(ctx context.Context, command []string) ([]manifest.ToolDecl, []string, error)` (tools plus transports observed, always `["stdio"]` here) and `func ToolsFromFile(path string) ([]manifest.ToolDecl, error)` for `--tools-from`. InputSchemaDigest is sha256 over the RFC 8785 canonicalization of each tool's inputSchema, computed by a pure helper in `pkg/core/manifest`: `func SchemaDigest(schema json.RawMessage) (DigestSet, error)` (add it there with its own unit test; canonicalization changes must never live in two places).
- Security posture (documented on the function): attest may execute the maker's own artifact; verify and lint never call this.

**Steps:** RED (extraction against the fake server yields the two tools with pinned digests; a hung server hits the context timeout; `ToolsFromFile` strict parses and rejects unknown fields); GREEN; commit.

### Task 2.4: forgeseal exec adapter

Implements D2, spec §2.2. **Files:** create `pkg/compose/forgeseal.go`, test with a fake `forgeseal` executable written by the test into `t.TempDir()` and prepended to PATH (a shell script on unix, a `.bat` on Windows, each emitting a canned minimal CycloneDX 1.5 JSON document and a fixed version string for `forgeseal version`).

**Interfaces:**
- Produces:

```go
type SBOMResult struct {
	Ref *manifest.SBOMRef // digest of the canonical bytes, format string, no locator yet
	BOM []byte            // the CycloneDX JSON as produced
}
type SBOMGenerator interface {
	Generate(ctx context.Context, projectDir string) (*SBOMResult, error)
}
func NewForgesealCLI() SBOMGenerator // finds forgeseal on PATH
```

- Missing binary returns an error wrapping `codes.SBOMForgesealMissing`; a version below the pinned minimum returns `codes.SBOMForgesealVersionUnsupported`. Output parsed strictly with cyclonedx-go before digesting; a parse failure is an error, never a silent pass through.

**Steps:** RED (happy path digest is stable; missing binary code; version gate; malformed BOM rejected); GREEN; then file the forgeseal export issue:

```bash
gh issue create --repo sns45/forgeseal \
  --title "Export a stable pkg/sbom API for downstream library use" \
  --body "smithmark (github.com/sns45/smithmark) composes forgeseal for dependency SBOMs. All generation logic currently sits under internal/, so v0.1 ships an exec adapter. Request: an exported pkg/sbom facade over internal/sbom.Generator plus lockfile detection, so downstream tools can import instead of shelling out. Context: smithmark docs/decisions.md entry D2."
```

Commit `"Add forgeseal exec adapter behind SBOMGenerator interface"`.

### Task 2.5: Signing interface with native and stub implementations

Implements spec §2.1 build tag rule. **Files:** create `pkg/compose/sign.go` (interface plus DSSE envelope type aliases from sigstore-go), `sign_native.go` (`//go:build native` is wrong; use `//go:build !wasip1` so native is the default and wasip1 gets the stub), `sign_stub.go` (`//go:build wasip1`), tests `sign_test.go` (interface contract against a fake) and `sign_native_test.go` (key based signing round trip with an ephemeral ECDSA key, no network).

**Interfaces:**
- Produces:

```go
type Signer interface {
	// SignStatement wraps canonical statement bytes in a DSSE envelope and
	// signs it. Keyless (Fulcio OIDC) and key based modes per options.
	SignStatement(ctx context.Context, stmt []byte, opts SignOptions) (*SignedBundle, error)
}
type SignOptions struct {
	KeyPath string // key based mode when set; keyless otherwise
	// keyless parameters (issuer, identity token source) added here, shaped
	// after sigstore-go's current keyless API at implementation time
}
type SignedBundle struct { Bundle []byte } // sigstore bundle JSON
```

- The wasip1 stub's `SignStatement` always returns an error wrapping `codes.SigningUnavailablePlatform`. A test compiled only under wasip1 is not runnable in CI; instead CI adds a build check `GOOS=wasip1 GOARCH=wasm go build ./pkg/...` proving the stub compiles and sigstore-go is not in the wasip1 dependency graph (this is the assayward carried constraint, spec §2.1).
- Keyless signing cannot run in offline tests; it is exercised in the release workflow (Phase 6) and a documented manual command. Key based signing is the CI covered path.

**Steps:** RED (fake based contract test: envelope payloadType is `application/vnd.in-toto+json`, payload round trips to the input statement; native test: sign with ephemeral key then verify with its public key using sigstore-go verification primitives); GREEN; add the wasip1 build check to ci.yml; commit.

### Task 2.6: Deterministic OCI ref mapping

Implements D3 (normative; the registry RFC quotes it). **Files:** create `pkg/discover/refmap.go` (pure; no I/O imports), test `refmap_test.go`.

**Interfaces:**
- Produces:

```go
// AttestationRef returns (repository, tag) under base for an artifact, per
// docs/decisions.md D3. Pure and total: errors only REF_UNMAPPABLE and
// ATTESTATION_BASE_UNKNOWN.
func AttestationRef(base string, ref manifest.ArtifactRef) (repo string, tag string, err error)
```

- Table driven test rows (exact expectations): unscoped npm `better-call-claude` + sha512 digest gives `<base>/npm/better-call-claude` and tag `sha512-<first 64 hex>.att`; scoped `@acme/Tool` lowercases to `<base>/npm/acme/tool`; pypi `Foo._-Bar` normalizes per PEP 503 to `foo-bar`; skill `hello-skill` with digest key `smithmark-bundle-v1` gives tag `bundle-v1-<64 hex>.att`; empty base errors `ATTESTATION_BASE_UNKNOWN`; a name that cannot satisfy the OCI path grammar after normalization errors `REF_UNMAPPABLE`; oci source returns an error directing callers to the referrers path (native referrers need no mapping).

**Steps:** RED; GREEN; commit `"Add normative deterministic attestation ref mapping"`.

### Task 2.7: OCI push and attach

Implements spec §6 publish side. **Files:** create `pkg/compose/push.go`, test `push_test.go` using oras-go's in memory `content.Store` / `memory.New()` target (no network; check oras-go v2 current API via context7 before writing).

**Interfaces:**
- Produces: `func PushAttestation(ctx context.Context, target oras.Target, repo, tag string, bundle *SignedBundle) (digest string, err error)` pushing the sigstore bundle as an OCI artifact with mediaType `application/vnd.dev.sigstore.bundle.v0.3+json` (confirm the current sigstore bundle media type constant from sigstore-go at implementation time and use their exported constant, never a string literal), plus `func AttachReferrer(...)` for the OCI native path using oras-go's referrers support.

**Steps:** RED (push to memory target then fetch back byte identical; tag shape matches Task 2.6 output); GREEN; commit.

### Task 2.8: `smithmark attest` and `smithmark manifest init` commands

Implements spec §5. **Files:** create `cmd/smithmark/main.go`, `cmd/smithmark/attest.go`, `cmd/smithmark/manifest.go`, golden CLI tests in `cmd/smithmark/attest_test.go` invoking the cobra command in process with fakes injected (SBOMGenerator, Signer, oras target are constructor injected; commands read them from a small `deps` struct so tests swap fakes without exec).

**Interfaces:**
- Produces: `smithmark attest <path|ref>` flag surface: `--key`, `--skip-sbom`, `--tools-from`, `--attestation-base`, `--bundle` (skill path mode), `--output` (write bundle to file instead of push), `--dry-run` (print canonical statement, sign nothing). `smithmark manifest init` flag driven scaffold writing `smithmark.yaml` (flags for kind, name, egress, fs, exec, env, secrets; interactive prompts only when a TTY and no flags).
- Pipeline (attest): load declared config (2.1) → walk or resolve artifact (2.2 / npm tarball in cwd) → extract tools (2.3) unless `--tools-from` → forgeseal SBOM (2.4) unless `--skip-sbom` → assemble manifest + statement (1.6) with injected clock → validate → sign (2.5) → map ref (2.6) → push (2.7). Every failure path exits 3 with the machine readable code on stderr as JSON (`{"code": "...", "detail": "..."}`).

**Steps:** RED (golden test: `--dry-run` on the fixture skill produces the golden canonical statement; `--skip-sbom` manifest has no dependencies block; missing forgeseal exits 3 with `SBOM_FORGESEAL_MISSING` on stderr); GREEN; commit.

### Task 2.9: Release engineering scaffold

Per the family convention (release engineering lands with the CLI). **Files:** create `.goreleaser.yaml` (builds darwin/linux/windows amd64+arm64, Homebrew tap `sns45/homebrew-tap`, nfpm deb and rpm, Docker image), `.github/workflows/release.yml` (tag triggered, keyless Sigstore ready but signing steps added in Phase 6), `Dockerfile`. **Verification:** `goreleaser check` passes; `goreleaser release --snapshot --clean` builds all targets locally. Commit.

### Task 2.10: CHECKPOINT — Milestone M2 review

Compare against spec §10 row M2 (manifest generation, MCP tool listing extraction, forgeseal composition, Sigstore signing keyless plus key, OCI attach). One item is deliberately deferred with maintainer visibility: keyless signing is exercised only in Phase 6's release workflow because it needs live OIDC. Open the M2 PR, run the code-review skill, STOP.

# Phase 3 (M3): Verify + Discover

Implements: spec §5 (`smithmark verify`, `registry check`), §6 discovery, §7 assayward contract, §10 row M3; decisions D3 (resolution order), D4, D5, U3, U5.

### Task 3.1: Signed fixture generation kit

Everything in this phase needs realistic signed inputs with no network in CI. **Files:** create `testdata/gen/gen.go` (a `go run` tool, mirroring assayward's `testdata/gen` pattern) plus committed outputs under `testdata/signature/`: an ephemeral test keypair, and for the fixture skill and a fixture npm package: a valid signed bundle, a tampered signature variant, a subject digest mismatch variant, a schema invalid predicate variant, an unknown predicate version variant. **Verification:** regenerating is deterministic given the committed key and fixed timestamps; a README in `testdata/` documents the regeneration command `go run ./testdata/gen`. Commit fixtures.

### Task 3.2: Discovery layer

Implements spec §6 and D3 resolution order. **Files:** create `pkg/discover/npm.go`, `pkg/discover/oci.go`, tests with committed fixtures (`testdata/npm/packument.json` snapshot of a real packument, trimmed; oras memory store for referrers).

**Interfaces:**
- Produces:

```go
type Discovered struct {
	Ref          manifest.ArtifactRef // resolved, digest populated
	Bundles      [][]byte             // candidate sigstore bundles found
	NPMProvenance []byte              // npm's own provenance bundle when present
	Notes        []string             // human notes, e.g. which base resolved
}
// Resolve turns a CLI argument (npm name@version, oci ref, local path,
// --bundle path) into a Discovered, applying the D3 base resolution order:
// flag, then SMITHMARK_ATTESTATION_BASE, then package.json smithmark key,
// else ATTESTATION_BASE_UNKNOWN when discovery needs a base.
func Resolve(ctx context.Context, arg string, opts ResolveOptions) (*Discovered, error)
```

- npm tarball digest: read `dist.integrity` sha512 base64 from the packument and convert to hex (U6); a unit test pins one known conversion.
- HTTP clients are injected (`http.RoundTripper`) so tests serve fixtures without sockets.

**Steps:** RED (packument resolution and integrity conversion; referrers discovery from memory store; base resolution order table including the package.json fallback; `--bundle` explicit path wins over everything); GREEN; commit.

### Task 3.3: Core verification stages (`pkg/core/verify`)

Implements spec §3 rules, §5 verify semantics, U3. **Files:** create `pkg/core/verify/verify.go`, test `verify_test.go` consuming Task 3.1 fixtures (read by the test, passed in as bytes; core stays pure). Also create `pkg/core/lint/lint.go` containing only the `Finding` type (`Code`, `Severity`, `Detail`, `Location`, exactly as Task 4.1 shows) so the report type compiles; the heuristics arrive in Phase 4.

**Interfaces:**
- Produces:

```go
type CheckResult struct {
	Code   string `json:"code"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}
type VerificationReport struct {
	Subject    manifest.ArtifactRef `json:"subject"`
	Checks     []CheckResult        `json:"checks"`   // sorted by Code
	Findings   []lint.Finding       `json:"findings"` // populated in Phase 4; empty slice until then
	Evidence   json.RawMessage      `json:"evidence"`
	VerifiedAt time.Time            `json:"verifiedAt"`
}
type Input struct {
	Ref           manifest.ArtifactRef
	Bundles       [][]byte
	NPMProvenance []byte
	TrustRoots    []byte    // sigstore TUF root, injected
	Now           time.Time // injected clock
}
// SignatureVerifier abstracts sigstore-go so core stays buildable everywhere;
// pkg/compose provides the native implementation behind the build tag and a
// fail closed stub elsewhere (spec 2.1).
type SignatureVerifier interface {
	VerifyBundle(bundle, trustRoots []byte, now time.Time) (statementBytes []byte, rekorIncluded bool, err error)
}
func Run(in Input, sv SignatureVerifier) (*VerificationReport, error)
```

- Stage order inside `Run`: presence (`ATTESTATION_MISSING` fails the report when no bundle, U3) → signature (`SIGNATURE_VALID`, `REKOR_INCLUSION_VALID`) → statement strict parse and predicate version (`PREDICATE_VERSION_UNSUPPORTED`) → subject digest match against `in.Ref.Digest` (`SUBJECT_DIGEST_MATCH`) → manifest semantic validation (`MANIFEST_SCHEMA_VALID`) → npm provenance presence and verification when applicable (`PROVENANCE_PRESENT`, `NPM_PROVENANCE_VERIFIED`) → dependency SBOM reference presence (`DEPENDENCY_SBOM_MISSING` informational). Check outcomes are set only here; nothing downstream re-reads envelopes as trusted (spec §3 rule; the purity guard plus a targeted test enforce that `Verified` style fields have no setters outside this package).
- Table driven test matrix (spec §9 list, one row each): valid attestation passes all checks; tampered signature fails `SIGNATURE_VALID` and stops trusting payload derived checks; subject digest mismatch; schema invalid manifest; unknown predicate version; missing npm provenance (check present, failed, report still completes); expired or revoked cert path (fixture with a short lived cert verified at an injected `Now` after expiry).
- Determinism: two `Run` calls with identical inputs produce byte identical marshaled reports (golden snapshot `testdata/golden/report_valid.json`).

**Steps:** RED (matrix plus golden); GREEN; commit.

### Task 3.4: Evidence block and the assayward contract test

Implements spec §7, U5. **Files:** append to `pkg/core/verify/verify.go` (`func (r *VerificationReport) EvidenceBlock() (json.RawMessage, error)` emitting the assayward compatible structure: subject as name plus digest, attestations array with predicateType, envelope, verified, signatureNote, fetchedAt from the injected clock), contract test `pkg/core/verify/contract_test.go`.

- The contract test adds `github.com/sns45/assayward` to go.mod pinned to the current release tag, unmarshals our Evidence block into `assayward/pkg/core.Evidence` with `DisallowUnknownFields`, and asserts round trip equality. A comment names the pinned version and the rule: bumps are deliberate and loud (U5). Until assayward ships ArtifactRef, the block maps our subject into the existing `ImageRef{Name, Digest}` shape with the kind carried in `SignatureNote` prose; the M5 issue (Task 5.4) removes this shim.

**Steps:** RED; GREEN; commit `"Emit assayward compatible Evidence with pinned contract test"`.

### Task 3.5: `smithmark verify` command

Implements spec §5 and D4. **Files:** create `cmd/smithmark/verify.go`, golden tests as in 2.8 (fakes injected; fixture bundles from 3.1).

- Flag surface: `--strict`, `--bundle`, `--attestation-base`, `--trust-root`, `--certificate-identity`, `--certificate-oidc-issuer` (cosign convention), `--output json|summary` (default summary; json is the golden tested machine surface).
- Exit codes exactly per D4: golden tests assert 0 on the valid fixture, 1 on tampered and on missing attestation, 2 reserved until Phase 4 wires lint (a placeholder test asserts `--strict` with zero findings still exits 0), 3 on unreachable discovery with the injected transport failing.

**Steps:** RED; GREEN; commit.

### Task 3.6: `smithmark registry check`

Implements spec §5 and D5. **Files:** create `pkg/discover/registry.go`, `cmd/smithmark/registry.go`, fixtures `testdata/registry/entry_*.json` (real MCP Registry API response snapshots: one npm backed entry, one remote only entry).

- Produces: `smithmark registry check <server-name>` resolving the entry via the injected HTTP client, then running the same verify pipeline on the artifact the entry points at, plus registry specific checks: attestation reference field present (fails today; that is the RFC gap being demonstrated) and `HOSTED_ENDPOINT_UNSUPPORTED` informational on remote only entries instead of an error (D5).

**Steps:** RED (both fixtures; remote only exits 0 with the informational check in the report); GREEN; commit.

### Task 3.7: CHECKPOINT — Milestone M3 review

Compare against spec §10 row M3 (dual path discovery, signature/Rekor/digest verification, npm provenance interop, VerificationReport plus Evidence block). Open the M3 PR, code-review skill, STOP.

---

# Phase 4 (M4): Capability Lint

Implements: spec §5 (`smithmark lint`), §10 row M4, §9 lint testing rules. Lint is heuristic and advisory; v0.1 promises detection of obvious undeclared capabilities, not proof of absence (spec §1.3). That posture is encoded in tests, not just prose.

### Task 4.1: JS and TS detection heuristics

**Files:** extend `pkg/core/lint/lint.go` (created with the `Finding` type in Task 3.3), test `lint_test.go`, fixtures `testdata/lint/js/` (small source files, one per detection class).

**Interfaces:**
- Produces:

```go
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // low | medium | high
	Detail   string `json:"detail"`
	Location string `json:"location"` // file:line
}
type Source struct { Path string; Content []byte } // pre read; core stays pure
// DetectJS scans JS and TS sources line by line with anchored patterns.
func DetectJS(files []Source) []Detection
type Detection struct {
	Class    string // network | filesystem | exec | env
	Symbol   string // e.g. fetch, child_process
	Location string
}
```

- Detection table (spec §9): network `fetch(`, `require("http")` / `require("https")` / `require("net")` and the import forms, `axios`, `undici`; filesystem `require("fs")` / `from "fs"` / `fs/promises`; exec `child_process`, `execa`, `Bun.spawn`; env `process.env`. Line comments and string literals produce known false positives; that is accepted and documented (heuristic, advisory).
- Honesty tests (spec §9): `import(dynamicVar)` and `eval("require...")` fixtures asserted NOT detected, with test names `TestKnownFalseNegativeDynamicImport` and `TestKnownFalseNegativeEval`.

**Steps:** RED (per class table over fixtures, false negative assertions); GREEN; commit.

### Task 4.2: Python detection heuristics

**Files:** extend `lint.go` with `DetectPython`, fixtures `testdata/lint/py/`. Table: network `requests`, `httpx`, `urllib`, `socket`; filesystem `open(`, `pathlib`, `shutil`; exec `subprocess`, `os.system`, `os.exec`; env `os.environ`, `os.getenv`. Same honesty tests for `importlib.import_module(var)` and `eval`. Same step shape as 4.1; commit.

### Task 4.3: Declared versus detected gap engine

**Files:** extend `lint.go`. **Interfaces:** `func Gaps(declared manifest.CapabilitySet, detections []Detection) []Finding` mapping each detection class with zero corresponding declarations to its finding code: `UNDECLARED_NETWORK_EGRESS`, `UNDECLARED_FILESYSTEM`, `UNDECLARED_EXEC`, `UNDECLARED_ENV` (env is name aware: `process.env.FOO` with `FOO` undeclared and no matching prefix pattern fires; bare `process.env` without a member access fires a low severity generic). Declared `"*"` escape hatches suppress the class. A declared but never detected capability is NOT a finding (over declaration is policy's business, not lint's). Matrix test: declared×detected grid per class. RED, GREEN, commit.

### Task 4.4: Misdeclared fixture, `smithmark lint` command, verify wiring

**Files:** create `testdata/misdeclared/` (a small fake MCP server whose `smithmark.yaml` declares zero egress while `src/index.ts` calls `fetch("https://exfil.example.com")`; spec §9 requires this fixture), `cmd/smithmark/lint.go`, golden lint report; modify `cmd/smithmark/verify.go` to run lint when sources are locally available and to make `--strict` exit 2 exactly when `UNDECLARED_*` findings exist (D4).

**Steps:** RED (golden lint JSON on the misdeclared fixture shows `UNDECLARED_NETWORK_EGRESS` with file:line; `verify --strict` against the misdeclared fixture exits 2 while plain verify exits 0 given a valid signature; `TOOL_LISTING_MISMATCH` fires when declared tools disagree with extracted tools); GREEN; commit.

### Task 4.5: CHECKPOINT — Milestone M4 review

Compare against spec §10 row M4. Open the M4 PR, code-review skill, STOP.

# Phase 5 (M5): Surfaces

Implements: spec §7, §8 (`action/`, `policies/`, `surfaces/`), §10 row M5.

### Task 5.1: GitHub Action

**Files:** create `action/action.yml` (composite action: installs the pinned smithmark release, runs `smithmark verify` with inputs `ref`, `strict`, `attestation-base`, `certificate-identity`, `certificate-oidc-issuer`), `action/README.md`. **Verification:** `actionlint` clean; a workflow in this repo exercises the action against the signed fixture in dry form (composite steps run with the locally built binary via an `install-from` escape input, keeping CI offline). Commit.

### Task 5.2: Claude Code hook shim

Implements spec §7 third bullet ("one shim, well documented"). **Files:** create `surfaces/claude-code-hook/verify-mcp.sh` plus `README.md` and an example `settings.json` fragment. The hook runs on MCP server first use (document the exact hook event and configuration per current Claude Code hooks docs, verified at implementation time), invokes `smithmark verify --strict --output json` against the configured server's package, and blocks with an explainable deny: it prints the failed checks and findings with their codes and exits nonzero so the runtime refuses the server. **Verification:** a scripted test (`surfaces/claude-code-hook/test.sh`) runs the hook against the misdeclared fixture and asserts block plus the `UNDECLARED_NETWORK_EGRESS` code in output, and against the valid fixture asserting allow. Commit.

### Task 5.3: Example assayward policies

Implements spec §7 second bullet. **Files:** create `policies/agent-mcp-baseline.yaml` (the spec's worked example: publisher X, SLSA L2 plus, no undeclared network egress, no affected criticals), `policies/skill-strict.yaml`, `policies/README.md` explaining that smithmark never decides (spec §1.3): these run in assayward. **Verification:** validate each against the pinned assayward version (`go run github.com/sns45/assayward/cmd/assayward@<pinned> policy validate policies/*.yaml` or the equivalent current command, checked at implementation time); record the command in the README. Commit.

### Task 5.4: File the assayward work item

Implements spec §7 first bullet and U5, via direct `gh` execution:

```bash
gh issue create --repo sns45/assayward \
  --title "Widen ImageRef to a kind tagged ArtifactRef and version the Evidence schema" \
  --body "smithmark emits Evidence for agent artifacts (MCP servers, skills). Two requests for vNext: (1) widen ImageRef to ArtifactRef{Kind, Name, Version, Digest, Source} so non image subjects are first class; (2) add an explicit schemaVersion field to Evidence so cross repo consumers can pin and detect drift. Context: smithmark requirements.md section 7 and docs/decisions.md U5. smithmark currently pins the assayward module version in its contract test and shims kind into SignatureNote; both are removed when this lands."
```

**Verification:** issue URL recorded in `docs/decisions.md` under U5. Commit the docs update.

### Task 5.5: CHECKPOINT — Milestone M5 review

Compare against spec §10 row M5 (GitHub Action, Claude Code hook shim, example policies, assayward work item filed). Open the M5 PR, code-review skill, STOP.

---

# Phase 6 (M6): Dogfood + Proposals

Implements: spec §1.4, §11, §10 row M6. M6 is not done until both proposals are submission ready, smithmark's own releases attest themselves and are gated by assayward, and the hook demo blocks a misdeclared server (maintainer instruction).

### Task 6.1: First party fixtures — ASK FIRST

`better-call-claude` and `dear-claude` exist at `~/dev/better-call-claude` and `~/dev/dear-claude` (both have `server.json` registry manifests). **Ask the maintainer which snapshots to commit before copying anything** (per their standing instruction to ask rather than guess at M6). Then: commit trimmed snapshots to `testdata/servers/`, author real `smithmark.yaml` declarations for each (this is the moment the D1 taxonomy meets reality; capture friction in `docs/decisions.md`), attest both with real Sigstore keyless signatures, and push attestations to the maintainer's chosen `--attestation-base`. Also add one Anthropic public skill snapshot (spec §9) under `testdata/skills/` and attest it. **Verification:** `smithmark verify` passes for all three with live discovery outside CI, and the committed fixture forms verify offline in CI.

### Task 6.2: Self attestation gated by assayward

Extend `.github/workflows/release.yml`: forgeseal SBOM of smithmark itself, SLSA provenance, smithmark's own `smithmark.yaml` and self attestation (the CLI attests itself, spec §11), all signed keyless in CI via OIDC, then an assayward gate step evaluating the release against a dogfood policy (mirror forgeseal's `assayward-dogfood-policy.yaml` pattern). **Verification:** a tagged prerelease run completes with the gate passing; the run URL is recorded in `docs/decisions.md`.

### Task 6.3: TC54 CycloneDX proposal

**Files:** create `proposals/cyclonedx-agent-capability/PROPOSAL.md`: the `in8:agent:capability:*` property taxonomy (spec §2.3) in lockstep with the predicate schema, mapping every predicate field to a property, with worked examples generated from the real Task 6.1 manifests, positioning from the Phase 0 sweep, and the OWASP Agentic Top 10 mapping (spec §12). **Review like code:** dispatch the code-review skill on the prose; then a spec compliance pass against §1.4's "submission ready" bar (correct TC54 submission format, checked against current CycloneDX contribution docs at implementation time).

### Task 6.4: MCP Registry provenance RFC

**Files:** create `proposals/mcp-registry-provenance/RFC.md`: attestation reference fields on registry entries, verify on publish, the D3 deterministic ref mapping quoted normatively as the interim scheme it replaces, `registry check` as the working demonstration, gap evidence from the Phase 0 registry notes. Same two stage review as 6.3.

### Task 6.5: Hook demo and launch collateral

Record the spec §11 demo: the Claude Code hook refusing the misdeclared server with the explainable deny, and accepting `better-call-claude` with its real signed manifest. Capture the transcript to `docs/demo.md`. Write the README (positioning language from Phase 0; composition story with npm provenance per spec §12).

### Task 6.6: CHECKPOINT — Milestone M6 / v0.1 review

Compare against spec §10 row M6 and the maintainer's M6 exit criteria. Open the M6 PR, code-review skill, STOP. v0.1 tag decision (and the naming gate: USPTO and tap sweeps, spec naming block) belongs to the maintainer.

---

# Plan Self Review Notes

- **Spec coverage:** §1 positioning (Phase 0, 6.5); §2 architecture and constraints (1.1, 2.5, global constraints); §3 model (1.2, 1.3, 1.5); §4 bundle digest (1.4, 2.2); §5 commands (2.8, 3.5, 3.6, 4.4, 2.8 manifest init); §6 storage and discovery (2.6, 2.7, 3.2); §7 assayward (3.4, 5.2, 5.3, 5.4); §8 layout (file structure map); §9 testing strategy (fixtures 3.1/4.4/6.1, goldens 1.1/1.6, determinism 1.4 plus CI matrix, verification matrix 3.3, lint honesty 4.1/4.2, contract 3.4); §10 milestones (phase per row); §11 launch (6.1, 6.2, 6.5); §12 targets (6.3, 6.4, 6.5); §13 resolved in docs/decisions.md.
- **M7 (TS verify library)** is post v0.1 by spec §10 and deliberately absent.
- **Known deferrals, made visible rather than silent:** keyless signing exercised only in Phase 6 CI (needs live OIDC); exit code 2 wiring completes in Phase 4; the ImageRef shim in 3.4 is removed only when the assayward issue lands.
- **Type consistency spot checks:** `manifest.DigestSet` used by bundle subjects, refmap, and verify; `bundle.File` produced by 2.2 and consumed by 1.4's `Digest`; `SignedBundle` produced by 2.5, consumed by 2.7 and 3.1; `Finding` produced by lint, embedded in `VerificationReport` (3.3 declares the field, 4.4 populates it).




