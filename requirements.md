# smithmark — Requirements & Architecture Specification

> **Working name:** `smithmark` (the smith's mark: the maker's stamp struck on a forged tool)
> **Module path:** `github.com/sns45/smithmark`
> **One-line:** Provenance and capability attestation for the agent tool supply chain — signed, verifiable maker's marks for MCP servers and skills.

> **Naming status:** Cleared npm, crates.io, PyPI, Homebrew core, and GitHub (2026-07 sweep; 5 ambient GitHub matches, none software claimants). **Remaining manual gates before first public commit:** USPTO (Smithmark Publishers — defunct book imprint, likely Class 16 vs. our 9/42, verify no live registration), third-party Homebrew taps, domain if wanted. No logic depends on the name. Fallbacks in priority order: `touchmark`, `provenmark`, `tangmark`.

> **Whitespace status:** Sweep completed 2026-07-16 (M0; evidence and verdict in `docs/research/whitespace-sweep.md`, 14 swept items). The original blanket claim was falsified by named prior art (Enclawed for skills; `studiomeyer-io/mcp-server-attestation` and ETDI for MCP servers); §1.2 below now carries the narrowed composition claim adopted at the M0 gate. Watch items on record: see the canonical list with resolution conditions in `docs/research/whitespace-sweep.md` section 4 (Enclawed's trajectory; Ken Huang's skill signing essay before M6; the contested TC54 venue).

---

## 1. Purpose & Position in the Portfolio

smithmark is the fourth tool in the trust-as-code family, and the bridge between its two hemispheres — the zero-trust supply chain trilogy and the agentic tooling line:

| Tool | Question | Role |
|------|----------|------|
| **forgeseal** | *What* is running? | Attestation producer (containers, packages) |
| **svidmint** | *Who* is running it? | Identity issuer |
| **assayward** | *Whether* to let it run | Policy gate (consumer) |
| **smithmark** | *Who made the agent's tools, and what can they do?* | Attestation producer for agent artifacts |

Agent tools — MCP servers and SKILL.md bundles — are installed today the way containers were installed in 2015: pulled by name, trusted by reputation. An MCP server can place phone calls, read email, and push commits; a skill is arbitrary instructions plus scripts loaded into a privileged context. Nothing in the ecosystem attests who built these artifacts, what they are capable of, or whether what they declare matches what their code can do.

smithmark produces the missing evidence. assayward consumes it.

### 1.1 What smithmark is
A generator, signer, publisher, and verifier of attestations for agent artifacts:
1. **Capability manifests** — a signed, schema-validated declaration of what an MCP server or skill exposes and requires (tools, network egress, filesystem, exec, env, secrets).
2. **Build provenance** — SLSA-style provenance for skill bundles and MCP packages, composing (not duplicating) npm provenance and Sigstore.
3. **Capability lint** — heuristic static detection of *undeclared* capabilities: the gap between what the manifest claims and what the code appears able to do.
4. **Verification** — `smithmark verify` resolves an artifact, discovers its attestations, verifies signatures and subject digests, and emits a machine-readable report consumable by assayward as policy evidence.

### 1.2 The novelty claim (narrow, falsifiable — per EB-1A discipline)
> smithmark is the first attestation framework to cover both MCP servers and skills with capability declarations issued as portable, signed attestations (in-toto DSSE) for an external policy engine to consume: it composes npm provenance, Sigstore, SLSA, and CycloneDX rather than replacing them or minting a bespoke trust root, and it closes the loop from publication (maker's mark) to admission (assayward policy).

Enclawed signs skill manifests for its own runtime; `studiomeyer-io/mcp-server-attestation` signs tool and spawn allowlists for MCP servers under trust on first use; ETDI binds OAuth scoped tool definitions to a client side policy check. None covers both artifact kinds, none composes the existing supply chain standards, and none separates the maker's mark from the gate that consumes it. Scanners inspect; registries curate; the near neighbors sign in silos; smithmark composes. Demonstration with named prior art and documented failure modes: `docs/research/whitespace-sweep.md`.

### 1.3 Non-goals
- **Not a scanner or marketplace.** No vulnerability database, no curation, no hosted registry. (vs. Snyk Agent Scan, formerly Invariant Labs `mcp-scan`, and ToolHive)
- **Not a policy engine.** All allow/deny/audit decisions live in assayward. smithmark verifies and reports; it never decides.
- **Not an SBOM generator.** Dependency SBOMs come from forgeseal (which already handles 16 lockfile formats). smithmark adds the capability layer on top.
- **Not a runtime sandbox.** Enforcing capabilities at runtime (Wasm capability sandboxing) is a tracked separate direction, explicitly out of scope here.
- **Not sound static analysis.** Capability lint is heuristic and advisory. v0.1 promises detection of *obvious* undeclared capabilities, not proof of absence.

### 1.4 The standards deliverable is a first-class artifact
This project exists to manufacture the portfolio's missing upstream-standards contribution. Two proposal drafts live **in-repo** under `proposals/` and version with the reference implementation:
1. **CycloneDX agent-capability taxonomy** — property namespace / profile proposal targeted at Ecma TC54.
2. **MCP Registry provenance RFC** — attestation-reference fields on registry entries + verify-on-publish, targeted at `modelcontextprotocol/registry`.

The tool is the reference implementation of the proposals, not the other way around. Milestone M6 is not done until both drafts are submission-ready. Treat the TC54 venue as time sensitive: CycloneDX issue #895 (Agent BOM, March 2026, closed as duplicate) shows demand already circling the slot; evidence in `docs/research/whitespace-sweep.md` section 4.

---

## 2. Architecture Overview

Same layering discipline as assayward: a pure core, all I/O in adapters.

```
                    ┌──────────────────────────────────────┐
                    │        CORE  (pkg/core)               │
                    │  pure Go, deterministic, no I/O       │
                    │  - capability manifest model + schema │
                    │  - canonical skill-bundle digest      │
                    │  - verification logic                 │
                    │  - capability lint rules              │
                    └──────────────────────────────────────┘
                      │              │               │
        ┌─────────────┘        ┌─────┘         ┌─────┘
        ▼                      ▼               ▼
  pkg/discover            pkg/compose      cmd/smithmark
  (OCI referrers, npm,    (forgeseal SBOM,  (CLI: attest, verify,
   registry, local paths)  sigstore-go)      lint, registry check)
        │                                        │
        ▼                                        ▼
  surfaces/npm (TS verify lib, M7)      action/ (GitHub Action)
  surfaces/claude-code-hook             policies/ (assayward examples)
```

### 2.1 Layering rules
- `pkg/core` is **pure and deterministic**: no network, no clock except injected, no filesystem walks (bundle contents are passed in as an already-read file set). Same evidence + same time → byte-identical output. This is what makes golden-file tests and future Wasm/TS ports viable.
- **All I/O lives outside core**: fetching npm metadata, walking a skill directory, OCI referrer discovery, Rekor lookups, invoking forgeseal.
- **Signature operations are native-only.** Carried constraint from assayward: `sigstore-go` and `in-toto-golang` do not compile under `GOOS=wasip1`. All signing/verification sits behind a build-tag interface; any future Wasm build gets a **fail-closed stub with a machine-readable reason code**, never a silent skip. Do not target Wasm in v0.1.

### 2.2 Hard dependency constraints
- **Reuse, do not re-implement:** `sigstore/sigstore-go` (signing, bundle + Rekor verification), `in-toto/in-toto-golang` (DSSE envelopes, predicate framing), CycloneDX Go library (SBOM parsing), `github.com/sns45/forgeseal` (dependency SBOM generation — prefer library import; fall back to exec-adapter if the needed API isn't exported, and note the export as a forgeseal work item).
- No hand-rolled crypto, JWT, or envelope parsing anywhere.
- Strict schema parsing throughout: unknown fields are errors (consistent with assayward's policy parser).

### 2.3 Attestation format decision
**Primary envelope: in-toto DSSE with a custom predicate type** `https://in8.sh/attestation/agent-capability/v1`. Rationale: in-toto predicates are the designed extension point, verify with the same machinery as SLSA/CycloneDX predicates, and attach anywhere DSSE attaches (OCI referrers, release assets, sigstore bundles).
**Secondary mapping: CycloneDX property taxonomy** (`in8:agent:capability:*`) documented in `proposals/` — this is the TC54 pitch, kept in lockstep with the predicate schema. The predicate is the implementation; the taxonomy is the standards proposal. If TC54 engagement succeeds, the taxonomy becomes primary in v2.

---

## 3. Core Domain Model (`pkg/core`)

```go
type ArtifactKind string // "mcp-server" | "skill"

type ArtifactRef struct {
    Kind    ArtifactKind
    Name    string     // npm name, OCI ref, PyPI name, or skill name
    Version string
    Digest  Digest     // canonical digest: npm tarball sha512, OCI digest, or skill bundle digest (§4)
    Source  SourceKind // npm | oci | pypi | local | mcp-registry
}

type CapabilityManifest struct {
    SchemaVersion string
    Subject       ArtifactRef
    MCP           *MCPSurface    // non-nil for mcp-server
    Skill         *SkillSurface  // non-nil for skill
    Capabilities  CapabilitySet  // DECLARED by the maker
    Dependencies  *SBOMRef       // digest + locator of forgeseal CycloneDX SBOM
    GeneratedAt   time.Time      // injected
}

type MCPSurface struct {
    Tools     []ToolDecl   // name + input-schema digest per tool
    Resources []string
    Prompts   []string
    Transport []string     // stdio | http | sse
}

type SkillSurface struct {
    EntryDigest  Digest      // SKILL.md file digest
    Scripts      []FileRef   // executable/supporting files
    InvokesTools []string    // MCP tools / binaries the skill instructs use of
}

type CapabilitySet struct {
    NetworkEgress []EgressRule // domain patterns; empty = none declared
    Filesystem    []FSRule     // path pattern + read|write
    Exec          []ExecRule   // binary patterns
    Env           []string     // env var names read
    Secrets       []string     // credential kinds expected (e.g. "oauth:google")
}

type LintFinding struct {
    Code     string   // e.g. "UNDECLARED_NETWORK_EGRESS"
    Severity Severity
    Detail   string
    Location string   // file:line where detected
}

type VerificationReport struct {
    Subject    ArtifactRef
    Checks     []CheckResult    // SIGNATURE_VALID, SUBJECT_DIGEST_MATCH, PROVENANCE_PRESENT, MANIFEST_SCHEMA_VALID, ...
    Findings   []LintFinding    // declared-vs-detected gaps
    Evidence   json.RawMessage  // assayward-compatible evidence block (§7)
    VerifiedAt time.Time
}
```

**Rules:**
- `Verified`/check outcomes are set only by verification stages; nothing downstream reads a raw envelope as trusted (assayward's rule, carried over — add the same lint/test guard).
- Every check and finding has a **stable machine-readable code**. These codes are API; document and never repurpose them.
- All reports are deterministic given identical inputs + injected time.

---

## 4. Canonical Skill-Bundle Digest (`pkg/core/bundle`)

Skills have no registry tarball, so smithmark must define what is being signed. This algorithm is normative and its stability is a compatibility promise:

1. Collect all files under the skill root; **reject symlinks** (machine-readable error) — no resolution ambiguity in v1.
2. Normalize each entry to `(relative path with forward slashes, mode ∈ {regular, executable}, sha256 of content)`. No mtimes, no ownership, no empty directories.
3. Sort entries bytewise by path.
4. Serialize as canonical JSON (RFC 8785 style: sorted keys, no insignificant whitespace).
5. Bundle digest = sha256 of that serialization, prefixed `smithmark-bundle-v1:`.

Determinism across OSes (path separators, file modes on Windows) is a required test. The digest is the `Subject.Digest` for skill attestations and what admission-time verification recomputes.

---

## 5. Command Surface (`cmd/smithmark`)

- **`smithmark attest <path|ref>`** — generate capability manifest (from declared config + extracted MCP tool listing), invoke forgeseal for the dependency SBOM, wrap in DSSE, sign via Sigstore (keyless in CI via OIDC; key-based supported), attach/publish per §6.
- **`smithmark verify <ref>`** — resolve artifact, discover attestations (§6), verify signatures + Rekor inclusion + subject digest, validate manifest schema, run lint, emit `VerificationReport` (JSON + human summary). Exit non-zero on verification *failure*; lint findings alone do not fail (policy is assayward's job) unless `--strict`.
- **`smithmark lint <path>`** — capability lint only, no signatures: JS/TS and Python import/require scanning for network, filesystem, exec, and env access; MCP tool-listing extraction; report declared-vs-detected gaps. Heuristic, advisory, documented false-negative posture.
- **`smithmark registry check <server-name>`** — evaluate an MCP Registry entry's attestation state (the demo surface for the registry RFC).
- **`smithmark manifest init`** — interactive/flag-driven scaffold of a declared manifest for maintainers adopting smithmark.

Release engineering identical to the family: goreleaser, Homebrew tap, deb/rpm via nfpm, Docker image, pkg.go.dev.

---

## 6. Attestation Storage & Discovery (`pkg/discover`)

Where a maker's mark lives depends on how the artifact ships. Dual-path discovery, mirroring assayward's referrers-plus-explicit-paths decision:

| Artifact | Primary attestation home | Discovery |
|----------|--------------------------|-----------|
| OCI-distributed MCP server | OCI referrers on the image digest | referrers API |
| npm-distributed MCP server | OCI registry as universal attestation store (ORAS push to GHCR under a deterministic ref derived from pkg+version+tarball-digest) | well-known ref mapping; npm's own provenance verified via npm attestations in parallel |
| Skill bundle | OCI (same pattern) or explicit bundle path / release asset | ref mapping; `--bundle` flag |
| MCP Registry entry | attestation-reference field (the RFC proposal) | registry API, once field exists |

Notes:
- **Compose with npm provenance, never compete**: `smithmark verify` checks npm's Sigstore provenance where present *and* smithmark's capability attestation; the report distinguishes the two.
- The deterministic OCI ref mapping is normative — document it in the RFC draft, since it's what the registry field would eventually replace.
- All discovery is I/O-layer; core verifies whatever bundles it is handed.

---

## 7. assayward Integration (cross-repo contract)

- smithmark emits an **Evidence block** structurally compatible with assayward's `Evidence`, with one required generalization: assayward vNext must widen `ImageRef` → `ArtifactRef` (kind-tagged). This is a tracked assayward work item, not a smithmark hack — do not fork the evidence schema.
- Ship example assayward `TrustPolicy` documents in `policies/`: e.g. *"agents may only load MCP servers signed by publisher X, SLSA L2+, with no undeclared network egress and no `affected` criticals."*
- Ship one **reference runtime shim**: a Claude Code hook (`surfaces/claude-code-hook/`) that runs `smithmark verify` against a configured MCP server before first use and blocks on failure per local policy. One shim, well documented; the pattern generalizes, the repo does not chase every runtime.

---

## 8. Repository Layout

```
smithmark/
├── cmd/smithmark/            # CLI (goreleaser entrypoint)
├── pkg/core/                 # pure, deterministic
│   ├── manifest/             # capability manifest schema + strict validation
│   ├── bundle/               # canonical skill-bundle digest (§4)
│   ├── verify/               # signature/provenance/manifest verification logic
│   └── lint/                 # capability detection heuristics + finding codes
├── pkg/discover/             # OCI referrers, npm, registry, explicit paths (I/O)
├── pkg/compose/              # forgeseal SBOM adapter, sigstore signing adapter
├── surfaces/
│   ├── claude-code-hook/     # reference runtime shim
│   └── npm/                  # TS verify-only library on sigstore-js (M7, not v0.1)
├── action/                   # GitHub Marketplace action (verify in CI)
├── policies/                 # example assayward agent policies
├── proposals/
│   ├── cyclonedx-agent-capability/   # TC54 taxonomy draft
│   └── mcp-registry-provenance/      # registry RFC draft
└── testdata/                 # real artifacts, committed (§9)
```

Single comprehensive files preferred over fragmentation, per family convention.

---

## 9. Testing Strategy

- **Real fixtures, committed, never fetched in CI**: copy real MCP server packages and skill bundles into `testdata/` — including `better-call-claude` and `dear-claude` snapshots, at least one Anthropic public skill, and one deliberately misdeclared fixture (manifest claims no egress; code contains `fetch`) to exercise lint.
- **Golden-file snapshots with `-update`**: manifest generation output, canonical bundle digests, verification reports, lint findings (mirrors forgeseal's `.sbom.json` pattern).
- **Determinism tests**: same inputs + injected time → byte-identical manifest/report; bundle digest identical across Linux/macOS/Windows path semantics.
- **Table-driven verification tests**: valid attestation, tampered signature, subject-digest mismatch, schema-invalid manifest, unknown predicate version, missing npm provenance, revoked/expired cert.
- **Lint tests**: per-language tables (JS/TS `fetch`/`http`/`child_process`/`fs`; Python `requests`/`socket`/`subprocess`/`os`), declared-vs-detected matrices, documented known false negatives (dynamic import, eval) asserted as *not* detected — honesty encoded in tests.
- **Cross-repo contract test**: emitted Evidence block validates against assayward's schema (pin the schema version; break loudly on drift).

---

## 10. Milestones

| Phase | Deliverable | Est. |
|-------|-------------|------|
| **M0 — Whitespace sweep** | Done 2026-07-16: named prior art validation of §1.2 (Snyk Agent Scan, ToolHive, ETDI, registry mechanisms, npm provenance, plus nine discovered items); verdict, positioning, and watch items in `docs/research/whitespace-sweep.md`; narrowed claim adopted (decisions D7) | 1–2 days |
| **M1 — Core model** | Manifest schema + strict validation, canonical bundle digest, finding/check codes, golden tests | 3–4 days |
| **M2 — Attest** | `smithmark attest`: manifest generation, MCP tool-listing extraction, forgeseal composition, Sigstore signing (keyless + key), OCI attach | 4–5 days |
| **M3 — Verify + discover** | `smithmark verify`: dual-path discovery, signature/Rekor/digest verification, npm provenance interop, VerificationReport + Evidence block | 4–5 days |
| **M4 — Lint** | `smithmark lint`: JS/TS + Python heuristics, declared-vs-detected gap findings, misdeclared fixture | 3–4 days |
| **M5 — Surfaces** | GitHub Action, Claude Code hook shim, example assayward policies, assayward `ArtifactRef` work item filed | 2–3 days |
| **M6 — Dogfood + proposals** | better-call-claude and dear-claude signed with capability manifests; smithmark's own releases attested by itself + forgeseal and gated by assayward; TC54 + registry drafts submission-ready | 3–4 days |
| **M7 (post-v0.1) — TS verify lib** | `surfaces/npm`: verify-only TypeScript library on sigstore-js, conformance-tested against Go fixtures | scoped later |

---

## 11. Self-Demonstrating Launch

The launch artifact is the portfolio closing its own loop:

1. **better-call-claude** and **dear-claude** become the first MCP servers in the ecosystem to ship capability manifests as portable, signed attestations composing the existing supply chain standards (near neighbors sign allowlists in silos; `docs/research/whitespace-sweep.md` documents them): the maker's mark on tools that can place calls and touch Jira, which is exactly the demo that lands.
2. smithmark's own releases carry a forgeseal SBOM, SLSA provenance, a smithmark capability manifest (yes, the CLI attests itself), and are **gated by assayward** like the rest of the family.
3. The Claude Code hook demonstrates admission: an agent runtime refusing to load an unattested or misdeclared MCP server, live, with an explainable deny from assayward.

Trilogy verifies the supply chain; smithmark extends the same discipline to the tools the agents themselves wield. That is the KubeCon abstract and the EB-1A exhibit in one demo.

---

## 12. Standards & Adoption Targets (positioning)

- **Ecma TC54 / CycloneDX** — agent-capability property taxonomy (proposal in-repo).
- **MCP Registry** — provenance/attestation-reference RFC (proposal in-repo).
- **SLSA** — build provenance levels applied to agent artifacts; document what L1–L3 mean for a skill bundle.
- **OWASP Agentic Security Top 10** — map manifest fields and lint findings to specific AST10 risks (article + proposal appendix material).
- **CoSAI WS4** — engage with the capability-declaration framing.
- **EU CRA (full applicability Dec 2027)** — agents and their tools are software with digital elements; capability manifests as CRA-aligned technical documentation. Same framing that anchored forgeseal.
- **npm provenance / Sigstore** — explicit composition story: smithmark is additive evidence, not a parallel trust root.

---

## 13. Open Questions to Resolve in the Plan

1. **Capability taxonomy granularity v1** (§3): network egress as domain patterns vs. boolean-plus-note; filesystem as path patterns vs. coarse read/write flags. Recommend domain patterns + path patterns (policy needs them), with `"*"` escape hatch — confirm.
2. **forgeseal integration mode** (§2.2): library import vs. exec adapter — depends on what forgeseal currently exports; decide and, if needed, file the forgeseal API-export work item first.
3. **Attestation ref mapping for npm/skills** (§6): finalize the deterministic OCI ref scheme (it becomes normative in the registry RFC).
4. **`verify --strict` semantics** (§5): which lint findings, if any, may fail verification directly vs. everything routing through assayward policy. Recommend: pure-verify default, `--strict` fails on UNDECLARED_* only.
5. **Remote/hosted MCP servers (SSE/HTTP endpoints)**: out of scope for v0.1 (artifact-distributed only). Hosted-endpoint attestation is the phase-2 hook that ties into svidmint identity and the delegation direction — confirm deferral.
6. **Predicate schema sign-off** (§2.3): final field-level review of `agent-capability/v1` before M2, since it ships in the TC54 draft verbatim.
