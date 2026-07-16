# smithmark: Decisions (ADR lite)

Each entry records a decision resolved during the build. D1 to D6 resolve spec §13 Q1 to Q6; D7 records the M0 gate outcome; U entries cover items the spec left open. All spec references are to `requirements.md` in the repo root. All decisions below were approved by the maintainer on 2026-07-16.

## D1: Capability taxonomy granularity (spec §3, §13 Q1)

Domain patterns and path patterns, with a `"*"` escape hatch.

- **Egress**: `host` is an exact DNS name, an IP literal, a single leftmost wildcard label (`*.example.com`, TLS certificate semantics), or bare `"*"`. Optional `ports` array (absent means any port). Optional `reason` string; `manifest init` prompts for it.
- **Filesystem**: glob patterns with `**`; `access` is one of `read|write|readwrite`; paths use portability tokens `${home}`, `${tmp}`, `${cwd}` rather than absolute paths.
- **Exec**: basename patterns (`ffmpeg`, `git`) with `*` escape; optional `reason`.
- **Env**: exact names plus a trailing `*` prefix form (`AWS_*`).
- **Secrets**: namespaced `kind:provider` strings (`oauth:google`, `api-key:twilio`).

**Why**: assayward policy needs patterns, not booleans ("no egress except `api.company.com`"). The escape hatch keeps authoring honest when hosts are dynamic. Reasons stay optional so adoption is not taxed, but the scaffolder nudges for them because they make declarations reviewable (the TC54 story).

## D2: forgeseal integration mode (spec §2.2, §13 Q2)

Exec adapter in v0.1; library import later.

Evidence: forgeseal exports no packages (all logic sits under `internal/`), so a library import is impossible today. `pkg/compose` shells out to `forgeseal sbom --lockfile <path> --output <file>`, strict parses the CycloneDX JSON with cyclonedx-go, and enforces a minimum forgeseal version via `forgeseal version`. A missing binary fails `attest` with a machine readable code; an explicit `--skip-sbom` produces a manifest with no dependencies block, and verify then reports informational `DEPENDENCY_SBOM_MISSING`. The adapter sits behind an interface so the future swap to a library import is contained to one file.

**Follow up**: file a gh issue on `sns45/forgeseal` requesting an exported `pkg/sbom` facade over `internal/sbom.Generator` plus lockfile detection. File it when the adapter lands in M2.

## D3: Deterministic OCI attestation ref scheme (spec §6, §13 Q3) — NORMATIVE, feeds the registry RFC

For an artifact with source ecosystem `E`, name `N`, canonical digest `D`:

```
<base>/<E>/<encoded-N>                                        repository
npm:    sha512-<first 64 hex chars of tarball sha512>.att     tag
skill:  bundle-v1-<sha256 hex, 64 chars>.att                  tag
oci:    native referrers API on the image digest; no mapping
```

- **Name encoding**: npm `@scope/name` maps to `scope/name` (npm has no unscoped names containing `/`, so this is injective), lowercased; PyPI names normalized per PEP 503; skill names must match `[a-z0-9-]+` (taken from SKILL.md frontmatter). Any name that still fails the OCI path segment grammar is a hard error `REF_UNMAPPABLE`, overridable with `--ref`. Fail closed, never guess.
- **Base resolution order**: `--attestation-base` flag, then `SMITHMARK_ATTESTATION_BASE` env, then a `smithmark.attestationBase` key in the artifact's own `package.json`, else error `ATTESTATION_BASE_UNKNOWN`.
- **Version is not in the tag**: the digest is the identity; version lives in the attestation subject; version tags would be mutable and ambiguous.

**Why safe**: tags are discovery only; trust always comes from verifying the full subject digest inside the DSSE envelope, so digest truncation and hostile bases both fail closed (worst case, discovery fetches an attestation that fails subject digest match). The `.att` suffix mirrors cosign's convention deliberately. The registry RFC's attestation reference field is what eventually retires the base resolution bootstrap; the RFC will say so explicitly.

## D4: `verify --strict` semantics and exit codes (spec §5, §13 Q4) — exit codes are API

Default is pure verify: lint findings never fail the command. `--strict` additionally fails on findings whose code matches `UNDECLARED_*`, and nothing else.

Exit codes, documented and stable:

| Code | Meaning |
|------|---------|
| 0 | verification passed |
| 1 | verification failure (signature, digest, schema, missing attestation) |
| 2 | strict lint gate only (verification passed, `UNDECLARED_*` present under `--strict`) |
| 3 | operational error (network, missing forgeseal, unusable config) |

**Why**: CI and the Claude Code hook must distinguish "artifact is bad" from "I could not check".

## D5: Hosted/SSE MCP servers deferred to phase 2 (spec §13 Q5)

v0.1 attests and verifies artifact distributed servers only. Two guards: `MCPSurface.Transport` still records all declared transports (a stdio artifact may also serve http; declaring it is not an error), and `registry check` reports informational `HOSTED_ENDPOINT_UNSUPPORTED` on remote only registry entries instead of erroring. Phase 2 ties hosted endpoint attestation to svidmint identity.

## D6: `agent-capability/v1` predicate schema (spec §2.3, §13 Q6) — ships verbatim in the TC54 draft

Field level shape approved 2026-07-16. Envelope: in-toto Statement v1, predicate type `https://in8.sh/attestation/agent-capability/v1`. Predicate fields: `schemaVersion` (semver), `artifact` {kind, name, version, source}, exactly one of `mcp` {transports, tools, resources, prompts} or `skill` {entryDigest, scripts, invokesTools} matching `artifact.kind`, `capabilities` (all five keys required), `dependencies` {sbomDigest, sbomFormat, locator} (optional block), `generatedAt`, `generator` {name, version}.

Binding rules:

- The subject digest lives only in the in-toto statement subject; it is never duplicated into the predicate (one source of truth).
- All five `capabilities` keys are required; an empty array means "declared none". Absence is never ambiguous, which is what makes `UNDECLARED_*` lint meaningful.
- `tools[].inputSchemaDigest` is sha256 over the RFC 8785 canonical JSON of the tool's input schema.
- Unknown fields are errors, everywhere, in both directions (generation and verification).
- Subject naming: purl for npm (`pkg:npm/name@version`); skill name for skills.

## D7: M0 whitespace verdict adopted; §1.2 narrowed to the composition claim

**Decided 2026-07-16 at the M0 gate.** The sweep (`docs/research/whitespace-sweep.md`) falsified the original blanket "first" claim: Enclawed (arXiv 2605.00424, implemented) ships signed skill manifests with a capability vocabulary and policy gate; `studiomeyer-io/mcp-server-attestation` signs MCP tool and spawn allowlists; ETDI binds signed tool definitions to a policy check. The maintainer adopted the narrowed composition claim (both artifact kinds; portable in-toto DSSE composing npm provenance, Sigstore, SLSA, and CycloneDX; external publication to admission loop) and the companion neighbor naming text; `requirements.md` §1.2, §1.3, and the whitespace status block were updated in the same commit. Watch items: canonical list with resolution conditions in `docs/research/whitespace-sweep.md` section 4, including the time sensitive TC54 venue. Development proceeds in a private GitHub repo (`sns45/smithmark`) with one PR per milestone; the naming gates recorded in U7 still apply before anything goes public.

## U1: Declared manifest source is `smithmark.yaml`

Makers declare capabilities and surfaces in `smithmark.yaml` at the artifact root; strict parsed; schema mirrors the predicate's `capabilities` and surface blocks. `manifest init` scaffolds it. Rejected: `package.json` embedding (skills have no `package.json`); JSON only (hostile to hand authoring). The `package.json` `smithmark` key carries only `attestationBase` discovery metadata (D3), never capability declarations.

## U2: Tool listing extraction — attest may execute, verify must not

`attest` launches the stdio server locally and issues `tools/list`; the maker is running their own code, and this yields exact tool names and input schema digests. `--tools-from <json>` is the escape hatch for CI that cannot launch the server. `verify` and `lint` never execute the artifact; lint is static only. This asymmetry is a documented security posture.

## U3: A missing attestation is a verification failure

`ATTESTATION_MISSING` is a failed check (exit 1); verification cannot succeed on nothing, matching cosign semantics. The `VerificationReport` is still emitted so assayward can consume the absence as evidence.

## U4: Skill identity

`ArtifactRef.Version` is optional for `kind=skill` (SKILL.md frontmatter `version` when present, else empty; the bundle digest is the identity). The statement subject digest key for skills is `smithmark-bundle-v1` (in-toto permits custom DigestSet keys), keeping it self describing and unconfusable with a plain file sha256.

## U5: assayward Evidence contract pinning

assayward's `Evidence` has no schema version field today. The cross repo contract test pins the assayward Go module at a fixed version in `go.mod` and round trips smithmark's Evidence block through assayward's `pkg/core` types with strict decoding; version bumps are deliberate and loud. The M5 gh issue on `sns45/assayward` asks for two things: widen `ImageRef` to a kind tagged `ArtifactRef`, and add an explicit `schemaVersion` field to `Evidence`.

## U6: Digest representation

in-toto DigestSet style throughout: `{"<alg>": "<hex>"}`. npm `sha512-<base64>` integrity strings are converted to hex at ingestion. Normative.

## U7: Naming gates

USPTO and third party Homebrew tap sweeps remain the maintainer's manual gates before the first public commit; local development proceeds under the smithmark name. Fallbacks per spec: `touchmark`, `provenmark`, `tangmark`.
