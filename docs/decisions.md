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

Amendment 2026-07-16: filesystem path patterns reject dotdot segments and backslashes; the bundle path hygiene rule applies to declared paths as well.

## D2: forgeseal integration mode (spec §2.2, §13 Q2)

Exec adapter in v0.1; library import later.

Evidence: forgeseal exports no packages (all logic sits under `internal/`), so a library import is impossible today. `pkg/compose` shells out to `forgeseal sbom --dir <projectDir> --output <file>` (the upstream `--lockfile` flag exists but the adapter passes the project directory instead), strict parses the CycloneDX JSON with cyclonedx-go, and enforces a minimum forgeseal version via `forgeseal version`. A missing binary fails `attest` with a machine readable code; an explicit `--skip-sbom` produces a manifest with no dependencies block, and verify then reports informational `DEPENDENCY_SBOM_MISSING`. The adapter sits behind an interface so the future swap to a library import is contained to one file.

Note: `attest --output` writes the raw SBOM as an `<output>.sbom.json` sidecar and stamps that filename as the manifest's dependencies locator before signing; the push path leaves the locator empty for now. SBOM publication and locator assignment for the push path land with M3 discovery or M6 release wiring.

Amendment 2026-07-17: M3 discovery ships the SBOM reference presence check only (`DEPENDENCY_SBOM_MISSING`, informational). SBOM locator assignment for the push path and sidecar SBOM discovery both land with the M6 release wiring, deliberately, not in M3.

**Follow up**: file a gh issue on `sns45/forgeseal` requesting an exported `pkg/sbom` facade over `internal/sbom.Generator` plus lockfile detection. File it when the adapter lands in M2. Filed: https://github.com/sns45/forgeseal/issues/26

## D3: Deterministic OCI attestation ref scheme (spec §6, §13 Q3) — NORMATIVE, feeds the registry RFC

For an artifact with source ecosystem `E`, name `N`, canonical digest `D`:

```
<base>/<E>/<encoded-N>                                        repository
npm:    sha512-<first 64 hex chars of tarball sha512>.att     tag
skill:  bundle-v1-<sha256 hex, 64 chars>.att                  tag
oci:    native referrers API on the image digest; no mapping
```

- **Name encoding**: npm `@scope/name` maps to `scope/name` (npm has no unscoped names containing `/`, so this is injective), lowercased; PyPI names normalized per PEP 503; skill names must match `[a-z0-9-]+`, taken from the `smithmark.yaml` declaration, with SKILL.md frontmatter as a cross check when present. Any name that still fails the OCI path segment grammar is a hard error `REF_UNMAPPABLE`, overridable with `--ref`. Fail closed, never guess.
- **Base resolution order**: `--attestation-base` flag, then `SMITHMARK_ATTESTATION_BASE` env, then a `smithmark.attestationBase` key in the artifact's own `package.json`, else error `ATTESTATION_BASE_UNKNOWN`.
- **Version is not in the tag**: the digest is the identity; version lives in the attestation subject; version tags would be mutable and ambiguous.

**Why safe**: tags are discovery only; trust always comes from verifying the full subject digest inside the DSSE envelope, so digest truncation and hostile bases both fail closed (worst case, discovery fetches an attestation that fails subject digest match). The `.att` suffix mirrors cosign's convention deliberately. The registry RFC's attestation reference field is what eventually retires the base resolution bootstrap; the RFC will say so explicitly.

Amendment 2026-07-16: digest values must be exact length for the mapping (npm sha512 exactly 128 hex, pypi and skill digests exactly 64); wrong lengths are REF_UNMAPPABLE, never truncated or padded.

Amendment 2026-07-17 (live OCI scoping deferred): M3 exercises attestation discovery against an injected oras target with an in memory store; the live registry client is not yet scoped to the per artifact repository `AttestationRef` computes. `discoverByTag` keeps only the tag half of the `(repository, tag)` pair, and the CLI builds its read target from the raw `--attestation-base` flag rather than resolving it through `ResolveAttestationBase`. When the base resolves to empty, the production read target factory now fails closed with a coded `DISCOVERY_FAILED` naming the limitation instead of an uncoded `INTERNAL_ERROR`. No memory store test can catch the scoping gap, so the full live wiring lands with the M6 dogfood, the first live consumer. Tracked: https://github.com/sns45/smithmark/issues/4

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

Amendment 2026-07-17 (two class check design): verification checks fall in two classes. A failing class check drives the nonzero verify exit code (the table above) when it fails; an informational check is marked `informational` in the report, never drives an exit code, and is left for downstream policy such as assayward to weigh. The classification is authored in exactly one place, `pkg/core/verify`, and documented per code in `docs/codes.md`; the exported `FailingChecksFailed` helper is the single authority every exit mapping keys off, so a false informational check (a key based offline bundle's absent Rekor entry, or the npm interop checks) never rejects a valid artifact.

Amendment 2026-07-17 (v0.1 verification scope): v0.1 verifies key based offline bundles against a PEM public key only. There is no transparency log to consult offline, so `REKOR_INCLUSION_VALID` reports an informational false for these bundles rather than a failure. Keyless certificate verification (Fulcio, the Sigstore TUF trust root), transparency log inclusion proofs, and cryptographic verification of npm's own SLSA provenance (`NPM_PROVENANCE_VERIFIED`) are all accepted as inputs but report as not attempted; they land, exercised live, in M6.

Amendment 2026-07-17 (M4, capability lint attaches to verify only for local source trees): `smithmark verify` now runs the capability lint (the M4 declared versus detected gap engine) and populates the report's `Findings`, but only when the artifact argument is a local directory. A remote or bundle only verification leaves `Findings` an empty, non nil slice and emits a `lint skipped: no local sources` note on stderr (summary mode). The reason is the U2 posture: verify never executes an artifact, and a remote artifact carries no source tree to statically scan, so there is nothing to lint; the only artifact with source on hand is a local install, which is exactly what the M6 Claude Code hook demo verifies. The findings never change any verification check outcome; they feed only the `--strict` exit 2 gate. That gate is now live: a passing verification (every failing class check passed) that carries any `UNDECLARED_*` finding exits 2 under `--strict` and 0 without it, completing the D4 exit contract. The lint reads the declared capabilities from the local `smithmark.yaml`, the same declaration `smithmark lint` uses, so the two commands scan a tree one way.

Amendment 2026-07-17 (M4, lint detector coverage and the hook demo fixture): the capability lint ships a static detector for four of the five declared capability classes, network, filesystem, exec, and env. The fifth, secrets, has none in v0.1, because a secret is not a syntactic construct a line matching heuristic can recognize, so four `UNDECLARED_*` codes deliberately cover five declared classes and an undeclared secret is never a lint finding. Separately, the M6 Claude Code hook demo needs a SIGNED, misdeclared `mcp-server` fixture to block, and that does not exist yet: the only signed misdeclared fixture today is a skill (`testdata/skills/misdeclared-skill`, verified through `--bundle`), while the misdeclared `mcp-server` fixture (`testdata/misdeclared`) is unsigned and its npm sourced declaration cannot complete attestation discovery offline. Until M6 mints a signed misdeclared server fixture, the strict verify hook test targets the signed misdeclared skill through `--bundle`.

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

## D8: The Homebrew tap ships smithmark as a Cask

**Decided 2026-07-16 at the M2 gate.** goreleaser 2.17 hard fails on the deprecated `brews` block, so smithmark publishes to `sns45/homebrew-tap` as a Cask (`brew install --cask smithmark`) while the sibling tools remain Formulas for now. The maintainer accepted the divergence; siblings migrate to casks whenever they next upgrade goreleaser. The snapshot build verified the cask installs a working binary on PATH.

## U1: Declared manifest source is `smithmark.yaml`

Makers declare capabilities and surfaces in `smithmark.yaml` at the artifact root; strict parsed; schema mirrors the predicate's `capabilities` and surface blocks. `manifest init` scaffolds it. Rejected: `package.json` embedding (skills have no `package.json`); JSON only (hostile to hand authoring). The `package.json` `smithmark` key carries only `attestationBase` discovery metadata (D3), never capability declarations.

## U2: Tool listing extraction — attest may execute, verify must not

`attest` launches the stdio server locally and issues `tools/list`; the maker is running their own code, and this yields exact tool names and input schema digests. `--tools-from <json>` is the escape hatch for CI that cannot launch the server. `verify` and `lint` never execute the artifact; lint is static only. This asymmetry is a documented security posture.

Amendment 2026-07-17 (M4, `TOOL_LISTING_MISMATCH` fires at attest time only): because `verify` and `lint` never execute an artifact, the declared versus extracted tool comparison can only run where execution is already sanctioned, namely `attest`. When an attest invocation carries BOTH `--tools-from` and a declared launch command, attest runs the live extraction, compares it against the file by tool name and input schema digest (order independent, description ignored), and fails closed with a typed `TOOL_LISTING_MISMATCH` naming the disagreement. Signing a manifest whose tool listing deviates from the provided reference is exactly the misdeclaration this project exists to catch, so it is refused rather than silently preferring one source. With only one of the two present the prior behavior stands (the file is trusted, or the server is the sole source); with neither, attest still fails with `TOOL_EXTRACTION_FAILED` naming both remedies. The `TOOL_LISTING_MISMATCH` docs row now names this attest emit site rather than reading "reserved".

## U3: A missing attestation is a verification failure

`ATTESTATION_MISSING` is a failed check (exit 1); verification cannot succeed on nothing, matching cosign semantics. The `VerificationReport` is still emitted so assayward can consume the absence as evidence.

## U4: Skill identity

`ArtifactRef.Version` is optional for `kind=skill` (SKILL.md frontmatter `version` when present, else empty; the bundle digest is the identity). The statement subject digest key for skills is `smithmark-bundle-v1` (in-toto permits custom DigestSet keys), keeping it self describing and unconfusable with a plain file sha256.

## U5: assayward Evidence contract pinning

assayward's `Evidence` has no schema version field today. The cross repo contract test pins the assayward Go module at a fixed version in `go.mod` and round trips smithmark's Evidence block through assayward's `pkg/core` types with strict decoding; version bumps are deliberate and loud. The M5 gh issue on `sns45/assayward` asks for two things: widen `ImageRef` to a kind tagged `ArtifactRef`, and add an explicit `schemaVersion` field to `Evidence`.

Amendment 2026-07-17 (M4, lint findings are not yet carried in Evidence): `smithmark verify` populates `VerificationReport.Findings` from the capability lint over a local source tree and gates the `--strict` exit 2 on them (D4), but the assayward compatible Evidence block does NOT carry those findings, because assayward's `Evidence` has no findings field. The M5 Task 5.4 issue therefore asks for a third thing alongside the `ArtifactRef` widening and the `schemaVersion` field: that Evidence carry the lint findings, or a findings digest, so a policy engine can weigh them without re running the lint itself. Until that lands, findings live only in smithmark's own report surface, never in the Evidence handed to assayward.

Filed 2026-07-17 (M5 Task 5.4): the work item covering all three asks (kind tagged `ArtifactRef` with algorithm aware digest matching, an explicit `schemaVersion`, and lint findings in Evidence) is `sns45/assayward#1` (https://github.com/sns45/assayward/issues/1). The issue also flags the `verify/slsa.go` unconditional `sha256:` strip as the concrete reason the digest widening must be algorithm aware. smithmark drops the `SignatureNote` kind shim once the widening ships in a tagged assayward release.

## U6: Digest representation

in-toto DigestSet style throughout: `{"<alg>": "<hex>"}`. npm `sha512-<base64>` integrity strings are converted to hex at ingestion. Normative.

## U7: Naming gates

USPTO and third party Homebrew tap sweeps remain the maintainer's manual gates before the first public commit; local development proceeds under the smithmark name. Fallbacks per spec: `touchmark`, `provenmark`, `tangmark`.

## U8: M6 dogfood — the D1 capability taxonomy meets real first party servers (2026-07-17)

Task 6.1 authored honest `smithmark.yaml` declarations for two real MCP servers (better-call-claude 3.1.1 and dear-claude 1.1.0) by reading their vendored `src`, attested them with the throwaway dogfood key, and verified they pass. This is where D1 (the capability taxonomy) and D6 (the manifest schema) first met real product code rather than fixtures. Both real servers validate and lint clean; the only lint finding across all three committed fixtures is the intended `UNDECLARED_NETWORK_EGRESS` on the deliberately misdeclared server. The friction the taxonomy surfaced, captured honestly for the record:

- **`server.json` carries no tool listing.** The plan assumed tools would be derived from `server.json`'s declared tool names. The MCP Registry `server.schema.json` (2025-12-11) that both servers publish carries only packages, transports, and environment variable names; it has no tools array at all. The tool names and their input schemas live in the server `src` (better-call-claude registers ten tools inline in `index.ts`; dear-claude registers eight in `mcp.ts`). Both happen to use plain JSON Schema, not zod, so `manifest.SchemaDigest` could compute a real `inputSchemaDigest` over a static transcription committed as `tools.json`. Where a server used zod or built schemas dynamically, no offline digest would have been possible without executing the server, which verify and lint must never do (U2); the real release path is attest launching the server for a live extraction. Recorded so the D3/6.4 MCP Registry provenance RFC can note that a provenance aware registry entry would benefit from carrying (or referencing) the tool listing the manifest attests, since the schema does not surface it today.

- **Env var driven filesystem paths the D1 fs grammar cannot express.** dear-claude reads a GitHub App private key from whatever path `GITHUB_APP_PRIVATE_KEY_PATH` names, watches an Obsidian vault at `OBSIDIAN_VAULT_PATH`, and spawns Claude with a caller selectable `working_dir`. D1's fs grammar offers the portability tokens `${home}`, `${tmp}`, `${cwd}` plus relative paths, but it has no way to say "an arbitrary absolute path supplied at runtime by an env var" short of the bare `**` escape hatch, which would be dishonestly broad. Resolution: declare the concrete known paths (`${home}/.dear-claude/**`, `data/**`, `${home}/.claude.json`, `${tmp}/dear-claude-debug.log`) and record the unbounded env driven paths here as a genuine taxonomy gap rather than papering over them with `**`.

- **Transitive exec has no first class representation.** dear-claude spawns the `claude` binary through `@anthropic-ai/claude-agent-sdk`'s `query()`, not a literal `child_process` call, and better-call-claude spawns `claude` directly. D1's exec rule is a binary basename, which fits both, but the manifest has no way to mark an exec as transitive (the SDK spawns it) versus direct, nor to record that the spawned Claude runs with permissions fully bypassed. Both were declared as `exec: claude` with the transitivity noted in the reason string; the "runs with bypassed permissions" fact has no schema home and lives only in prose.

- **Egress hosts hidden behind SDKs and libraries.** better-call-claude's WhatsApp egress goes through `@whiskeysockets/baileys`, whose concrete WebSocket hosts are managed inside the library (only `@s.whatsapp.net`, an addressing suffix, appears as a source literal). Telnyx, OpenAI, and Anthropic egress likewise flows through SDK clients whose base URLs are not in the source. Resolution: declare the canonical, well known hosts conservatively (`*.whatsapp.net`, `web.whatsapp.com`, `api.telnyx.com`, `api.openai.com`, `api.anthropic.com`) and note in each reason that the exact host is library managed. The taxonomy is honest here only because the author knows the library's endpoints; a purely static reading of the source could not have produced them.

- **Configurable egress destinations.** dear-claude's `GITLAB_URL` lets the GitLab host be any self hosted instance; the default is `gitlab.com`. D1's host grammar has no "configurable, defaults to X" form. Declared `gitlab.com` and noted the override; a `*` would be dishonestly broad.

- **Lint suppression is class level, not per destination (a precision boundary, not a false positive).** For network, filesystem, and exec, any one non empty declared entry suppresses every detected call of that class (spec 1.3, by design: the detectors match constructs like `fetch`, not resolved destinations). So a server that declared `api.twilio.com` but omitted `api.openai.com` would still lint clean. This is a documented limitation of the static heuristics, not a false positive: it means lint catches an entirely undeclared class, never an under declared subset within a class. Because lint cannot enforce host level completeness, the declarations carry it by authorial principle instead: every host any code path causes the artifact to contact is declared, and that principle is applied to subprocess mediated egress too, not only direct `fetch` calls. A host the artifact causes a spawned subprocess to reach is a real egress and is declared with an explicit reason naming the transitivity: `api.anthropic.com` for the spawned claude in both servers, and `api.giphy.com` for the gif search curl dear-claude hands its spawned claude. The per host list is therefore complete including subprocess mediated destinations, so lint staying clean reflects true declarations, not a suppressed class. Env is the one class the lint checks by name, so both real declarations enumerate the exact literal `process.env.X` set the code reads.

- **Secrets are advisory `kind:provider` metadata with an unconstrained vocabulary.** D1 validates the `kind:provider` grammar but never lint checks secrets, and it fixes no vocabulary for `kind`. Mapping the env credential semantics to pairs (`api-key:twilio`, `access-token:github`, `webhook-secret:linear`, `private-key:github`, and so on) is author judgment; `account-sid:twilio` versus `api-key:twilio` is a coin flip the schema does not adjudicate. Declared representative kinds per provider.

- **No lint false positive was observed.** Every construct the JS detector flagged in the two real servers was a real capability, and declaring it (or, for env, the exact name) cleared it. The heuristics' known false positive posture (commented out or inert constructs still match) did not fire on either real server.

- **Attestation stand ins, recorded for honesty.** The subjects carry fabricated fixed `sha512` digests because the snapshots are not published tarballs (the Task 3.1 pattern); the bundles omit the forgeseal SBOM because `forgeseal` was absent on PATH during authoring (the real release attests with it). Both stand ins are documented in `testdata/README.md`.
