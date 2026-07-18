# MCP Registry provenance: an attestation reference field and verify on publish

**A proposal to the MCP Registry maintainers to add an attestation reference field to registry entries and to define verify on publish semantics, so that a registry entry can point at a portable, signed capability attestation and the registry can check it before the entry goes live.**

| | |
|---|---|
| Status | Draft for community discussion |
| Target venue | `github.com/modelcontextprotocol/registry` (GitHub Discussions, then a schema change PR / SEP per the process in section 12) |
| Registry schema targeted | `server.json`, schema `2025-12-11` (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`) |
| Reference implementation | smithmark (`github.com/sns45/smithmark`), the `smithmark registry check` command and the `agent-capability/v1` in-toto predicate |
| Companion proposal | `proposals/cyclonedx-agent-capability/PROPOSAL.md` (the TC54 taxonomy the referenced attestation projects into) |
| Author | smithmark maintainer |
| Sources verified | 2026-07-18 (see the References section) |

> `smithmark registry check` is the working demonstration of this proposal. It fetches a real MCP Registry entry, reports that the entry carries no attestation reference field (because none exists in the schema today), and then, because the registry gives it no pointer, falls back to a deterministic OCI reference computed from the package identity to find and verify the capability attestation anyway. The fallback is exactly the interim scheme the proposed field would retire.

---

## 1. Summary and the ask

The MCP Registry is the community catalog that gives MCP clients a curated list of servers. It verifies that a publisher controls a namespace before that publisher may publish under it, and it moderates listings. It does not, and does not claim to, attest what a server is or what it may do at runtime. An MCP server can place phone calls, read a filesystem, spawn subprocesses, and reach credentialed network endpoints; the registry entry that a client resolves by name states none of this in an attestable form.

Two things are missing, and this proposal asks for both.

**The ask, in two parts:**

1. **Add an attestation reference field to registry entries.** A registry entry should be able to carry a reference (a locator plus a digest, and the predicate type) to a portable, signed attestation of the server's provenance and capability surface. The reference points at the attestation; it does not embed it. Section 6.1 gives a concrete field shape and an interim `_meta` form that needs no schema change to pilot.

2. **Define verify on publish semantics.** When an entry carries an attestation reference, the registry should fetch the referenced attestation at publish time, verify its signature, confirm the attested subject digest binds to the package the entry distributes, and record the outcome. Section 6.2 specifies this. Namespace verification proves who owns the name; verify on publish additionally proves the referenced attestation is authentic and bound to the artifact.

The referenced attestation is not a new bespoke format. It is the `agent-capability/v1` in-toto DSSE predicate that smithmark already emits, signs, and verifies today, and whose capability taxonomy the companion TC54 proposal standardizes. This RFC is the discovery and admission layer; that predicate is the payload; the TC54 taxonomy is its SBOM projection. The three are one design viewed from three points.

Nothing here asks the registry to become a signing authority, to mint keys, or to host attestations. The maker signs once, publishes the attestation wherever attestations already live (an OCI registry today), and the entry carries a reference the registry can check. This composes with the supply chain trust infrastructure that already exists rather than replacing it.

---

## 2. The problem, stated against the real schema

### 2.1 What a registry entry carries today (verified against source)

The `2025-12-11` `server.json` schema, which every live entry references and which both worked example servers in section 8 publish, defines these top level fields on the server object: `$schema`, `_meta`, `name`, `title`, `description`, `version`, `icons`, `repository`, `websiteUrl`, `packages`, and `remotes`. Within each entry of `packages` it defines `registryType`, `identifier`, `version`, `fileSha256`, `registryBaseUrl`, `transport`, `packageArguments`, `runtimeHint`, `runtimeArguments`, and `environmentVariables`. This was read directly from the published schema and the registry docs on 2026-07-18 (References).

The only integrity metadata anywhere in that shape is `fileSha256`, described in the schema as:

> "SHA-256 hash of the package file for integrity verification. Required for MCPB packages and optional for other package types."

That is a content hash for a bundle. It is integrity, not provenance and not a capability declaration. It says the bytes you fetched are the bytes the publisher listed; it says nothing about who built them, from what source, or what they are permitted to do. There is no signature over `server.json`, no reference to a build provenance attestation, and no field that names or points at a capability declaration. The `environmentVariables` array names the variables a server reads, which is a partial and advisory view of one capability class, but it is neither signed nor bound to the artifact digest, and it does not cover egress, filesystem, exec, or secrets.

### 2.2 The gap is confirmed, not assumed

This gap was recorded during the smithmark Phase 0 registry investigation (`docs/research/notes/mcp-registry.md`, accessed 2026-07-16) and again in the whitespace sweep (`docs/research/whitespace-sweep.md`, section 4):

> The registry RFC gap is confirmed. server.json has no attestation reference field today; `fileSha256` for MCPB bundles is the only integrity metadata.

It was reconfirmed for this RFC by fetching the live `2025-12-11` schema, the registry docs, and the registry OpenAPI on 2026-07-18. All three agree: no attestation, provenance, signature, or capability reference field exists at the top level or within packages. The schema version live entries reference has not changed since the Phase 0 read, and the field is still absent. If the registry adds such a field, this RFC becomes a comment on that field's shape rather than a request to create one; as of the verification date it does not exist.

### 2.3 What this costs

Agent tools are installed the way container images were installed in 2015: pulled by name, trusted by reputation. A client that resolves `io.github.sns45/dear-claude` from the registry receives a name, a description, an npm identifier, a transport, and a list of environment variable names. It does not receive, and cannot ask the registry for, a signed statement of what that server may do or a pointer to one. Every consumer that wants provenance or a capability declaration must reconstruct it out of band, and every consumer reconstructs it differently. There is no portable evidence and no admission gate the registry itself can run.

---

## 3. Named prior art and concurrent work (novelty demonstrated, not asserted)

The idea of adding trust signals to a registry entry is not empty whitespace, and this section names the neighbors so the specific slot this RFC occupies is visible. The discipline is the same one the smithmark whitespace sweep applied to the framework claim: cite where each neighbor stops rather than assert novelty.

### 3.1 Active registry proposals (verified in the issue tracker, 2026-07-18)

The registry maintainers are already discussing adjacent trust signals. These are the most important neighbors because they are live, in the target venue, and this RFC must relate to them rather than ignore them.

- **A `verified` publisher field (issue #823, open).** A subregistry maintainer asks for a first class `verified` field indicating whether a server is from a verified or trusted publisher, optionally with `verifiedBy` and a publisher identifier. This is an ownership and reputation signal produced by the registry. It answers "did a trusted party publish this," not "what may this artifact do" and not "is there a signed statement bound to this exact build." It is complementary: a `verified` flag and an attestation reference answer different questions, and an entry could carry both.

- **A security scan metadata field (issue #1273, open).** A proposal to add an optional field pointing at external scan results (referencing the Agent Threat Rules detection standard and scanners such as cisco-ai-defense/skill-scanner and microsoft/agent-governance-toolkit). This is the scanner angle: point in time findings produced by a third party detector, not a declaration signed by the maker and bound to the artifact. Scanners inspect; they emit findings, not attestations. A scan result is a useful signal to surface next to an entry, and it is a different artifact from a capability attestation: one is an outside opinion about the code, the other is the maker's signed statement of intent that a policy engine can hold the code to.

- **Trust at first contact via an AID DNS record and key handshake (issue #406, open, labeled v1).** A proposal to bind the published MCP URI to a server key the publisher controls, using an Agent Identity and Discovery DNS record, so a client can prove ongoing key continuity of a live endpoint. This targets the hosted, remote endpoint case and the identity continuity problem. It is orthogonal to and complementary with this RFC: identity continuity of a running endpoint is a different guarantee from a signed capability attestation bound to a distributed artifact digest, and smithmark's own hosted endpoint story (decision D5) is deliberately deferred to a later phase precisely because it needs a runtime identity primitive like this one.

- **The `_meta` vendor extension mechanism (issues #356, #292, resolved).** The registry already supports reverse DNS namespaced vendor extensions under `_meta` (for example the live `io.modelcontextprotocol.registry/official` block every entry carries). This is the mechanism section 6.1 proposes to use for an interim, no schema change pilot of the attestation reference.

### 3.2 Concurrent academic proposals (surfaced 2026-07-18)

A web search on the verification date surfaced concurrent academic work proposing cryptographic provenance for the MCP registry. These are near neighbors and are named here so the claim stays falsifiable.

- **Attested Tool-Server Admission (arXiv 2605.24248).** The closest neighbor. It proposes an external attestation reference (a small offline signed clearance assertion a server publishes at a well known URI, verified against a pinned trust root before tool dispatch), a per server deny by default tool allowlist, and a gated enforcement mode. This overlaps this RFC's first ask directly: an external, signed, referenced assertion rather than a signature over the metadata. It differs in venue and payload: it verifies at connect and dispatch time against a well known URI on the running server, and its declared surface is a tool allowlist. This RFC proposes a reference on the registry entry, checked at publish and discovery time, pointing at a capability attestation that covers the full surface (network egress, filesystem, exec, environment, secrets) for both MCP servers and skills, and composes existing supply chain roots rather than pinning a bespoke one. The two are complementary layers of the same defense, and an honest reading is that the external referenced assertion idea is shared, while the capability breadth, the both kinds coverage, the registry entry carriage, and the supply chain composition are this proposal's distinct contribution.

- **A Trustworthy MCP Registry blueprint (Future Internet, doi 10.3390/fi18050243).** Proposes signing the canonical server registration with Sigstore keyless, recording it in Rekor, and publishing the publisher key at a well known URI, with a dual signature model. This signs the metadata: it is origin and integrity of the `server.json` registration, which is valuable and which this RFC does not duplicate. It does not carry a capability declaration; a perfectly signed registration still says nothing about what the server may do. The distinction is the same one the whitespace sweep drew for Docker MCP Catalog and NVIDIA Verified Agent Skills, which sign their own inventory: the signature attests origin, not capability.

- **Cryptographic Registry Provenance against dependency confusion (arXiv 2605.03309).** A structural defense for naming and dependency confusion in AI package ecosystems. Adjacent and complementary; it concerns which package a name resolves to, not what the resolved package may do.

### 3.3 The framework level neighbors (from the smithmark whitespace sweep)

The broader landscape study (`docs/research/whitespace-sweep.md`, fourteen swept items, accessed 2026-07-16) records the capability attestation neighbors and where each stops: Enclawed signs skill manifests for its own runtime (skills only, bespoke Ed25519 trust root); studiomeyer-io/mcp-server-attestation signs an MCP server tool and spawn allowlist under trust on first use (egress, filesystem, and secrets out of scope, no skills); ETDI binds OAuth scoped tool definitions to a client side check (its upstream MCP SDK contribution was closed unmerged); npm provenance and Docker and NVIDIA sign build origin or inventory, never capability. None covers both artifact kinds, none composes npm provenance, Sigstore, SLSA, and CycloneDX through a portable predicate, and none feeds an external admission gate.

### 3.4 The specific slot this RFC occupies

Putting the three groups together, the unoccupied slot is precise and falsifiable: a reference field **on the registry entry itself** that points at a **portable, signed capability attestation** covering **both MCP servers and skills**, whose predicate **composes the existing supply chain roots** and is **projected into CycloneDX** for SBOM native policy, checked by a **verify on publish** gate the registry runs. Each near neighbor holds part of this. A single prior design that held all of it would falsify the claim; as of 2026-07-18 the sweep and the search found none.

---

## 4. What the registry does well today, and why this composes with it

This proposal is additive and respectful of the model that exists.

- **Namespace ownership verification** (GitHub OAuth and OIDC, DNS challenge, HTTP challenge) proves that a publisher controls the name at publish time. That proof is real and this RFC relies on it: verify on publish runs after ownership is established, so an attestation reference is only meaningful for a publisher who already proved they own the namespace.
- **Moderation** removes entries that violate policy. An authenticated capability attestation gives moderators a signed, machine readable basis for a decision rather than a manual read of the source.
- **The `_meta` extension mechanism** already lets vendors attach reverse DNS namespaced metadata. The interim form of the attestation reference (section 6.1) rides this mechanism, so a pilot needs no schema change at all.

What ownership verification does not provide, by design, is any statement about the artifact after publish. Verification proves who controls a namespace at publish time, not that any artifact is authentic thereafter, and never what the artifact may do. That is the gap this RFC fills, and it fills it without weakening anything the registry already guarantees.

---

## 5. The reference points at a capability attestation (relationship to the predicate and the TC54 taxonomy)

The attestation this RFC asks entries to reference is smithmark's `agent-capability/v1` in-toto DSSE statement. Its shape is fixed and implemented (smithmark decision D6):

- an in-toto Statement v1 whose subject digest is the artifact (the npm tarball sha512 for a server, the `smithmark-bundle-v1` bundle digest for a skill),
- predicate type `https://in8.sh/attestation/agent-capability/v1`,
- a predicate declaring the artifact identity, exactly one of an `mcp` or `skill` surface, and all five capability classes (network egress, filesystem, exec, environment, secrets), plus an optional dependency SBOM reference and the producing generator,
- signed with Sigstore and verifiable offline against a public key.

Two design facts make this the right payload for a registry reference:

1. **The subject digest is the binding.** Trust always comes from verifying the full subject digest inside the DSSE envelope. A reference that a registry stores is discovery only; the guarantee comes from the signature over the digest, so a hostile or stale reference fails closed (worst case, discovery fetches an attestation whose subject digest does not match the package, and verification rejects it). This is what lets the registry carry a reference safely without becoming a trust authority.

2. **The predicate is projected, not reinvented, into CycloneDX.** The companion TC54 proposal (`proposals/cyclonedx-agent-capability/PROPOSAL.md`) maps every predicate field either to a native CycloneDX construct or to one `in8:agent:capability:*` property, kept in lockstep by a `schemaVersion` anchor. So the same facts a registry consumer discovers through this reference are the facts an SBOM aware policy engine reads through the taxonomy. The registry field is the discovery seam; the taxonomy is the SBOM seam; the predicate is the single source of truth behind both. The three proposals are deliberately coherent: this RFC and the TC54 proposal cite each other, and neither invents a field the other does not carry.

---

## 6. The proposal in detail

### 6.1 An attestation reference field on registry entries

**First class form (the schema change asked for).** Add an optional `attestations` array to the server object, a sibling to `packages` and `remotes`. Each entry references one attestation:

```json
"attestations": [
  {
    "type": "capability",
    "predicateType": "https://in8.sh/attestation/agent-capability/v1",
    "url": "oci://ghcr.io/sns45/attestations/npm/dear-claude:sha512-<first 64 hex of tarball sha512>.att",
    "digest": { "sha256": "<sha256 of the DSSE bundle>" },
    "subjectDigest": { "sha512": "<npm tarball sha512 hex>" }
  }
]
```

- `type` is an open, lowercase token so the field is not specific to capability attestations; a `provenance` reference (an npm or SLSA build provenance attestation) fits the same shape, which keeps the field useful beyond this one predicate.
- `predicateType` lets a consumer decide whether it understands the payload before fetching it.
- `url` is where the attestation lives. An `oci://` reference to an OCI registry is the expected transport today (attestations already live in OCI registries as referrers or tagged objects); an `https://` bundle is equally valid.
- `digest` binds the reference to the exact attestation bytes, so a consumer knows the fetched envelope was the one the publisher listed even before it verifies the signature.
- `subjectDigest` optionally restates the artifact digest the attestation is expected to bind to, so verify on publish can cross check it against the package's own `fileSha256` (for MCPB) or resolved npm integrity without first fetching the attestation. It is a convenience, never the trust anchor; the DSSE subject digest remains authoritative.

**Interim form (no schema change, pilot today).** Because the registry already supports reverse DNS namespaced `_meta` extensions (issues #356, #292), a publisher can carry the same reference under a vendor namespace without any schema change:

```json
"_meta": {
  "sh.in8/attestation": {
    "predicateType": "https://in8.sh/attestation/agent-capability/v1",
    "url": "oci://ghcr.io/sns45/attestations/npm/dear-claude:sha512-<first 64 hex>.att",
    "digest": { "sha256": "<sha256 of the DSSE bundle>" }
  }
}
```

This is the recommended way to gather real world signal before committing the schema. A pilot under `_meta` costs the registry nothing, lets clients and smithmark exercise the reference against live entries, and informs the eventual first class field. The reverse DNS namespace keeps it unambiguous and revocable, exactly as the extension mechanism intends.

### 6.2 Verify on publish semantics

When a submitted entry carries an attestation reference (in either form), the registry, or a publish side validator the registry invokes, performs the following at publish time, before the entry is surfaced as active:

1. **Fetch** the attestation at `url` and confirm its bytes match `digest`. A mismatch, or an unfetchable reference, fails the publish (or, in a softer rollout, records a failed verification status the entry carries; see the rollout note).
2. **Verify the signature** of the DSSE envelope. For a Sigstore keyless attestation this means the Fulcio certificate chain and the Rekor inclusion proof against the public good trust root; for a key based attestation, against a publisher key established through the same namespace proof the registry already performs. Signature failure fails the publish.
3. **Bind the subject to the artifact.** Confirm the attestation's subject digest matches the artifact the entry distributes: for an MCPB package, the entry's `fileSha256`; for an npm package, the tarball integrity the identifier and version resolve to. A subject that does not bind to the published artifact fails the publish. This is the step that turns a signed statement into a statement about *this* server rather than any server.
4. **Recognize the predicate.** Confirm `predicateType` is one the registry admits. An unknown predicate type is not a failure of authenticity; it is recorded and the entry may still publish, since the registry need not understand every predicate to carry a reference to it.
5. **Record the outcome.** Store the verification result (verified, failed, or not attempted) with the entry, so a client resolving the entry learns not only that a reference exists but that the registry checked it at publish time. This is the durable, attributable evidence the security frameworks in section 9 call for.

**Rollout.** Verify on publish can ship in stages. Stage one records the verification outcome without blocking publication, so publishers adopt references and the registry accumulates signal with no risk of a false rejection. Stage two makes verification failure block publication for entries that opt in (or for namespaces that require it). Stage three, if the community wants it, makes a verified capability attestation a precondition for a `verified` publisher badge (relating this RFC to issue #823). Each stage is independently valuable and none is a prerequisite for shipping the reference field itself.

### 6.3 The interim discovery scheme the field replaces (normative, quoted from smithmark decision D3)

Until the registry carries a reference, a verifier that has only a package identity must compute where the attestation lives. smithmark specifies a deterministic mapping from an artifact's ecosystem, name, and digest to an OCI reference, so discovery needs no registry pointer. This is the scheme `smithmark registry check` uses today, and it is exactly the bootstrap the proposed field retires. It is reproduced here verbatim from the smithmark decision record (`docs/decisions.md`, decision D3, which is normative in that project) so this RFC is precise about what the field replaces:

> For an artifact with source ecosystem `E`, name `N`, canonical digest `D`:
>
> ```
> <base>/<E>/<encoded-N>                                        repository
> npm:    sha512-<first 64 hex chars of tarball sha512>.att     tag
> skill:  bundle-v1-<sha256 hex, 64 chars>.att                  tag
> oci:    native referrers API on the image digest; no mapping
> ```
>
> - **Name encoding**: npm `@scope/name` maps to `scope/name` (npm has no unscoped names containing `/`, so this is injective), lowercased; PyPI names normalized per PEP 503; skill names must match `[a-z0-9-]+`, taken from the `smithmark.yaml` declaration, with SKILL.md frontmatter as a cross check when present. Any name that still fails the OCI path segment grammar is a hard error `REF_UNMAPPABLE`, overridable with `--ref`. Fail closed, never guess.
> - **Base resolution order**: `--attestation-base` flag, then `SMITHMARK_ATTESTATION_BASE` env, then a `smithmark.attestationBase` key in the artifact's own `package.json`, else error `ATTESTATION_BASE_UNKNOWN`.
> - **Version is not in the tag**: the digest is the identity; version lives in the attestation subject; version tags would be mutable and ambiguous.

The digest exactness amendment to D3 is part of the scheme and is quoted with it:

> digest values must be exact length for the mapping (npm sha512 exactly 128 hex, pypi and skill digests exactly 64); wrong lengths are REF_UNMAPPABLE, never truncated or padded.

The npm tag therefore carries the first 64 hex characters of the full 128 hex tarball sha512, and a skill tag carries the full 64 hex sha256 of its bundle digest; the `.att` suffix mirrors cosign's convention deliberately.

**Why this scheme is safe and why the registry field still improves on it.** Tags in this scheme are discovery only; trust always comes from verifying the full subject digest inside the DSSE envelope, so digest truncation in the tag and a hostile `<base>` both fail closed. The scheme works today with zero registry cooperation, which is its virtue. Its cost is the `<base>` bootstrap: a verifier must be told, out of band, which OCI registry to look in (`--attestation-base`, an env var, or a `package.json` key). A registry that carries the attestation reference directly retires that bootstrap: the `url` in the reference names the location exactly, so no base resolution and no name encoding are needed, and a publisher who stores attestations somewhere the deterministic scheme cannot express (a private registry, a non OCI transport) can still be discovered. The deterministic scheme is the interim; the reference field is the destination. smithmark's decision D3 says this explicitly: the registry RFC's attestation reference field is what eventually retires the base resolution bootstrap.

---

## 7. The working demonstration: `smithmark registry check`

This RFC does not propose a mechanism in the abstract. smithmark ships `smithmark registry check <server-name>`, which measures the gap against real entries and demonstrates the interim scheme end to end. Its behavior is real and committed (`pkg/discover/registry.go`, `cmd/smithmark/registry.go`, `pkg/core/verify/verify.go`).

**What it does.** It resolves `<server-name>` against the real MCP Registry API (the get specific server version operation, requesting `latest`), decodes the entry leniently the same way it treats npm's foreign formats, and builds two registry specific checks. When the entry carries an npm package it then runs the full `smithmark verify` pipeline against that package, discovering the attestation through the D3 deterministic OCI reference (section 6.3) because the registry offers no pointer, and merges the registry checks into the same `VerificationReport` verify itself produces. When the entry has no npm package it returns just the two registry checks.

**The two checks, both informational (they never drive an exit code, per smithmark decision D4):**

- **`REGISTRY_ATTESTATION_REF_PRESENT`.** Passes only if the entry carries an attestation reference field. No real entry does today, so it fails for every entry the command has ever fetched, with this detail:

  > this MCP Registry entry carries no attestation reference field; that field does not exist in the registry schema today, which is the gap the MCP Registry provenance RFC proposes to close

  This is the measured gap. The check is not a placeholder that always returns false: it reads the entry's decoded `attestations` slot (a field the smithmark client already models in anticipation) and passes the moment a real entry carries a present, non empty reference. The day the registry adds the field and a publisher populates it, this check turns green against that entry with no code change. That is the demonstration's whole point: the tool is built to reward the change it asks for.

- **`HOSTED_ENDPOINT_UNSUPPORTED`.** Passes when the entry carries an npm package smithmark can verify. It fails, informationally, for a remote only entry, a non npm distribution, or an entry with no distribution at all, each with a distinct detail. This encodes smithmark decision D5: v0.1 attests and verifies artifact distributed servers only, and a hosted, remote only entry is reported as an informational limitation, never an error. It is the honest boundary of what the demonstration covers, and it is where the AID trust at first contact work (issue #406) and smithmark's own deferred hosted endpoint phase would eventually meet.

**What the demonstration proves.** Run against `io.github.sns45/better-call-claude` or `io.github.sns45/dear-claude`, the command shows the registry cannot answer "where is this server's capability attestation," so smithmark computes the answer itself from the npm identity via D3, fetches the attestation, verifies the signature and the subject digest, and reports the capability posture, all while flagging that the registry entry itself carried no reference. The proposed field would let the entry carry that answer directly, and verify on publish would let the registry make the same check smithmark makes, at publish time, for every consumer at once. The gap is not hypothetical; it is a failing check with a stable code, run against live entries, today.

---

## 8. Worked examples: two real, published servers

Both worked example servers are real, publish the `2025-12-11` schema, and have honest, signed capability declarations in the smithmark reference implementation (`testdata/servers/*/smithmark.yaml`, authored by reading the vendored source and verified by `smithmark verify`; the same two servers the TC54 proposal uses).

**`io.github.sns45/better-call-claude` 3.1.1** distributes as npm `better-call-claude`, transport stdio, and its `server.json` lists twelve environment variables. Its real capability surface, which the registry entry cannot state, includes egress to `api.twilio.com`, `api.telnyx.com`, `api.openai.com`, `*.whatsapp.net`, and `api.anthropic.com`; exec of `claude`, `tailscale`, and `sudo`; and secrets of kind `api-key` for twilio, telnyx, and openai. The registry entry carries the env var names and the npm `fileSha256` equivalent integrity, and nothing that says this server places phone calls or spawns a permission bypassed subprocess. The attestation reference this RFC proposes would point at the signed statement that does say exactly that.

**`io.github.sns45/dear-claude` 1.1.0** distributes as npm `dear-claude`, transport stdio, and its `server.json` lists twenty four environment variables spanning GitHub, Linear, Jira, GitLab, and Notion credentials. Its real surface includes egress to `api.github.com`, `gitlab.com`, `*.atlassian.net`, and, transitively through a spawned `claude`, `api.anthropic.com` and `api.giphy.com`; filesystem access under `${home}/.dear-claude/**`; and fifteen secrets. As the smithmark dogfood friction log records (`docs/decisions.md`, U8), the registry `server.json` schema carries no tool listing at all, so even the tools this server exposes are absent from the entry; they live in the source and in the attestation smithmark produces. A provenance aware registry entry that referenced the capability attestation would carry (by reference) the tool listing and the full capability surface the schema does not surface today.

These two are the concrete stakes. A client resolving either entry by name today is trusting reputation. With the referenced attestation and verify on publish, the client, and the registry, could instead trust a signed, digest bound declaration.

---

## 9. Security framing: the agent tool supply chain

### 9.1 OWASP Top 10 for Agentic Applications, ASI04

The OWASP Top 10 for Agentic Applications (2026 edition, released 2025-12-09 by the OWASP GenAI Security Project) names `ASI04` Agentic Supply Chain Vulnerabilities as a top risk. Pulling an agent tool by name and trusting it by reputation, with no signed statement of provenance or capability bound to the artifact, is precisely this risk. An attestation reference on the registry entry plus verify on publish is a preventive and detective control for it: the referenced attestation is a signed, digest bound supply chain artifact; verify on publish gives the registry the facts to refuse or flag an entry whose attestation does not authenticate or does not bind to the published artifact; and the recorded outcome is durable, attributable audit evidence (touching `T8` Repudiation and Untraceability in the companion OWASP threats and mitigations taxonomy). The capability surface the referenced predicate declares also gives a downstream policy engine leverage over `ASI02` Tool Misuse, `ASI03` Identity and Privilege Abuse, and `ASI05` Unexpected Code Execution, the same mapping the TC54 proposal details. The honest scope is the same as that proposal's: a published capability attestation does not address runtime and multi agent risks (`ASI07`, `ASI08`, `ASI09`); the contribution concentrates on the supply chain and admission risks, and most directly on `ASI04`.

### 9.2 EU Cyber Resilience Act

The EU Cyber Resilience Act, Regulation (EU) 2024/2847, imposes essential cybersecurity requirements and technical documentation obligations on products with digital elements, with the main obligations applying from 11 December 2027. A signed capability attestation, referenced from the registry entry and checked at publish, is machine readable technical documentation of exactly the kind those obligations call for: it states in an attestable form what an artifact is capable of and binds that statement to a specific build by digest. The claim is deliberately modest, matching the companion proposal: this is supporting evidence toward CRA aligned documentation, not a conformity guarantee.

---

## 10. What is implemented versus proposed

Stated plainly, so the reader knows what exists and what is being asked for.

### 10.1 Implemented today (the reference implementation)

- `smithmark registry check`, which fetches real MCP Registry entries, reports `REGISTRY_ATTESTATION_REF_PRESENT` (failing for every real entry) and `HOSTED_ENDPOINT_UNSUPPORTED`, and runs the full verification pipeline against npm backed entries (`pkg/discover/registry.go`, `cmd/smithmark/registry.go`).
- The deterministic OCI reference scheme of section 6.3 (smithmark decision D3), which discovers attestations from package identity with no registry cooperation.
- The `agent-capability/v1` in-toto DSSE predicate the reference would point at, signed with Sigstore and verified by `smithmark verify`, with two real signed capability declarations for the section 8 servers.

### 10.2 Proposed here (the standards deliverable)

- The attestation reference field on registry entries (section 6.1), first class and in an interim `_meta` form.
- Verify on publish semantics (section 6.2).

The smithmark client already models the reference field it hopes to read (`RegistryEntry.HasAttRef`, decoded from an `attestations` slot), so the reference implementation is ready to consume the field the day the registry ships it. That is deliberate: the tool demonstrates the gap and is built to close against the fix.

---

## 11. Design questions for the maintainers

Recorded honestly, so the proposal is adopted with eyes open.

1. **Field placement.** First class `attestations` array versus a `_meta` extension for the pilot. This RFC recommends piloting under `_meta` and promoting to first class once the shape settles. Which does the registry prefer for the durable form?
2. **One reference or many.** An entry may warrant both a capability attestation and a build provenance attestation (npm or SLSA). The array shape supports both via `type`; is a single typed array the right model, or should provenance and capability references be distinct fields?
3. **How strict is verify on publish at launch.** Record only, block on failure, or block only for opt in namespaces. The staged rollout in section 6.2 exists to defer this, but the maintainers own the policy.
4. **Transport of the referenced attestation.** `oci://` is the expected default today; `https://` bundles and future transports should remain valid. Should the registry constrain the transport, or accept any and verify by digest?
5. **Relationship to the `verified` field (issue #823) and scan metadata (issue #1273).** These are complementary signals. Should a verified capability attestation be one input to the `verified` badge, and should the attestation reference and the scan metadata field share a design so consumers read trust signals uniformly?

None of these blocks the core asks; they scope the durable design.

---

## 12. Submission path

The MCP project runs a defined process, verified on 2026-07-18.

**Near term, registry Discussion.** The registry `CONTRIBUTING` guidance routes product and technical requirements through GitHub Discussions on `modelcontextprotocol/registry` before implementation. The first step is a Discussion that states the gap (section 2), links this RFC, and explicitly relates the proposal to the open issues it neighbors: the `verified` field (#823), the security scan metadata field (#1273), and trust at first contact (#406). Framing the attestation reference as one member of a family of trust signals the registry is already discussing is the honest and productive entry.

**The schema change, as a SEP.** Changes to the specification and to the `server.json` schema flow through the Specification Enhancement Proposal process (documented at `modelcontextprotocol.io/seps`; the workflow is defined in SEP-1850 and has been pull request based since November 2025). A SEP carries a concise technical specification and rationale, gathers community review, and, if accepted, ships in a subsequent specification and schema release. The `server.json` schema already tracks JSON Schema 2020-12 (SEP-1613), so the `attestations` field of section 6.1 is expressible in the schema's own dialect. This RFC is written to become the rationale section of that SEP with minimal reshaping.

**The pilot needs neither.** Because the interim `_meta` form (section 6.1) rides the existing vendor extension mechanism, a publisher can begin carrying the reference today, and `smithmark registry check` can begin reading it, before any Discussion concludes or any SEP merges. Running signal from a real pilot is the strongest input to both the Discussion and the SEP.

Treat the venue as time sensitive. The issue tracker shows the registry maintainers are actively discussing adjacent trust signals right now, and concurrent academic proposals are circling the same provenance gap. A shipping reference implementation that already measures the gap against live entries is the strongest position from which to propose the field.

---

## References

All accessed 2026-07-18 unless noted.

**The registry, its schema, and its API (the target of this RFC):**

- MCP Registry repository: `https://github.com/modelcontextprotocol/registry`
- `server.json` schema, version `2025-12-11` (the version every live entry references): `https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`
- `server.json` format documentation: `https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md`
- Registry REST API OpenAPI description (publish and get server version operations): `https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/openapi.yaml`
- Live API confirmation: `https://registry.modelcontextprotocol.io/v0/servers` returned entries on the `2025-12-11` schema with no attestation field, 2026-07-18.

**Active registry proposals this RFC relates to:**

- Issue #823, request for a `verified` publisher field: `https://github.com/modelcontextprotocol/registry/issues/823`
- Issue #1273, proposal for optional security scan metadata: `https://github.com/modelcontextprotocol/registry/issues/1273`
- Issue #406, trust at first contact via AID DNS record and key handshake: `https://github.com/modelcontextprotocol/registry/issues/406`
- Issues #356 and #292, the reverse DNS namespaced `_meta` vendor extension mechanism: `https://github.com/modelcontextprotocol/registry/issues/356`

**Concurrent academic work (surfaced by search, 2026-07-18):**

- Attested Tool-Server Admission, a security extension to MCP: `https://arxiv.org/abs/2605.24248`
- The Trustworthy Model Context Protocol Registry (architectural blueprint for cryptographic provenance): `https://doi.org/10.3390/fi18050243`
- Cryptographic Registry Provenance against dependency confusion in AI package ecosystems: `https://arxiv.org/abs/2605.03309`

**The MCP proposal process:**

- Specification Enhancement Proposals: `https://modelcontextprotocol.io/seps`
- Registry contribution guidance (Discussions before implementation): `https://github.com/modelcontextprotocol/registry/blob/main/CONTRIBUTING.md`

**Security and regulatory framing:**

- OWASP Top 10 for Agentic Applications, 2026 edition (released 2025-12-09), `ASI04` Agentic Supply Chain Vulnerabilities: `https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/`
- EU Cyber Resilience Act, Regulation (EU) 2024/2847 (main obligations apply 11 December 2027): `https://eur-lex.europa.eu/eli/reg/2024/2847/oj`

**smithmark, the reference implementation:**

- `smithmark registry check` implementation: `pkg/discover/registry.go`, `cmd/smithmark/registry.go`, and `pkg/core/verify/verify.go` (the `RegistryChecks` function)
- Machine readable codes, including `REGISTRY_ATTESTATION_REF_PRESENT` and `HOSTED_ENDPOINT_UNSUPPORTED`: `docs/codes.md`
- Decision D3 (the deterministic OCI reference scheme, quoted in section 6.3), decision D5 (hosted endpoint deferral), decision D6 (the predicate schema), and U8 (the dogfood friction log, including the missing tool listing): `docs/decisions.md`
- Phase 0 registry investigation and the confirmed gap: `docs/research/notes/mcp-registry.md`
- Whitespace sweep (prior art landscape and the confirmed registry gap): `docs/research/whitespace-sweep.md`
- Companion TC54 proposal (the CycloneDX taxonomy the referenced attestation projects into): `proposals/cyclonedx-agent-capability/PROPOSAL.md`
- The two real capability declarations used as worked examples: `testdata/servers/better-call-claude/smithmark.yaml`, `testdata/servers/dear-claude/smithmark.yaml`
