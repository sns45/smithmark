# CycloneDX agent capability property taxonomy

**A proposal to register the `in8` top level namespace and adopt the `in8:agent:capability:*` property taxonomy for machine readable, attestable capability declarations of MCP servers and skills.**

| | |
|---|---|
| Status | Draft for community review |
| Target venue | Ecma TC54 / CycloneDX (property taxonomy registration; longer term, an official capability taxonomy) |
| Base specification | CycloneDX 1.7 (2025-10-21); the CycloneDX specification is standardized by Ecma International as ECMA-424 (first edition 2024 covered 1.6; the edition covering 1.7 was published 2025-12-10) |
| Reference implementation | smithmark (`github.com/sns45/smithmark`), the `agent-capability/v1` in-toto predicate and CLI |
| Predicate lockstep version | `https://in8.sh/attestation/agent-capability/v1`, `schemaVersion` 1.0.0 |
| Author | smithmark maintainer |
| Sources verified | 2026-07-18 (see the References section) |

> The tool is the reference implementation of this proposal, not the other way around. Every property in the taxonomy below is a projection of a field that smithmark already emits, signs, and verifies today; the two real worked examples are the honest capability declarations of two shipping MCP servers, attested and verified by the reference implementation.

---

## 1. Summary and the ask

Agent tools, meaning MCP servers and skill bundles, are installed the way container images were installed in 2015: pulled by name, trusted by reputation. An MCP server can place phone calls, read a filesystem, spawn subprocesses, and reach credentialed network endpoints. Nothing standard travels with the artifact that states, in a machine readable and cryptographically attestable form, what the tool is capable of, so every consumer must reinspect from scratch and no policy engine can reason over a portable declaration.

smithmark already closes this gap at the attestation layer. It emits a signed in-toto DSSE statement whose predicate, `https://in8.sh/attestation/agent-capability/v1`, declares an agent tool's capability surface (network egress, filesystem, exec, environment, secrets) plus its MCP or skill surface. That predicate is implemented, signed with Sigstore, and verified by the `smithmark verify` command; it is the source of truth.

What does not yet exist is a **standard place in the SBOM world** for the same facts, so that a CycloneDX native policy engine or registry can read an agent tool's declared capabilities without parsing a bespoke predicate. CycloneDX is the natural home: it already models components, hashes, external references, and package URLs, and since version 1.3 it has carried an extensible name/value **property** mechanism governed by a community property taxonomy. It has no taxonomy for agent tool capabilities. CycloneDX issue #895 (Agent BOM, March 2026) asked for exactly this framing, "what components make up this autonomous agent and what is it authorised to do", and was closed as a duplicate without defining a taxonomy, so the slot is open and demand is documented.

**The ask, in three parts:**

1. **Reserve the `in8` top level namespace** in the CycloneDX property taxonomy registry, via the repository's documented issue based process.
2. **Adopt the `in8:agent:capability:*` property taxonomy** defined in section 6 of this document as the public taxonomy documentation for that namespace. It maps every field of the `agent-capability/v1` predicate either to a native CycloneDX construct or to one property, mechanically and losslessly for policy purposes.
3. **Consider, longer term, promoting the agent capability surface to an official CycloneDX taxonomy or profile** through the Ecma TC54 standardization process, so the capability declaration becomes a first class part of the specification rather than a vendor namespace.

The near term ask (parts 1 and 2) is available immediately and matches how dozens of organizations already extend CycloneDX. The longer term ask (part 3) is a multi step standardization effort described in section 12.

---

## 2. The problem, stated with named prior art

The novelty here is narrow and demonstrable, not asserted. Signed capability declarations for agent tools already exist in pieces; what is missing is a portable, standard, capability declaration that a CycloneDX native consumer can read. The `docs/research/whitespace-sweep.md` landscape study (fourteen swept items, accessed 2026-07-16) records the neighbors and where each one stops:

- **Enclawed** (arXiv 2605.00424, implemented) signs skill manifests with a fixed capability vocabulary and denies any capability not declared, but it covers skills only, mints its own Ed25519 trust root, and its gate is its own runtime rather than a portable attestation an external policy engine consumes.
- **studiomeyer-io/mcp-server-attestation** signs an MCP server's tool and spawn allowlist under trust on first use, but network egress, filesystem, and secrets are explicitly out of scope, and there is no skills coverage and no standard emission format.
- **ETDI** (arXiv 2506.01333) binds tool definitions to signed JWTs whose capabilities are OAuth scopes, verified client side at discovery, not published as a portable artifact; its upstream MCP SDK contribution was closed unmerged.
- **CycloneDX issue #895** asked for an Agent BOM covering what an agent is authorised to do and was closed as a duplicate with no taxonomy defined.

Scanners inspect one install at a time and emit findings, not declarations. Registries curate and sign their own inventory, but the signature says nothing about what the artifact may do. Provenance (npm provenance, SLSA) proves build origin and never capability. The near neighbors that do sign a capability declaration each mint a bespoke trust root, bundle their own gate, cover one artifact kind, and emit a private format. None of that evidence travels into the CycloneDX ecosystem where SBOM aware policy engines already live.

This proposal does not claim to invent capability declarations. It claims one specific, unoccupied thing: a **standard CycloneDX taxonomy** for agent tool capabilities, kept in lockstep with a portable signed predicate that already composes npm provenance, Sigstore, SLSA, and CycloneDX rather than replacing them. That claim is falsifiable and remains open; a single prior taxonomy in CycloneDX (or any SBOM standard) for agent tool capabilities would falsify it, and the sweep found none.

---

## 3. Relationship to the in-toto predicate (lockstep, not duplication)

smithmark's primary artifact is an in-toto Statement v1 whose predicate type is `https://in8.sh/attestation/agent-capability/v1`. This proposal does **not** replace that predicate; it projects it.

- **The predicate is the implementation and the source of truth.** It is strict parsed (unknown fields are errors in both directions), canonicalized under RFC 8785, and signed. It carries the full structure, including the human readable `reason` prose on each egress, filesystem, and exec rule.
- **The property taxonomy is the standards projection.** It is a flat, policy queryable index of the same facts, expressed in the CycloneDX property model so that a consumer already parsing an SBOM can read declared capabilities without a second parser.
- **They are kept in lockstep by a version anchor.** The property `in8:agent:capability:schemaVersion` carries the exact predicate `schemaVersion` (`1.0.0` today). A consumer reads that property to know which taxonomy revision produced the rest, and a producer that bumps the predicate schema bumps the property in the same change.
- **Direction of travel.** Today the predicate is primary and the taxonomy is a documented projection. If TC54 adopts the taxonomy as an official capability declaration format, smithmark's v2 makes the CycloneDX representation primary and the in-toto predicate the secondary carrier. That is a deliberate, staged plan, recorded in the smithmark specification section 2.3, not a hedge.

Because the predicate remains lossless, no fidelity is lost by keeping the property values compact. Where a property value carries only the policy actionable subset of a rule (for example a host and its ports, without the free text reason), the full rule is recoverable from the predicate, which the BOM references by digest. This is the intended division of labor: **properties for matching, the predicate for provenance prose.**

---

## 4. How CycloneDX properties work (verified against the source)

The following is quoted or paraphrased from the CycloneDX property taxonomy repository README (`github.com/CycloneDX/cyclonedx-property-taxonomy`, accessed 2026-07-18) and the CycloneDX specification. It is the mechanism this proposal builds on, stated so a reviewer can check the taxonomy against the real rules.

- A CycloneDX **property** is a name/value pair. Properties attach to a `component`, to `metadata`, and to several other object types, and the same property name **may repeat**, which is how a property carries a list.
- A property **name** may be prefixed by a **namespace**. Quoting the README: "A namespace is a hierarchical sequence of segments separated by colons. The first segment is the top-level namespace; subsequent segments are sub-namespaces." So `in8:agent:capability:networkEgress` has top level namespace `in8`, nested segments `agent` and `capability`, and local name `networkEgress`.
- **Character rules** (quoted): "Names and namespace segments MUST NOT contain `:`." and "The only characters that SHALL be used in official property namespace segments and names are alphanumerical characters, `-`, `_` and ` ` from the US ASCII character set." Also: "Namespaces SHOULD be lower case. Names MAY use upper case." Every name in this taxonomy is alphanumeric (`networkEgress`, `schemaVersion`, `invokesTools`), so it satisfies the rule; property **values** are unrestricted strings, which is where host patterns, paths, and secret identifiers live.
- **Registration** (quoted): "The process for registering a new top-level namespace is to create a new issue requesting it." "Registered top-level namespaces SHOULD be more than two characters long." (`in8` is three characters.) A reserved namespace must publish its taxonomy documentation before use: "Before using your `RESERVED` namespace, documentation for the taxonomy of the namespace SHOULD be publicly available", and "Failure to do so MAY result in the namespace reservation being revoked."
- **Where taxonomy docs live.** The registry holds one example taxonomy file (`cdx.md`) in the repository, but most registered namespaces link out to documentation the owning organization hosts in its own repository. This proposal is that documentation for `in8`; it lives in the smithmark repository under `proposals/` and versions with the reference implementation.

A key consequence: several predicate fields have a **better home in native CycloneDX than in a property**, and the taxonomy uses it. Component identity is not invented as a property when `name`, `version`, and `purl` already exist; digests are not invented as properties when `hashes` exists; the dependency SBOM is an `externalReferences` entry of type `bom`, not a property. The new namespace carries only what CycloneDX has no native slot for: the capability surface itself. That boundary is exactly the standards gap this proposal fills.

---

## 5. Mapping principle (mechanical and auditable)

Every field of the `agent-capability/v1` predicate is accounted for by one of two rules, so the mapping can be checked field by field rather than trusted.

**Rule A, native CycloneDX construct.** Identity, digests, timestamps, the producing tool, and the dependency SBOM map to constructs CycloneDX already defines.

**Rule B, `in8:agent:capability:*` property.** Everything describing the capability or surface maps to a property whose name is derived mechanically: take the predicate JSON path, drop array indices, join segments with `:`, prefix `in8:agent:capability:`, and elide the single `capabilities` container segment (the namespace already encodes it). A repeated array element becomes a repeated property of the same name.

Worked transform examples:

| Predicate JSON path | Property name |
|---|---|
| `schemaVersion` | `in8:agent:capability:schemaVersion` |
| `artifact.kind` | `in8:agent:capability:artifact:kind` |
| `capabilities.networkEgress[2]` | `in8:agent:capability:networkEgress` (3rd instance) |
| `capabilities.filesystem[0].access` + `.path` | `in8:agent:capability:filesystem` (value encodes both) |
| `mcp.transports[0]` | `in8:agent:capability:mcp:transports` |
| `skill.invokesTools[0]` | `in8:agent:capability:skill:invokesTools` |

---

## 6. The `in8:agent:capability:*` property taxonomy

### 6.1 Native CycloneDX mappings (Rule A)

| Predicate field | CycloneDX construct | Notes |
|---|---|---|
| `artifact.name` | `component.name` | |
| `artifact.version` | `component.version` | |
| `artifact.name` + `artifact.source` | `component.purl` | `pkg:npm/name@version` for npm, `pkg:pypi/...` for PyPI, per the predicate's own subject naming; `local` and `mcp-registry` sources have no purl type and rely on the `artifact:source` property below |
| in-toto statement subject digest | `component.hashes[]` | for example `{ "alg": "SHA-512", "content": "<tarball sha512 hex>" }`; skills use the `smithmark-bundle-v1` bundle digest |
| `skill.entryDigest` | `component.hashes[]` on the skill's SKILL.md subcomponent | |
| `mcp.tools[].inputSchemaDigest` | `hashes[]` on a nested tool subcomponent | sha256 over the RFC 8785 canonical JSON of the tool input schema |
| `dependencies.sbomDigest` + `sbomFormat` + `locator` | `externalReferences[]` with `"type": "bom"`, the `locator` as `url`, and the digest in `hashes[]` | the dependency SBOM is itself a CycloneDX (forgeseal) document |
| `generatedAt` | `metadata.timestamp` | assumes one attested component per BOM (see note) |
| `generator.name` + `generator.version` | `metadata.tools.components[]` (name, version) | the tool that produced the manifest; assumes one attested component per BOM (see note) |

**Note on one attestation per BOM.** `metadata.timestamp` and `metadata.tools` are BOM level, one per document, so these two native mappings assume a single attested agent tool per BOM, which is smithmark's model (one capability manifest, one artifact). A BOM that aggregates several attested tools cannot carry a per component timestamp and producer through `metadata`; in that case a producer projects `generatedAt` and `generator` onto per component properties (`in8:agent:capability:generatedAt` and `in8:agent:capability:generator`, value `name@version`) instead. The single artifact BOM is the common and recommended shape.

### 6.2 Capability and surface properties (Rule B)

All properties below attach to the `component` that represents the agent tool. Array valued predicate fields become repeated properties. Property values follow the documented grammars; values are ordinary strings and may contain any character (colons in `kind:provider` and `sha256:` are fine because the colon rule constrains only names).

| Predicate field | Property name | Cardinality | Value grammar | Example value |
|---|---|---|---|---|
| `schemaVersion` | `in8:agent:capability:schemaVersion` | 1 | semver | `1.0.0` |
| `artifact.kind` | `in8:agent:capability:artifact:kind` | 1 | `mcp-server` \| `skill` | `mcp-server` |
| `artifact.source` | `in8:agent:capability:artifact:source` | 1 | `npm` \| `oci` \| `pypi` \| `local` \| `mcp-registry` | `npm` |
| `capabilities.networkEgress[]` | `in8:agent:capability:networkEgress` | 0..n | `host` optionally followed by a single space and a comma joined port list | `api.twilio.com 443` |
| `capabilities.filesystem[]` | `in8:agent:capability:filesystem` | 0..n | `access` (one of `read`, `write`, `readwrite`), a single space, then `path` | `readwrite data/baileys-auth/**` |
| `capabilities.exec[]` | `in8:agent:capability:exec` | 0..n | `binary` basename pattern | `claude` |
| `capabilities.env[]` | `in8:agent:capability:env` | 0..n | environment variable name | `BETTERCALLCLAUDE_PORT` |
| `capabilities.secrets[]` | `in8:agent:capability:secrets` | 0..n | `kind:provider` | `api-key:twilio` |
| `mcp.transports[]` | `in8:agent:capability:mcp:transports` | 0..n | `stdio` \| `http` \| `sse` | `stdio` |
| `mcp.tools[].name` | `in8:agent:capability:mcp:tools` | 0..n | tool name (the input schema digest is carried natively per 6.1) | `initiate_call` |
| `mcp.resources[]` | `in8:agent:capability:mcp:resources` | 0..n | resource identifier | |
| `mcp.prompts[]` | `in8:agent:capability:mcp:prompts` | 0..n | prompt identifier | |
| `skill.invokesTools[]` | `in8:agent:capability:skill:invokesTools` | 0..n | tool or binary name | |
| `skill.scripts[]` | `in8:agent:capability:skill:scripts` | 0..n | `mode` (one of `regular`, `executable`), a single space, then `path` (the file digest is carried natively per 6.1) | `executable scripts/build.sh` |

**On the `reason` field.** Each egress, filesystem, and exec rule in the predicate carries an optional free text `reason`. It is deliberately not projected into the property value, because a property value is meant for policy matching and the reasons are provenance prose. They remain in the predicate, which the BOM references by digest. A consumer that needs the reason dereferences the predicate. This keeps the property values greppable and the declaration lossless.

**Completeness check.** Every predicate field is now accounted for: `schemaVersion`, `artifact.{kind,name,version,source}`, `mcp.{transports,tools,resources,prompts}`, `skill.{entryDigest,scripts,invokesTools}`, `capabilities.{networkEgress,filesystem,exec,env,secrets}`, `dependencies.{sbomDigest,sbomFormat,locator}`, `generatedAt`, and `generator.{name,version}`. Nothing in the predicate is unmapped.

---

## 7. Worked example 1: better-call-claude 3.1.1

This is the real, committed capability declaration of better-call-claude 3.1.1 (`testdata/servers/better-call-claude/smithmark.yaml`), an MCP server that places phone calls and sends SMS and WhatsApp messages through Twilio and Telnyx. It was authored by reading the vendored source, attested with the dogfood key, and verified. Below is the same declaration projected into a CycloneDX component. Digest and SBOM values are elided placeholders; the fixture uses a documented stand in `sha512` per the smithmark dogfood notes, and the real release path fills them from the published tarball and the forgeseal SBOM.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "metadata": {
    "timestamp": "2026-07-17T00:00:00Z",
    "tools": {
      "components": [
        { "type": "application", "name": "smithmark", "version": "0.1.0" }
      ]
    }
  },
  "components": [
    {
      "type": "application",
      "name": "better-call-claude",
      "version": "3.1.1",
      "purl": "pkg:npm/better-call-claude@3.1.1",
      "hashes": [
        { "alg": "SHA-512", "content": "<tarball sha512 hex from the in-toto statement subject>" }
      ],
      "externalReferences": [
        {
          "type": "bom",
          "url": "better-call-claude-3.1.1.sbom.json",
          "hashes": [ { "alg": "SHA-256", "content": "<forgeseal CycloneDX SBOM sha256>" } ]
        }
      ],
      "properties": [
        { "name": "in8:agent:capability:schemaVersion", "value": "1.0.0" },
        { "name": "in8:agent:capability:artifact:kind", "value": "mcp-server" },
        { "name": "in8:agent:capability:artifact:source", "value": "npm" },

        { "name": "in8:agent:capability:mcp:transports", "value": "stdio" },

        { "name": "in8:agent:capability:networkEgress", "value": "api.twilio.com 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "messaging.twilio.com 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "api.telnyx.com 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "api.openai.com 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "*.whatsapp.net 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "web.whatsapp.com 443" },
        { "name": "in8:agent:capability:networkEgress", "value": "api.anthropic.com 443" },

        { "name": "in8:agent:capability:filesystem", "value": "readwrite data/baileys-auth/**" },
        { "name": "in8:agent:capability:filesystem", "value": "write ${tmp}/bcc-spawn-*" },

        { "name": "in8:agent:capability:exec", "value": "claude" },
        { "name": "in8:agent:capability:exec", "value": "tailscale" },
        { "name": "in8:agent:capability:exec", "value": "which" },
        { "name": "in8:agent:capability:exec", "value": "open" },
        { "name": "in8:agent:capability:exec", "value": "sudo" },

        { "name": "in8:agent:capability:env", "value": "BETTERCALLCLAUDE_OPENAI_API_KEY" },
        { "name": "in8:agent:capability:env", "value": "BETTERCALLCLAUDE_PHONE_ACCOUNT_SID" },
        { "name": "in8:agent:capability:env", "value": "BETTERCALLCLAUDE_PHONE_AUTH_TOKEN" },
        { "name": "in8:agent:capability:env", "value": "BETTERCALLCLAUDE_PORT" },

        { "name": "in8:agent:capability:secrets", "value": "api-key:twilio" },
        { "name": "in8:agent:capability:secrets", "value": "api-key:telnyx" },
        { "name": "in8:agent:capability:secrets", "value": "api-key:openai" }
      ]
    }
  ]
}
```

The `env` properties are abbreviated to four of the nineteen the real declaration carries; the full set repeats the property once per variable. A CycloneDX native policy engine can now express, for example, "admit this server only if every `in8:agent:capability:networkEgress` host is on the messaging allowlist and no `in8:agent:capability:exec` value is `sudo`", reading nothing but standard properties. Note that `sudo` is genuinely declared here, which is exactly the kind of fact a gate should be able to see.

---

## 8. Worked example 2: dear-claude 1.1.0, and where the taxonomy strains

dear-claude 1.1.0 (`testdata/servers/dear-claude/smithmark.yaml`) is an MCP server that touches GitHub, Linear, GitLab, Jira, and Notion and spawns Claude Code. Its real declaration exercises the parts of the taxonomy where the v1 grammar is honest but coarse. The excerpt below shows the representative properties; the full component carries nine `networkEgress`, four `filesystem`, six `exec`, twenty nine `env`, and fifteen `secrets` properties.

```json
{
  "type": "application",
  "name": "dear-claude",
  "version": "1.1.0",
  "purl": "pkg:npm/dear-claude@1.1.0",
  "properties": [
    { "name": "in8:agent:capability:schemaVersion", "value": "1.0.0" },
    { "name": "in8:agent:capability:artifact:kind", "value": "mcp-server" },
    { "name": "in8:agent:capability:artifact:source", "value": "npm" },
    { "name": "in8:agent:capability:mcp:transports", "value": "stdio" },

    { "name": "in8:agent:capability:networkEgress", "value": "api.github.com 443" },
    { "name": "in8:agent:capability:networkEgress", "value": "gitlab.com 443" },
    { "name": "in8:agent:capability:networkEgress", "value": "*.atlassian.net 443" },
    { "name": "in8:agent:capability:networkEgress", "value": "api.anthropic.com 443" },
    { "name": "in8:agent:capability:networkEgress", "value": "api.giphy.com 443" },

    { "name": "in8:agent:capability:filesystem", "value": "readwrite ${home}/.dear-claude/**" },
    { "name": "in8:agent:capability:filesystem", "value": "readwrite data/**" },
    { "name": "in8:agent:capability:filesystem", "value": "read ${home}/.claude.json" },
    { "name": "in8:agent:capability:filesystem", "value": "write ${tmp}/dear-claude-debug.log" },

    { "name": "in8:agent:capability:exec", "value": "claude" },

    { "name": "in8:agent:capability:secrets", "value": "access-token:github" },
    { "name": "in8:agent:capability:secrets", "value": "private-key:github" },
    { "name": "in8:agent:capability:secrets", "value": "webhook-secret:linear" }
  ]
}
```

Four honest limitations are visible in this single example, and section 9 records them as open taxonomy questions rather than papering over them:

- `gitlab.com 443` is the **default** host; dear-claude lets `GITLAB_URL` point at any self hosted instance. The v1 grammar has no "configurable, defaults to X" form, so the conservative default is declared and the override lives in the predicate reason. A bare `*` would be dishonestly broad.
- `*.atlassian.net 443` uses the leftmost wildcard form because the Jira subdomain is the tenant, chosen at runtime by `JIRA_DOMAIN`. The wildcard is honest here but coarser than the real constraint.
- `api.anthropic.com 443` and `api.giphy.com 443` are **transitive** egress: they are reached by the `claude` subprocess dear-claude spawns, not by a direct `fetch`. The taxonomy records them as ordinary egress with the transitivity noted only in the predicate reason; there is no first class "transitive" marker.
- `${home}/.dear-claude/**` and `data/**` are declared concretely, but dear-claude also reads a GitHub App private key from whatever absolute path `GITHUB_APP_PRIVATE_KEY_PATH` names and watches an Obsidian vault at `OBSIDIAN_VAULT_PATH`. The v1 filesystem grammar cannot express "an arbitrary absolute path supplied at runtime by an environment variable" without the dishonestly broad `**`, so those paths are recorded as a gap, not declared.

These are not defects in the projection; the property faithfully carries whatever the predicate declares. They are limits of the underlying **capability grammar**, surfaced by real product code, and they are precisely the input a standards body needs.

---

## 9. Documented limitations and open questions for TC54

Recorded honestly, from the smithmark dogfood friction log (`docs/decisions.md`, U8), so the taxonomy is adopted with eyes open. Each item is a candidate for a v2 grammar extension.

1. **Environment variable driven filesystem paths.** There is no way to say "an absolute path named at runtime by env var `X`". Candidate: a `path` form that references an `env` entry, for example `env:GITHUB_APP_PRIVATE_KEY_PATH`.
2. **Transitive versus direct capability.** A capability reached through a spawned subprocess or an SDK is indistinguishable from a direct one. Candidate: an optional `transitive` qualifier, and a way to record that a spawned process (here, `claude`) runs with permissions bypassed, a fact that today has no schema home and lives only in prose.
3. **Configurable destinations with a default.** `GITLAB_URL` style overrides have no representation. Candidate: a `default:` marker on a host or path.
4. **Capabilities hidden behind SDKs and libraries.** better-call-claude's WhatsApp egress runs through a library whose concrete hosts are not source literals; the declaration is honest only because the author knows the library's endpoints. A purely static reading could not produce them. This bounds what any automated capability extractor can promise and should be stated in the taxonomy's conformance notes.
5. **Secret vocabulary is unconstrained.** The `kind:provider` grammar is validated but the `kind` vocabulary is open, so `api-key:twilio` versus `account-sid:twilio` is author judgment. A registered, extensible `kind` vocabulary would make secret properties comparable across tools.
6. **Class level detection, not per destination.** smithmark's capability lint (the declared versus detected gap engine) suppresses a class once any entry of that class is declared, because the static detectors match constructs like `fetch`, not resolved hosts. So the taxonomy can be checked for an entirely undeclared class but not for an under declared subset within a class; per host completeness is carried by authorial principle, not enforced. This is a documented precision boundary of static analysis, not a false negative in the taxonomy.
7. **The registry does not surface the tool listing.** The MCP Registry `server.json` schema carries packages, transports, and environment variable names, but no tools array, so the `mcp:tools` properties come from the server source, not from the registry entry. This is the seam the companion MCP Registry provenance RFC addresses.

None of these blocks adoption of the taxonomy as it stands; the properties describe real, declared capabilities of real servers today. They scope what v1 promises and set the agenda for v2.

---

## 10. OWASP Agentic Security mapping

**Source and version.** OWASP Top 10 for Agentic Applications, 2026 edition, released 2025-12-09 by the OWASP GenAI Security Project (Agentic Security Initiative). Risk identifiers `ASI01` through `ASI10`. The companion OWASP Agentic AI Threats and Mitigations taxonomy (identifiers `T1` through `T15`) was updated to v1.1 and synchronized with the Top 10 in the same release. Both accessed 2026-07-18. The official list is used verbatim; note that some third party summaries circulate a divergent renumbering, which is not used here.

The ten risks, titles verbatim from the OWASP list: `ASI01` Agent Goal Hijack, `ASI02` Tool Misuse, `ASI03` Identity & Privilege Abuse, `ASI04` Agentic Supply Chain Vulnerabilities, `ASI05` Unexpected Code Execution, `ASI06` Memory & Context Poisoning, `ASI07` Insecure Inter-Agent Communication, `ASI08` Cascading Failures, `ASI09` Human-Agent Trust Exploitation, `ASI10` Rogue Agents.

A capability declaration is a preventive and detective control: it gives a policy engine the facts to deny an admission that would enable a risk, and it gives lint the declared baseline to flag a gap. The mapping below states, per smithmark mechanism, which risk it gives leverage over.

| smithmark mechanism (property or check) | Primary ASI risk | Secondary | How the declaration helps |
|---|---|---|---|
| `in8:agent:capability:networkEgress` + `UNDECLARED_NETWORK_EGRESS` lint | ASI02 Tool Misuse | ASI03, ASI04 | policy can bound exfiltration and credentialed endpoint reach to a declared host set; lint flags an entirely undeclared egress class |
| `in8:agent:capability:filesystem` + `UNDECLARED_FILESYSTEM` lint | ASI02 Tool Misuse | ASI06, ASI03 | bounds reads of secrets or context files and writes to memory or context stores (a poisoning vector) |
| `in8:agent:capability:exec` + `UNDECLARED_EXEC` lint | ASI05 Unexpected Code Execution | ASI02 | makes subprocess spawning explicit and gateable, including the `sudo` and `claude` cases the real servers declare |
| `in8:agent:capability:env` + `UNDECLARED_ENV` lint | ASI03 Identity & Privilege Abuse | ASI02 | enumerates the credential and config variables the tool reads |
| `in8:agent:capability:secrets` | ASI03 Identity & Privilege Abuse | ASI02 | declares which credential kinds the tool expects to hold |
| `in8:agent:capability:mcp:tools` + `TOOL_LISTING_MISMATCH` check | ASI01 Agent Goal Hijack | ASI02, ASI04 | binds the attested tool surface to the artifact; a tool doing more than declared is refused at attest time |
| signed statement + `SUBJECT_DIGEST_MATCH` + composed npm provenance and SLSA | ASI04 Agentic Supply Chain Vulnerabilities | ASI10 | the whole declaration is a signed, digest bound supply chain artifact; provenance composition ties it to build origin |
| `metadata.timestamp` + `generator` + signature (non repudiation) | ASI04 | (T8 Repudiation and Untraceability in the T taxonomy) | a signed, timestamped, attributable declaration is durable evidence for audit |

**Honest scope.** A static capability declaration does not address every agentic risk. `ASI07` Insecure Inter-Agent Communication, `ASI08` Cascading Failures, and `ASI09` Human-Agent Trust Exploitation are runtime and multi agent concerns outside what a published capability manifest can constrain; `ASI10` Rogue Agents is only partially addressed, through identity and provenance of the admitted artifact. smithmark's contribution concentrates on `ASI02`, `ASI03`, `ASI04`, `ASI05`, and `ASI06`, and most directly on `ASI04`. Claiming coverage of the full Top 10 would be dishonest; this proposal claims the five it earns.

---

## 11. EU Cyber Resilience Act alignment

The EU Cyber Resilience Act, Regulation (EU) 2024/2847, treats products with digital elements as subject to essential cybersecurity requirements and technical documentation obligations, with the main obligations applying from 11 December 2027 (vulnerability reporting obligations begin earlier, from September 2026). Agents and the tools they wield are software with digital elements.

A signed capability manifest is machine readable technical documentation of exactly the kind the CRA's documentation obligations call for: it states, in an attestable form, what an artifact is capable of at runtime and binds that statement to a specific build by digest. Projected into CycloneDX, it composes with the SBOM that the same regulation is already driving vendors to produce, so a single BOM can carry both the dependency inventory and the capability declaration. This is the same framing that anchored forgeseal's SBOM work in the portfolio. The claim is deliberately modest: capability manifests are supporting evidence toward CRA aligned documentation, not a conformity guarantee, and no such guarantee is asserted here.

---

## 12. What is implemented versus proposed, and the submission path

### 12.1 Implemented today (the reference implementation)

- The `agent-capability/v1` in-toto predicate, strict parsed and canonicalized (`pkg/core/manifest`).
- `smithmark attest`, `verify`, and `lint`, signing with Sigstore and verifying signatures, subject digests, and schema.
- Real signed, verified capability declarations for better-call-claude 3.1.1 and dear-claude 1.1.0 (sections 7 and 8), composing a forgeseal dependency SBOM.

### 12.2 Proposed here (the standards deliverable)

- The `in8` top level namespace and the `in8:agent:capability:*` property taxonomy (this document).
- Optionally, longer term, an official CycloneDX capability taxonomy or profile.

The CycloneDX projection in sections 6 through 8 is a specified mapping in this proposal; smithmark emits the predicate today and would add a `--format cyclonedx` projection as the taxonomy stabilizes.

### 12.3 Concrete submission path

The two asks travel two real, verified routes.

**Near term, property namespace registration** (`github.com/CycloneDX/cyclonedx-property-taxonomy`):

1. Open an issue on the property taxonomy repository requesting reservation of the `in8` top level namespace. This is the documented registration mechanism; there is no pull request step for the reservation itself.
2. Keep this taxonomy documentation public (it is, in the smithmark repository), satisfying the requirement that a reserved namespace publish its taxonomy before use. The registry table then links to it.
3. Begin emitting `in8:agent:capability:*` properties from the reference implementation, cited from this document.

**Longer term, official taxonomy or profile** (Ecma TC54 standardization process, per `cyclonedx.org/participate/standardization-process/`):

1. Open a proposal in the CycloneDX specification issue tracker to gather community feedback on the use cases and requirements for a standard agent tool capability declaration. CycloneDX issue #895 is the prior discussion to reference.
2. If the Core Working Group accepts, drive the change as an RFC pull request, announced on the mailing list and Slack, with a default four week comment window.
3. At the end of the RFC period the community votes by lazy consensus to accept or reject.
4. If accepted, the Core Working Group promotes the feature candidate to Ecma TC54, which decides by rough consensus of committee members.
5. On acceptance the feature ships in a subsequent CycloneDX specification release (and thus a future ECMA-424 edition).

The near term route is available immediately and does not depend on the longer one. Treat the venue as time sensitive: CycloneDX issue #895 shows the agent capability slot is already being circled, and the reference implementation is shipping, which is the strongest possible position from which to propose a taxonomy.

---

## References

All accessed 2026-07-18 unless noted.

- CycloneDX property taxonomy repository (namespace rules, registration process): `https://github.com/CycloneDX/cyclonedx-property-taxonomy`
- CycloneDX specification overview (version 1.7, released 2025-10-21; ECMA-424): `https://cyclonedx.org/specification/overview/`
- CycloneDX / Ecma TC54 standardization process: `https://cyclonedx.org/participate/standardization-process/`
- Ecma TC54 (committee home): `https://tc54.org/` and `https://ecma-international.org/technical-committees/tc54/`
- ECMA-424 (CycloneDX Bill of Materials Specification): `https://github.com/Ecma-TC54/ECMA-424`
- CycloneDX Agent BOM prior discussion (issue #895): `https://github.com/CycloneDX/specification` (issue 895)
- OWASP Top 10 for Agentic Applications, 2026 edition, released 2025-12-09 (ASI01 through ASI10): `https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/`
- OWASP Agentic AI Threats and Mitigations (T1 through T15, v1.1 synchronized with the Top 10): `https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/` and `https://genai.owasp.org/initiatives/agentic-security-initiative/`
- EU Cyber Resilience Act, Regulation (EU) 2024/2847 (main obligations apply 11 December 2027): `https://eur-lex.europa.eu/eli/reg/2024/2847/oj`
- smithmark predicate schema and lockstep source of truth: `pkg/core/manifest/manifest.go` (predicate type `https://in8.sh/attestation/agent-capability/v1`)
- smithmark whitespace sweep (prior art landscape, named neighbors, positioning): `docs/research/whitespace-sweep.md`
- smithmark decisions D1 (taxonomy granularity), D6 (predicate schema), U8 (dogfood friction): `docs/decisions.md`
- Real capability declarations used as worked examples: `testdata/servers/better-call-claude/smithmark.yaml`, `testdata/servers/dear-claude/smithmark.yaml`
