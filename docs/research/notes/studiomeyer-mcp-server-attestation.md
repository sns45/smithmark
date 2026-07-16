# studiomeyer-io/mcp-server-attestation

## What it is
An open source TypeScript/JavaScript library that adds a supply chain hardening layer to MCP servers. It signs a server's tool manifest with an Ed25519 key and attests spawn calls at runtime, targeting marketplace poisoning and two named CVEs (2025-69256, 2025-61591). This is the closest named neighbor for the MCP SERVER half of the smithmark claim.

## What it does
- Signs a tool manifest with Ed25519; the manifest declares the tools a server exposes and the spawn commands it is permitted to make.
- Enforces a default deny argument sanitizer and validates spawn calls against the signed allowlist at runtime.
- Trust on first use (TOFU) model: developers sign their own manifests; the first verification pins the public key locally at `~/.mcp-attest/trust.json`.
- Optional Sigstore Rekor cross reference via a `--sigstore` flag for fingerprint transparency.
- Published to npm with OIDC provenance; includes tests and CVE regression fixtures.

## What it does NOT do
- The signed manifest declares tools and permitted spawn commands only. The README explicitly excludes network egress control, sandboxing/containerization, and OAuth hardening. It is not a full capability manifest over egress, filesystem, env, and secrets.
- Does not compose npm provenance, SLSA, or CycloneDX into the attestation; the Sigstore hook is an optional supplemental cross reference, not an integrated composition.
- Covers MCP servers only; no skills / SKILL.md support.
- No central trust root or publish to admission approval loop; each user decides via TOFU when to trust a server. There is no registry to policy pipeline.
- Maturity is minimal: 0 stars, 26 commits, latest release v0.1.1 at access time.

## Strongest refutation quote
> "cryptographic verification of which tools a server is allowed to expose and which spawn calls it is allowed to make" (verbatim from the README, `studiomeyer-io/mcp-server-attestation`, accessed 2026-07-16)

Assessed: this is a genuine signed capability declaration for an MCP server, and it is the strongest MCP side hit. But its "capabilities" are limited to the tool list and spawn allowlist, with network egress explicitly out of scope, so it is a narrow tool allowlist signer rather than the resource capability manifest smithmark describes.

## Bearing on the §1.2 claim
Moderate to high on the word "first." A signed manifest of what an MCP server exposes, consumable to gate spawn calls, already exists and is published. What preserves the narrower claim: the manifest is a tool and spawn allowlist rather than a full capability set (egress, filesystem, env, secrets all excluded or absent), it uses a bespoke TOFU Ed25519 scheme rather than composing the four named standards, it covers no skills, and it closes no registry to admission loop. Combined with enclawed on the skills side and ETDI on the tool definition side, this item shows the "signed manifest for an agent tool" idea is being worked on from multiple directions. Smithmark's residual novelty is the composite, not the primitive.

## Sources
- https://github.com/studiomeyer-io/mcp-server-attestation (accessed 2026-07-16)
