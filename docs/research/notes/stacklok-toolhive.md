# Stacklok ToolHive

## What it is
An open source MCP platform that runs MCP servers as isolated containers and acts as a registry and runtime gateway. It curates a built in registry of MCP servers, enforces identity and access policy, and adds observability. Stacklok integrated Sigstore and GitHub Attestations into ToolHive so that servers from its registry can be provenance checked at deploy time.

## What it does
- Runs each MCP server in an isolated container with access policy and SSO (OIDC/OAuth).
- Curates a registry for discovery of MCP servers.
- At deploy time, extracts the container image digest, searches for signatures and attestations on that image, verifies the signatures against trusted certificate authorities, and validates build provenance against the expected source repository and GitHub Actions workflow.
- Displays a provenance verification status such as "Provenance signed by Sigstore" in the registry UI.

## What it does NOT do
- Does not itself sign a capability declaration. It is a consumer and verifier of provenance that other build systems (GitHub Actions, Sigstore) already produced.
- The provenance it checks attests build origin (which repository, which workflow, which commit built the image), not the server's runtime capabilities (network egress, filesystem, exec, secrets).
- Does not produce a signed, schema validated capability manifest of what an MCP server exposes and requires.
- Does not cover skills / SKILL.md bundles; the subject is container images.

## Strongest refutation quote
> "Verify provenance and sign servers with built-in security controls" (ToolHive README, `stacklok/toolhive`, accessed 2026-07-16)

and, on what "verified" actually means:

> servers that "Were built from the official GitHub repository / Used the expected GitHub Actions workflow / Were signed by GitHub's certificate authority" (Stacklok, "From unknown to verified", dev.to mirror, accessed 2026-07-16)

Assessed: the README phrase "sign servers" is the most dangerous sounding sentence found, but the primary detail shows ToolHive verifies pre existing container build provenance rather than producing a signed capability attestation. The verified badge means the image build origin is cryptographically checkable, which is orthogonal to declaring and signing what the server can do.

## Bearing on the §1.2 claim
ToolHive is the strongest incumbent on the supply chain axis because it genuinely composes Sigstore and GitHub build attestations for MCP servers. However it verifies build origin, it does not attest capabilities, and it does not produce a maker's mark; it is a runtime gateway plus registry (a §1.3 named non goal comparison). It closes no publication to admission capability loop because there is no capability artifact in the loop, only image build provenance. It does not falsify the claim, but it does establish that "provenance for MCP servers, via Sigstore, consumed as a deploy gate" is already shipping. Smithmark's differentiation must therefore rest on the capability declaration layer and on covering skills, not on the mere idea of provenance for MCP. Low to moderate bearing: no direct falsification, but it narrows the whitespace to the capability manifest specifically.

## Sources
- https://github.com/stacklok/toolhive (accessed 2026-07-16)
- https://dev.to/stacklok/from-unknown-to-verified-solving-the-mcp-server-trust-problem-5967 (accessed 2026-07-16)
- https://stacklok.com/blog/from-unknown-to-verified-solving-the-mcp-server-trust-problem/ (returned HTTP 403 on direct fetch 2026-07-16; content read via the dev.to mirror above)
- https://docs.stacklok.com/toolhive/guides-ui/registry (accessed 2026-07-16)
