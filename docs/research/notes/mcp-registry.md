# MCP Registry (modelcontextprotocol/registry) moderation and verification

## What it is
The official community MCP Registry, an app store style catalog that gives MCP clients a curated list of servers. Publication is governed by namespace ownership verification and moderation, not cryptographic attestation of the server.

## What it does (verification and moderation model)
- Namespace ownership verification: publishers prove they own a namespace before publishing under it. Mechanisms are GitHub OAuth/OIDC (login or GitHub Actions credentials), DNS verification, and HTTP challenge. Example: to publish `io.github.domdomegg/my-cool-mcp` you must authenticate as that GitHub identity; for `me.adamjones/my-cool-mcp` you must prove ownership of `adamjones.me`.
- Moderation removes or blocks entries that violate policy.
- The `server.json` schema carries `name`, `description`, `title`, `websiteUrl`, `repository`, `version`, `packages`, `remotes`, and `_meta`. Within `packages` there is a `fileSha256` used for MCPB bundle integrity.

## What it does NOT do
- Does not cryptographically sign `server.json` or the server, and does not verify a signature on it. Verification proves who controls a namespace at publish time, not that any artifact is authentic thereafter.
- Has no attestation reference field in `server.json` today. The only integrity metadata is a `fileSha256` hash for MCPB bundles, and a `_meta` extension slot for publisher provided metadata under reverse DNS namespacing; neither is an attestation of provenance or capabilities.
- Does not declare or attest capabilities (egress, filesystem, exec, secrets).

## Strongest refutation quote
The primary docs contain no sentence claiming cryptographic attestation. The nearest integrity language is:
> `fileSha256` "Includes a SHA-256 hash for integrity verification" (MCP Registry server.json reference, accessed 2026-07-16)

Assessed: a content hash for a bundle is integrity, not provenance and not a capability attestation. Namespace verification is an ownership proof, not a signed capability declaration.

## Bearing on the §1.2 claim
The registry curates and proves namespace ownership; it does not attest. This directly supports the smithmark positioning ("registries curate; smithmark attests") and, importantly, it substantiates the §1.4 standards deliverable: there is no attestation reference field in `server.json` today, which is exactly the gap the planned MCP Registry provenance RFC targets. No danger to the claim; this item strengthens the RFC gap statement.

## Sources
- https://github.com/modelcontextprotocol/registry (accessed 2026-07-16)
- https://raw.githubusercontent.com/modelcontextprotocol/registry/main/docs/reference/server-json/generic-server-json.md (accessed 2026-07-16)
