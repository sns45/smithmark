# Docker MCP Catalog

## What it is
A curated catalog of MCP servers distributed as Docker images through Docker Hub, run as isolated containers. Docker builds and signs the servers it hosts and attaches provenance and SBOM metadata.

## What it does
- Curates verified MCP servers and lets teams build custom catalogs.
- States that "All servers are versioned with full provenance and SBOM metadata" and that "Docker builds and signs all local servers in the catalog."
- Distinguishes verified servers (carry provenance and SBOM from partners and third parties) from Docker built servers (Docker builds and digitally signs them itself).
- Runs each server in an isolated container.

## What it does NOT do
- The provenance and signature cover build origin and image integrity, plus a dependency SBOM. There is no attestation of the server's runtime capabilities (network egress, filesystem, exec, secrets) as a declared, policy consumable artifact.
- The primary docs do not state whether signing uses cosign/Sigstore or another scheme, nor an attestation format for capabilities.
- Covers container packaged MCP servers only; no skills / SKILL.md.
- It is a curated marketplace (a §1.3 named non goal comparison), not a general attestation framework a third party runs over its own artifacts.

## Strongest refutation quote
> "All servers are versioned with full provenance and SBOM metadata" and "Docker builds and signs all local servers in the catalog." (Docker MCP Catalog docs, accessed 2026-07-16)

Assessed: this is build provenance plus SBOM plus image signing, which overlaps smithmark's provenance and dependency layers, but it is not a capability declaration. Provenance answers where the image came from; SBOM answers what dependencies it contains; neither answers what the server is permitted to do.

## Bearing on the §1.2 claim
Moderate on the composition story. Docker already pairs signing, build provenance, and CycloneDX style SBOM for MCP server images at scale, which means "signed provenance plus SBOM for MCP servers" is not novel. This narrows smithmark's whitespace to the capability layer specifically (the thing the SBOM and provenance do not carry) and reinforces §1.3 (smithmark is not an SBOM generator; dependency SBOMs come from forgeseal). Does not falsify the claim; it does raise the bar for how sharply smithmark must distinguish the capability manifest from provenance plus SBOM.

## Sources
- https://docs.docker.com/ai/mcp-catalog-and-toolkit/catalog/ (accessed 2026-07-16)
