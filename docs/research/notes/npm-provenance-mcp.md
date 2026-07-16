# npm provenance coverage of MCP packages

## What it is
npm provenance is a published attestation, generated when a package is built and published from a supported CI (for example GitHub Actions with `--provenance`), that links the published tarball to its source repository, commit, and build workflow. The npm registry exposes it at `https://registry.npmjs.org/-/npm/v1/attestations/<package>@<version>`. Two predicates are returned: the npm publish attestation (`https://github.com/npm/attestation/tree/main/specs/publish/v0.1`) and the SLSA provenance predicate (`https://slsa.dev/provenance/v1`).

## What it proves and does not prove
- Proves build origin: which source repository, which commit, which builder/workflow produced the artifact, plus the artifact digest.
- Does NOT prove capabilities: nothing in the SLSA provenance predicate states what the package can do at runtime (network egress, filesystem, exec, secrets). A package with perfect provenance can still open arbitrary sockets and read arbitrary files.

## Spot check (accessed 2026-07-16, via the npm registry attestations API)
Ten popular MCP server packages, latest version at access time:

| Package | Provenance |
|---|---|
| @modelcontextprotocol/server-filesystem@2026.7.10 | YES (npm publish + SLSA provenance) |
| @modelcontextprotocol/server-everything@2026.7.4 | YES |
| @modelcontextprotocol/server-memory@2026.7.4 | YES |
| @modelcontextprotocol/server-sequential-thinking@2026.7.4 | YES |
| @playwright/mcp@0.0.78 | YES |
| mcp-server-kubernetes@4.0.4 | YES |
| firecrawl-mcp@3.22.3 | NO |
| @upstash/context7-mcp@3.2.3 | NO |
| tavily-mcp@0.2.21 | NO |
| @executeautomation/playwright-mcp-server@1.0.12 | NO |

Result: 6 of 10 ship provenance (60 percent). The official `@modelcontextprotocol/*` first party servers and a few well maintained third parties publish provenance; several popular third party servers do not.

## What it does NOT do (relative to the claim)
- Even where present, npm provenance is build origin only; it is not a capability declaration and it is not consumed by a capability policy.
- Coverage is partial, so a consumer cannot assume any given MCP package carries even build provenance.

## Strongest refutation quote
> SLSA provenance is "a signed provenance attestation that names the source repository, the source commit, the build platform, the build configuration, and the resulting artifact digest." (SLSA framework description, accessed 2026-07-16)

Assessed: this is exactly the boundary the claim relies on. npm provenance answers "where did this build come from," never "what can this artifact do."

## Bearing on the §1.2 claim
Directly supportive. npm provenance is one of the four standards smithmark proposes to compose, not replace, and this note confirms two things the claim depends on: provenance proves build origin and not capabilities, and coverage across the MCP ecosystem is only partial (60 percent in this sample). The capability layer is genuinely unfilled by npm provenance. No danger to the claim; this is the composition story working as intended.

## Sources
- https://registry.npmjs.org/-/npm/v1/attestations/@modelcontextprotocol/server-filesystem@2026.7.10 (and the other nine packages, same API pattern; accessed 2026-07-16)
- https://docs.npmjs.com/generating-provenance-statements (npm provenance semantics; accessed 2026-07-16)
- https://slsa.dev/provenance/v1 (predicate definition; accessed 2026-07-16)
