# ETDI: Enhanced Tool Definition Interface (arXiv 2506.01333)

## What it is
A security extension to MCP proposed in an academic paper, "ETDI: Mitigating Tool Squatting and Rug Pull Attacks in Model Context Protocol (MCP) by using OAuth-Enhanced Tool Definitions and Policy-Based Access Control," by Manish Bhatt, Vineeth Sai Narajala, and Idan Habler, submitted 2025-06-02. ETDI adds cryptographic identity, immutable versioned tool definitions, and OAuth 2.0 scoped permissions to MCP tools, and proposes a policy engine that evaluates tool calls against explicit policies. This is the closest known neighbor and is treated here with extra rigor.

## What it does
- Binds tool definitions to signed JSON Web Tokens; tool providers sign with a key pair and an OAuth 2.0 identity provider is the signing authority. Clients verify the signature before accepting a tool definition.
- Makes each tool version immutable and signed, so a changed description or scope requires a new signed version, which defeats rug pull style silent mutation.
- Proposes fine grained, policy based access control where tool capabilities (expressed as OAuth scopes) are evaluated against explicit policies by a dedicated policy engine, considering runtime context beyond static scopes.

## Implementation status
Beyond the paper there is a documentation repository, `vineethsai/MCP-ETDI-docs`, which is docs and design only (no source). A reference implementation exists as a fork of the official SDK, `vineethsai/python-sdk`, and a pull request to upstream, `modelcontextprotocol/python-sdk` PR #845, which was CLOSED (not merged) on 2025-07-18. The maintainer (@ihrpr) redirected it to the specification first process at `modelcontextprotocol/modelcontextprotocol`. So a proof of concept implementation exists, but it was not accepted into the official SDK and is not a maintained standalone product.

## What it does NOT do
- Does not define a capability manifest over network egress, filesystem, exec, environment variables, or secrets. Its "capabilities" are OAuth scopes and permission categories on a tool, not the resource surface smithmark declares.
- Does not compose npm provenance, Sigstore, SLSA, CycloneDX, or SBOM. It invents its own signed JWT definition model rather than reusing the supply chain ecosystem; the paper cites Sigstore literature but does not integrate it.
- Does not cover skills / SKILL.md; the subject is MCP tool definitions only.
- Does not close a publication to admission loop as an artifact pipeline (publish attestation to a registry, then gate admission on it). Verification happens client side at tool discovery time.

## Strongest refutation quote
> "A tool's required capabilities (e.g., OAuth scopes) are declared in its signed definition." (arXiv 2506.01333v1, full text, accessed 2026-07-16)

Assessed: this is the single sentence in all swept prior art that comes closest to "signed capability declaration." It is a real hit and must be acknowledged. But ETDI conflates capability with OAuth scope; a signed OAuth scope on a tool is far narrower than a signed manifest of egress, filesystem, exec, env, and secrets, and it carries none of the supply chain composition or the skills coverage the claim asserts.

## Bearing on the §1.2 claim
ETDI partially overlaps the core idea (a signed, verifiable tool definition whose declared permissions are checked by a policy engine) and it predates smithmark. It is the strongest paper level challenge to the word "first." What keeps the claim alive is the specific scope: ETDI is OAuth scoped tool definitions for MCP tools only, with a bespoke JWT trust root, no supply chain standard composition, no skills, and no accepted implementation. Smithmark's differentiators against ETDI are (1) a capability manifest over concrete resources rather than OAuth scopes, (2) composition of npm provenance, Sigstore, SLSA, and CycloneDX via in-toto DSSE rather than a parallel trust root, (3) coverage of skills as well as MCP servers, and (4) a publication to admission loop with an external policy consumer. These are defensible but they are refinements of a shared idea, not a wholly empty field. Moderate to high bearing: the "first ... signed ... policy consumable ... for MCP" framing needs careful wording so it does not read as ignorant of ETDI.

## Sources
- https://arxiv.org/abs/2506.01333 (accessed 2026-07-16)
- https://arxiv.org/html/2506.01333v1 (accessed 2026-07-16)
- https://github.com/vineethsai/MCP-ETDI-docs (accessed 2026-07-16)
- https://github.com/modelcontextprotocol/python-sdk/pull/845 (accessed 2026-07-16)
