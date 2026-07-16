# Invariant Labs mcp-scan (now Snyk Agent Scan)

## What it is
A security scanner for the agent tool surface. The project, formerly `mcp-scan` from Invariant Labs, now carries Snyk Agent Scan branding; the GitHub README at `invariantlabs-ai/mcp-scan` and the raw README both now render Snyk Agent Scan content, and neither asserts how the rename came about. It discovers and scans MCP configurations, tools, and skills on a machine for prompt injection, tool poisoning, malware payloads, and hardcoded secrets. It also ships a proxy and guardrail capability (mcp-scan proxy) for runtime inspection of MCP traffic.

## What it does
- Auto discovers MCP configurations across Claude, Cursor, Windsurf, Gemini CLI, and other agents.
- Detects a stated 15 plus distinct security risks (prompt injection, tool poisoning, rug pull style changes, secrets).
- Operates in a discrete scan mode and an optional background monitoring mode.
- Emits JSON or rich text reports of findings.

## What it does NOT do
- Does not sign anything cryptographically.
- Does not produce a verifiable attestation about the artifact it scanned.
- Does not emit a capability manifest that a downstream policy engine consumes as signed evidence; its JSON is a findings report, and the docs warn the CLI output is experimental and not for production workflow dependence.
- Does not close a publication to admission loop; scanning is inspection, not a durable maker's mark.

## Strongest refutation quote
> "Discover[s] and scan[s] agent components on your machine for prompt injections and vulnerabilities."
(GitHub README, `invariantlabs-ai/mcp-scan`, accessed 2026-07-16)

Assessed: this is scanner language, not attestation language. There is no sentence in the primary source that resembles "signed capability declaration consumable by policy." The tool inspects; it does not attest.

## Bearing on the §1.2 claim
Confirms the spec's expectation. mcp-scan is a scanner and a runtime guardrail, occupying the "scanners inspect" half of the smithmark positioning (§1.3 explicitly names mcp-scan as a non goal comparison). It produces no signed artifact and no capability declaration, so it does not falsify the claim. It is the strongest example of the crowded "security for MCP" space that the claim deliberately does not compete in. No danger to the claim.

## Sources
- https://github.com/invariantlabs-ai/mcp-scan (accessed 2026-07-16)
- https://raw.githubusercontent.com/invariantlabs-ai/mcp-scan/main/README.md (accessed 2026-07-16)
- https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks (accessed 2026-07-16)
