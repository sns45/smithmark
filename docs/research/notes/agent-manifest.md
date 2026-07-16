# Agent Manifest (agent-manifest/agent-manifest)

## What it is
An open specification (v1.0, Standards Track) for autonomous AI agents to publish identity, capabilities, and operational boundaries in a structured, machine readable format before interaction begins. The subject is the agent itself, not an MCP server package or a skill bundle.

## What it does
- Provides a declarative format for an agent to declare identity, purpose, capabilities, and operational boundaries up front.
- Intentionally static: it is a declaration layer only.

## What it does NOT do
- Is not cryptographically signed and is not policy enforcing by design. The spec states it "does not execute, validate, score, enforce, or decide. It is static by design," and that validation, scoring, auditing, and enforcement belong to separate systems.
- Does not compose npm provenance, Sigstore, SLSA, or CycloneDX.
- Describes the agent, not the tool supply chain artifacts (MCP servers, skills) that smithmark attests.
- Minimal adoption: about 2 stars and 1 fork, though it has reached v1.0 with 307 commits as of March 2026.

## Strongest refutation quote
> "It defines what an agent declares, not what it does. Validation, scoring, auditing, and enforcement belong to separate systems." (agent-manifest specification, accessed 2026-07-16)

Assessed: this is an unsigned declaration layer for agents, explicitly decoupled from verification and enforcement. It is the opposite of a signed, policy consumable artifact; it is a declaration whose signing and consumption are deliberately left to others.

## Bearing on the §1.2 claim
Low. Different subject (the agent, not the tool artifact), unsigned, and explicitly not an attestation or policy mechanism. It does not falsify the claim. It is included because it appears prominently under "capability manifest" and "agent capabilities" searches and could be mistaken for competing prior art; it is a static declaration spec, not an attestation framework, so the distinction is worth recording.

## Sources
- https://github.com/agent-manifest/agent-manifest (accessed 2026-07-16)
