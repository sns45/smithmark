# CycloneDX "Agent BOM" proposal (CycloneDX/specification issue #895)

## What it is
A proposal filed on the CycloneDX specification tracker (issue #895) by GitHub user razashariff on 2026-03-26 to extend CycloneDX (v1.6) with an Agent Bill of Materials that tracks AI agent components: MCP servers, tools, models, credentials, and sanctions screening status. Its stated aim is to let a consumer verify what an autonomous agent is composed of and what it is authorized to do. This item bears on the smithmark §1.4 standards deliverable (the planned Ecma TC54 CycloneDX agent capability taxonomy), not directly on the tool novelty.

## What it does (as proposed)
- Extends CycloneDX to inventory agent components including MCP servers the agent connects to, tools it can call, and models it uses (id, version, provenance).
- Frames the goal as moving CycloneDX from "what software is in this system" to "what makes up this agent and what is it authorized to do."

## What it does NOT do
- Does not define a formal capability or authorization taxonomy. It names "tool definitions" and "capability scopes" as things to track but leaves the classification open.
- Is a proposal, and it was CLOSED with a "duplicate" label, meaning it was superseded by or merged into another discussion rather than accepted as written.
- Does not sign anything or define an attestation format; it is an inventory schema proposal.

## Strongest refutation quote
> "what components make up this autonomous agent and what is it authorised to do" (CycloneDX/specification issue #895, accessed 2026-07-16)

Assessed: this is scoping language for an inventory, not a defined taxonomy and not a signed attestation. It signals intent to describe agent authorization in CycloneDX but stops short of specifying it.

## Bearing on the §1.2 claim and the §1.4 deliverable
Two effects. On §1.2, none directly: this is an SBOM inventory proposal, not a signed capability attestation tool, so it does not falsify the novelty claim. On §1.4 (the CycloneDX agent capability taxonomy smithmark plans to pitch to TC54), it is a yellow flag: others are already asking CycloneDX to describe what agents and their tools are authorized to do, so the standards whitespace is contested and moving. The proposal not defining a taxonomy, and being closed as duplicate, means the specific taxonomy slot is not yet claimed, but smithmark should assume company in that venue and move promptly. Worth surfacing to the maintainer for the standards workstream even though it does not threaten the tool claim.

## Sources
- https://github.com/CycloneDX/specification/issues/895 (accessed 2026-07-16)
