# NVIDIA Verified Agent Skills

## What it is
An NVIDIA program and catalog that reviews, scans, cryptographically signs, and documents agent skills that teach AI agents to use NVIDIA tools and libraries. It builds on the open `agentskills.io` specification and ships machine readable skill cards. It is a curated publishing pipeline plus a signing step, not an open framework for arbitrary artifacts.

## What it does
- Publishing flow: daily catalog sync from product teams, automated policy checks and human review, security scanning (SkillSpector) for conventional and agent specific risks, cryptographic signing, and publication with a skill card.
- Signs with the OpenSSF Model Signing (OMS) format using detached signatures; the signature covers every file and subdirectory in the skill directory, so a downloaded skill can be verified as authentic and unchanged.
- Skill card (openly released template, YAML/markdown) declares what the skill does, owner, license, dependencies, known limitations and risks, and verification status.
- Grounds its risk framing in OWASP LLM guidance and MITRE ATLAS.

## What it does NOT do
- The signature is an integrity and authorship signature over the skill files; the skill card documents capabilities descriptively, but there is no evidence of a machine consumable capability manifest (egress, filesystem, exec, secrets) that an external policy engine ingests as signed evidence to gate admission.
- Does not compose npm provenance, Sigstore, SLSA, or CycloneDX; it uses OpenSSF Model Signing.
- Curated and NVIDIA operated. The catalog is NVIDIA's; it is not a general framework a third party runs over its own MCP servers and skills.
- MCP server coverage is not addressed; the subject is skills.

## Strongest refutation quote
> "The signature covers every file and subdirectory in the skill directory, giving developers a concrete way to verify that the downloaded skill is authentic and unchanged." (NVIDIA Technical Blog, accessed 2026-07-16)

Assessed: this is integrity and authenticity signing of a skill bundle (comparable to smithmark's build provenance layer for skills), not a signed, policy consumable capability declaration. The skill card carries capability description but the primary source does not show it being consumed as signed policy evidence.

## Bearing on the §1.2 claim
Moderate. NVIDIA already signs skill bundles for integrity and publishes machine readable skill cards, which overlaps smithmark's provenance and manifest surfaces for skills and shows a large vendor active in this exact space. It differs in that it is a curated vendor catalog, it signs for integrity rather than emitting a capability attestation consumed by an external policy gate, and it does not compose the four named standards or cover MCP servers. It does not falsify the claim, but it further narrows the whitespace: signed skill bundles with capability documenting cards are shipping at NVIDIA scale. The precise thing smithmark must own is the capability declaration as an attestable, portable, policy consumed artifact, distinct from a signed bundle plus a descriptive card.

## Sources
- https://developer.nvidia.com/blog/nvidia-verified-agent-skills-provide-capability-governance-for-ai-agents/ (accessed 2026-07-16)
