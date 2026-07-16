# SkillGuard: A Permission Framework for Agent Skills (arXiv 2606.03024)

## What it is
An academic paper by Shidong Pan, Xiaoyu Sun, Tianyi Zhang, Dianshu Liao, Kaiwen Yang, and Zhenchang Xing (CSIRO Data61), arXiv:2606.03024v2 dated 2026-07-13. SkillGuard is a runtime permission framework: each skill declares its capability surface through a JSON based Skill Manifest expressed in a domain specific language, and the framework instantiates those declared permissions into runtime policy state and mediates sensitive behavior during execution.

## What it does
- Requires each skill to declare a capability surface via a Skill Manifest (a declarative permission config).
- Instantiates declared permissions into runtime policy state and mediates sensitive behavior throughout execution.
- Covers agent skills and their delegation to MCP servers, from a skill centric permission viewpoint.

## What it does NOT do
- Does not cryptographically sign or attest the manifest. The paper does not discuss signing, attestation, or integrity protection; manifests are runtime enforced configurations without supply chain security.
- Does not compose npm provenance, Sigstore, SLSA, or CycloneDX; these are mentioned only as possible future directions.
- Is a runtime enforcement framework, not a supply chain attestation framework; there is no maker's mark and no publish to admission loop over a signed artifact.

## Strongest refutation quote
> "Skill manifests could become an expected artifact for documenting permissions, constraints, and security assumptions of agent skills" (arXiv 2606.03024v2, accessed 2026-07-16)

Assessed: this is aspirational and, crucially, unsigned. A declared but unsigned runtime permission manifest is exactly the "declaration without attestation" gap smithmark aims to fill; SkillGuard names the artifact but does not make it a signed, verifiable one.

## Bearing on the §1.2 claim
Supportive rather than threatening. SkillGuard demonstrates strong demand for skill capability manifests and even anticipates them becoming an expected artifact, but it explicitly stops short of signing or attesting them, which is precisely the whitespace §1.2 claims. It reinforces that the capability manifest idea is in the air while confirming that the signed, policy consumable, supply chain composed version is not what SkillGuard delivers. Low danger; useful as evidence that the manifest concept exists but the attestation of it does not (in this work).

## Sources
- https://arxiv.org/abs/2606.03024 (accessed 2026-07-16)
- https://arxiv.org/html/2606.03024 (accessed 2026-07-16)
