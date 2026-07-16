# Enclawed — "Skills as Verifiable Artifacts" (arXiv 2605.00424)

## What it is
An academic paper plus a working open source implementation, `enclawed` (github.com/metereconsulting/enclawed), by Alfredo Metere (Enclawed, LLC), arXiv:2605.00424v2 dated 2026-05-15. It proposes a trust schema for LLM agent skills in which each skill carries a signed manifest that enumerates the capabilities its content intends to invoke, and a runtime policy gate admits or denies calls against that manifest. This is the closest known neighbor for the SKILLS half of the smithmark claim and is the most serious threat found in the entire sweep.

## What it does
- Skills carry Ed25519 signed manifests declaring capabilities from a fixed vocabulary: `net.egress(host)`, `fs.read(path)`, `fs.write.rev(path)`, `fs.write.irrev(path)`, `tool.invoke(name)`, `spawn.proc(cmd)`, `publish(channel)`, `pay(token, amount)`, and `mutate.schema(target)`. This vocabulary is close to smithmark's own declared capability set (network egress, filesystem, exec, secrets, env).
- A runtime policy gate consumes the declaration: a capability not in the manifest is denied at the gate regardless of what the skill content asks.
- Four verification levels: unverified (default, human in the loop for every irreversible call), declared (signer attests behavior matches declared capabilities), tested (passes an adversarial ensemble check meeting a biconditional correctness criterion), and formal (machine checkable proof, aspirational).
- Hash chained audit logs; verification recorded immutably in the manifest at bootstrap.
- Ships as a real open source framework (enclawed), not paper only.

## What it does NOT do
- Does not compose npm provenance, Sigstore, SLSA, or CycloneDX. It uses its own Ed25519 signatures and Bell LaPadula style classification as primitives rather than reusing the supply chain ecosystem.
- Covers skills / SKILL.md only; it does not address MCP servers.
- Its policy gate is the enclawed runtime itself, not an external, portable policy consumer fed by a publish to registry to admission pipeline; verification is at bootstrap of that runtime.
- Does not emit an in-toto DSSE predicate or attach attestations to OCI referrers, registry entries, or Sigstore bundles.

## Strongest refutation quote
> "A skill's manifest must enumerate every capability its content intends to invoke. A capability not in M.caps is denied at the gate, regardless of what the skill content asks." (arXiv 2605.00424v2, accessed 2026-07-16)

Assessed: this is the strongest refutation in the entire sweep. It describes a signed capability declaration for a skill that a policy gate consumes to admit or deny, which is very close to the wording of the §1.2 claim, and it predates smithmark, and it is implemented. The residual gap is composition and coverage, not the core idea.

## Bearing on the §1.2 claim
High. For the skills half of the claim, enclawed already delivers signed capability declarations consumed by a policy gate, with an almost identical capability vocabulary and a working implementation, dated before smithmark. This is the single item most likely to falsify a loosely worded "first." What preserves a narrower claim: enclawed does not compose the four named supply chain standards (it rolls its own Ed25519 trust root), it does not cover MCP servers, and it binds verification to its own runtime rather than to a portable attestation format (in-toto DSSE) consumed by an independent policy engine across a publish to admission loop. Smithmark's defensible novelty against enclawed is therefore the specific composition (both artifact kinds, plus the four standards, plus a portable predicate consumed by an external policy tool), not the abstract idea of a signed capability manifest for skills, which is taken. Task 0.2 must decide whether the claim survives with that narrowing or must be re scoped.

## Sources
- https://arxiv.org/abs/2605.00424 (accessed 2026-07-16)
- https://arxiv.org/html/2605.00424 (accessed 2026-07-16)
- https://github.com/metereconsulting/enclawed (referenced as the implementation; accessed 2026-07-16)
