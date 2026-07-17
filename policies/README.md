# Example assayward policies

These are example assayward `TrustPolicy` documents for the artifacts
smithmark attests: MCP servers and skill bundles. They exist to demonstrate
the separation the spec insists on (section 1.3): smithmark is not a policy
engine, it never decides. It generates, signs, and verifies attestations,
then hands assayward an Evidence block; the allow, deny, or audit decision
is entirely assayward's, evaluated by these policies running inside
assayward, not inside smithmark.

## Files

- `agent-mcp-baseline.yaml`, a baseline gate for MCP servers an agent
  runtime is about to load: signature required, SLSA L2 plus, an SBOM
  required, and no unmitigated critical vulnerabilities. This is the spec
  section 7 worked example with the network egress clause held back; see
  below.
- `skill-strict.yaml`, a stricter gate for skill bundles: full SLSA L3, a
  required Rekor transparency log entry, and workload identity required.

## Reproducing validation

Both files are checked against the assayward version smithmark's own
`go.mod` pins, `v0.1.0`, using assayward's own strict policy parser, not a
private reimplementation of the schema. From the repository root:

```
go run github.com/sns45/assayward/cmd/assayward@v0.1.0 \
  policy validate policies/agent-mcp-baseline.yaml

go run github.com/sns45/assayward/cmd/assayward@v0.1.0 \
  policy validate policies/skill-strict.yaml
```

Both currently print `ok: <name>@v0.1.0 (mode enforce)` and exit zero. A
policy that does not validate is a bug in this directory, not an acceptable
committed state.

## What each policy gates today versus what assayward#1 adds

assayward v0.1.0's `TrustPolicy` has no capability or findings field, so
"no undeclared network egress" from the spec's worked example cannot be
expressed yet. That gap is filed as
[`sns45/assayward#1`](https://github.com/sns45/assayward/issues/1) and
recorded in `docs/decisions.md` under U5. Each policy file carries a
comment block headed "PENDING assayward#1" sketching the stanza it grows
once that issue ships; those blocks are prose, not live schema, and adding
them for real today would fail `policy validate` since v0.1.0 rejects
unknown fields.

| Gate | agent-mcp-baseline.yaml today | skill-strict.yaml today | Lands with assayward#1 |
|---|---|---|---|
| Signature required | yes, keyed CA pattern | yes, keyless GitHub Actions pattern | unchanged |
| Rekor entry required | no (smithmark v0.1 verify is key based offline) | yes (anticipates the M6 keyless CI migration) | unchanged |
| SLSA minimum level | L2 | L3 | unchanged |
| SBOM required | yes | yes | unchanged |
| Max unmitigated VEX severity | high, binary affected gate (see caveat below) | high, binary affected gate (see caveat below) | severity aware gating |
| Workload identity required | no | yes | unchanged |
| Undeclared network egress denied | not expressible | not expressible | one denied finding |
| All undeclared capability classes denied | not expressible | not expressible | full denied findings list |

Caveat on the VEX row: `vex.maxUnmitigatedSeverity` in assayward v0.1.0 is a
binary affected gate, not a severity threshold. Any CVE whose VEX status is
affected fails the check regardless of the configured value
(`pkg/core/policy/evaluate.go` in the pinned assayward module; the emitted
reason is `VEX_UNMITIGATED_CRITICAL` no matter the severity named). Severity
aware gating, where the configured value actually bounds which affected
CVEs are tolerated, lands in a future assayward version. Both policy files
keep the field and the value `high` as is: the schema is valid today and
the setting is forward compatible with that future gating; only this prose
and each policy's own comment describe the gap.

The lint finding codes named in the pending stanzas, `UNDECLARED_NETWORK_EGRESS`,
`UNDECLARED_FILESYSTEM`, `UNDECLARED_EXEC`, and `UNDECLARED_ENV`, already exist
in smithmark's own report surface (`pkg/core/lint`, `pkg/core/codes`); they
are just not yet carried into the Evidence block assayward reads.

## The digest algorithm note

A skill's subject digest carries a `smithmark-bundle-v1` prefixed key
(`docs/decisions.md` U4), the canonical skill bundle digest, not a plain
`sha256` one, because a skill has no single file to hash and no
`package.json` to key off. assayward's `verify/slsa.go` strips a literal
`sha256:` prefix unconditionally when matching a subject digest today,
which only happens to work for smithmark's Evidence because the mapping
shim in `pkg/core/verify.EvidenceBlock` carries the whole
`smithmark-bundle-v1:<hex>` string through as the digest value rather than
splitting on a colon itself. This is exactly why assayward#1 asks for
algorithm aware digest matching alongside the kind tagged `ArtifactRef` and
the findings carrying Evidence: a future digest kind that legitimately
contains more than one colon, or a verifier that does split on the first
colon expecting a known algorithm name, would break on a
`smithmark-bundle-v1` key without that widening.
