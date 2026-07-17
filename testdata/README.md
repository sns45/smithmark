# smithmark test data

Fixtures the smithmark test suite consumes. Most of this tree is hand authored
input (a fixture skill under `skills/`, a fake MCP server under `fakemcp/`, a
declaration under `declared/`). The `signature/` tree is different: it is
generated and committed by the signed fixture generation kit, so Phase 3
verification tests have realistic signed inputs with no network in CI.

## The throwaway test signing key

> [!WARNING]
> `signature/test-signing-key.pem` is a throwaway, test only ECDSA P-256
> private key. It exists solely to sign the fixtures in this directory. It must
> never sign a real artifact, a real release, or anything outside this test
> tree. It is committed in the clear on purpose: it guards nothing. Its public
> half, `signature/test-signing-key-pub.pem`, is what verification tests load to
> check the committed bundles.

## Regenerating the signed fixtures

From the repository root:

```
go run ./testdata/gen               # regenerate every fixture under signature/
go run ./testdata/gen --check       # verify the committed fixtures stay honest
go run ./testdata/gen --bootstrap   # mint a fresh throwaway key, then regenerate
```

The generator lives at `testdata/gen/gen.go`. The Go toolchain excludes any
directory named `testdata` from `go build ./...`, `go vet ./...`, and `go test
./...`, so this `main` package never enters the ordinary build; it is only ever
run explicitly through the commands above.

If `signature/test-signing-key.pem` already exists, the generator loads it and
never regenerates it, so regeneration reuses the same committed key and the
committed public key keeps verifying every bundle.

If no key is committed, plain regeneration refuses and exits non zero rather
than mint one silently, because a new key would swap the trust anchor and
resign every fixture. Minting is gated behind `--bootstrap`, which prints a loud
warning before it replaces the committed public key and rewrites every bundle.
`--bootstrap` combined with `--check` is an error, since one rewrites the
fixtures and the other only reads them.

## Determinism

The statement payloads are fully deterministic: the `generatedAt` clock is a
fixed constant (`2026-07-16T00:00:00Z`), the generator identity is fixed
(`{smithmark, test}`), the skill subject digest is the real canonical bundle
digest of `skills/hello-skill`, and the npm subject digest is a fabricated fixed
hex string.

Byte for byte reproducibility of the whole bundle is **not** achievable, because
ECDSA signing draws a fresh random nonce per signature. Every regeneration
therefore produces **new signature bytes over identical payloads**. This is
expected. The guard against silent breakage is not a byte diff but the `--check`
mode and the CI test at `pkg/compose/fixtures_test.go`, which both load each
committed bundle, verify (or, for the tampered variant, refuse) its DSSE
signature against the committed public key, and assert the payload parses (or
fails to parse) exactly as each variant intends.

Do not be alarmed if `git status` shows every `signature/**/*.sigstore.json`
file as modified after running `go run ./testdata/gen`: only the signature bytes
changed. Commit the regeneration only when the payloads themselves needed to
change; a routine rerun that changes nothing but signatures does not need to be
committed.

When you do regenerate for a real payload change, the `cmd/smithmark` verify
golden (`cmd/smithmark/testdata/golden/verify_valid_skill.json`) embeds the
winning bundle's DSSE envelope bytes, so it is coupled to the regenerated
`skill/valid.sigstore.json` fixture. Regenerate it in the same commit with `go
test -update ./cmd/smithmark`. The pure core golden
(`pkg/core/verify/testdata/golden/report_valid.json`) carries no envelope
(its evidence is `null`), so it is not coupled to the signature bytes.

## Fixture inventory

Two subjects generate the full five variant set, and one (the misdeclared
skill) generates only the `valid` variant:

- `signature/skill/` attests the `skills/hello-skill` fixture: a `skill` kind,
  `local` source subject whose subject digest is the true canonical bundle
  digest of that directory.
- `signature/npm/` attests the synthetic `fake-caller` `1.0.0` identity: an
  `mcp-server` kind, `npm` source subject whose subject digest is a fabricated
  fixed sha512 hex string. No real tarball exists; verification consumes the
  bundle plus an expected digest, so a fabricated digest is sufficient.
- `signature/misdeclared-skill/` attests the `skills/misdeclared-skill`
  fixture over its true canonical bundle digest, with only a `valid` variant.
  The signature and digest are entirely honest; the misdeclaration is in the
  predicate's capability set (it declares zero network egress while
  `scripts/exfil.ts` calls `fetch`), which the capability lint catches, not the
  crypto. It is the input to the `verify --strict` exit 2 end to end test: a
  passing signature verification that carries an `UNDECLARED_` finding exits 2
  under `--strict` and 0 without. The four negative crypto variants are not
  generated for it, since a crypto or schema defect is not what this fixture
  demonstrates.

The five variants, identical in shape across both subjects:

| File | What it is |
| --- | --- |
| `valid.sigstore.json` | A correctly signed bundle over the canonical statement. Signature verifies, statement parses, predicate validates, subject digest is the true one. |
| `tampered.sigstore.json` | The valid bundle with one byte of the DSSE signature flipped. Payload is byte identical to valid; the signature no longer verifies. |
| `digest-mismatch.sigstore.json` | Validly signed, but the subject digest is a deliberately wrong value. The digest is altered before signing, so the signature verifies while the subject is wrong. |
| `schema-invalid.sigstore.json` | Validly signed over a statement whose predicate carries `schemaVersion` `9.9.9`, which fails semantic validation. Assembled by hand to bypass the statement builder, which would reject it. |
| `unknown-predicate.sigstore.json` | Validly signed over a statement whose `predicateType` is `https://in8.sh/attestation/agent-capability/v2`, a version this build does not understand. |

All bundles are signed through the offline key based path (`compose.NewSigner`
with a `KeyPath`), the only mode a hermetic CI can exercise. Their verification
material is a bare public key, never a certificate; no Rekor inclusion proof and
no transparency log entry is involved.

## Cert expiry is deliberately NOT covered here

There is no `expired-cert.sigstore.json` fixture, and this is a considered
decision, not an omission.

The offline key based signing path (`compose.signWithKey`, backed by
sigstore-go's `sign.Bundle` with no certificate provider) stores **public key**
verification material, never an X.509 certificate. An inspection of any
committed bundle confirms this: `verificationMaterial` carries only a
`publicKey` object, with no `certificate` and no `x509CertificateChain` field.
With no certificate on this path there is no `notAfter` to expire, so a cert
expiry fixture cannot be built for the path Phase 3's offline verifier
exercises.

A certificate is issued only on the keyless path, where Fulcio mints a short
lived signing certificate from an OIDC identity. Verifying such a certificate
requires a trusted root (the Fulcio CA), signed certificate timestamps, and,
in practice, a Rekor inclusion proof. Hand assembling a self signed certificate
bundle offline would not exercise the same verification code path; sigstore-go's
verifier would reject it for a missing trusted root long before it ever reached
an expiry check, making it a misleading fixture rather than a useful one.

Consequence for Task 3.3: the cert expiry row of the verification behavior
matrix must be covered differently from the other rows. It is a keyless concept,
exercised live against Fulcio in the M6 release workflow, not offline in CI.
Task 3.3 documents how that row is addressed.

## Capability lint fixtures (`misdeclared/`, `skills/misdeclared-skill/`)

Two hand authored fixtures exercise the M4 capability lint, both deliberately
misdeclared: their `smithmark.yaml` declares fewer capabilities than their
source actually uses.

- `misdeclared/` is a fake MCP server (spec section 9): `smithmark.yaml`
  declares all five capability keys empty, while `src/index.ts` calls
  `fetch("https://exfil.example.com")`. It is lint only, never signed or
  verified, and is the golden input for `cmd/smithmark`'s
  `TestLintMisdeclaredGolden`: `smithmark lint --output json` over it reports a
  single `UNDECLARED_NETWORK_EGRESS` finding naming the fetch call site.
- `skills/misdeclared-skill/` is the same idea as a skill: `smithmark.yaml`
  declares zero network egress while `scripts/exfil.ts` calls `fetch`. Unlike
  `misdeclared/`, it is signed by the generation kit (see
  `signature/misdeclared-skill/` above) so it can drive the `verify --strict`
  exit 2 end to end test. Its `executables` list is declared empty so the
  bundle digest is identical on every OS regardless of on disk executable bits.

`npm/packument.json` and `npm/attestations.json` are real npm registry
responses, fetched once during Task 3.2's development (network access is
allowed for a maintainer preparing fixtures; it is never allowed in CI or in a
test).

- **Package**: `@modelcontextprotocol/server-filesystem`, version `2026.7.10`
  (the `latest` dist-tag at fetch time), chosen because it is an
  `@modelcontextprotocol` scoped MCP server whose latest publish carries both
  npm's own publish attestation and a SLSA provenance attestation, so the
  fixture exercises the real shape `pkg/discover/npm.go` reads.
- **Snapshot date**: 2026-07-16.
- **Source requests**:
  - `GET https://registry.npmjs.org/@modelcontextprotocol/server-filesystem`
  - `GET https://registry.npmjs.org/-/npm/v1/attestations/@modelcontextprotocol/server-filesystem@2026.7.10`
- **`packument.json` trim**: a packument is a foreign, npm owned format, so
  `pkg/discover/npm.go`'s `packument` type decodes it leniently (a plain
  `json.Unmarshal`, not `DisallowUnknownFields`), matching this codebase's
  existing posture for every other format it does not control the schema of
  (the attestations response below, package.json's smithmark key, SKILL.md
  frontmatter). The fixture is still trimmed down from the full real
  packument, but only for size, not for decode correctness: it keeps the top
  level `name`, `_id`, `_rev`, `description`, `maintainers`, and a `time` block
  with just `created` and `modified`, and, for the single `2026.7.10` version
  entry, `name`, `version`, `scripts`, and a `dist` block with `integrity`,
  `tarball`, `shasum`, `fileCount`, and `unpackedSize`. Every one of those
  fields beyond `dist.integrity` and `dist.tarball` is realistic noise this
  package's `packument` type does not model and never reads; it is committed
  deliberately, not accidentally, so the fixture itself pins the lenient
  posture: a strict decoder would reject every one of them, and this fixture
  proves the implementation does not.
- **`attestations.json`**: committed close to verbatim (undisturbed field
  values; only whitespace may differ from the live response), since
  `fetchNPMProvenance` in `pkg/discover/npm.go` decodes this response leniently
  (a plain `json.Unmarshal`, matching how this codebase already treats other
  foreign, community owned formats it does not own the schema of), so no
  trimming is required for the decode to succeed. It carries two attestations:
  npm's own publish attestation
  (`https://github.com/npm/attestation/tree/main/specs/publish/v0.1`) and a
  SLSA provenance attestation (`https://slsa.dev/provenance/v1`); smithmark's
  discovery layer identifies and returns only the latter as
  `Discovered.NPMProvenance`.
- **Pinned integrity conversion**: `pkg/discover/npm_internal_test.go`'s
  `TestNPMIntegrityToHexPinnedVector` converts this fixture's own
  `dist.integrity` value to hex independently (by hand, outside the
  implementation) and asserts the two agree, so the sha512 base64 to hex
  conversion (U6) is pinned against a real value, not merely self consistent.

## MCP Registry discovery fixtures (`registry/`)

`registry/entry_npm.json` and `registry/entry_remote.json` are real MCP
Registry API response snapshots, fetched once during Task 3.6's development
(network access is allowed for a maintainer preparing fixtures; it is never
allowed in CI or in a test). `registry/sentry_packument.json` is a real npm
registry response supporting the same task's npm continuation test; it
follows the exact trimming convention `npm/packument.json` above already
established.

- **Snapshot date**: 2026-07-17.
- **Registry API shape verified before fetching**: `smithmark` does not
  assume the MCP Registry's API shape; its published OpenAPI description
  (`GET https://registry.modelcontextprotocol.io/openapi.yaml`) was fetched
  and read during this task's development to confirm it. The operation
  `pkg/discover/registry.go`'s `FetchRegistryEntry` uses is "get specific MCP
  server version" (`GET /v0/servers/{serverName}/versions/{version}`, using
  the special version value `latest`), whose path parameter is documented as
  a server name encoded for the URL (the OpenAPI example is literally
  `com.example%2Fmy-server`); `FetchRegistryEntry` percent encodes the name
  with `url.PathEscape` before building the request for exactly this reason,
  since a real server name such as `io.github.getsentry/sentry-mcp` would
  otherwise split across path segments and never match the route. A search
  endpoint also exists (`GET /v0/servers?search=...`, substring match on
  name), used only to find real candidate entries during fixture preparation,
  never called by `FetchRegistryEntry` itself.
- **`entry_npm.json`**: `io.github.getsentry/sentry-mcp` version `0.25.0`
  (Sentry's official MCP server), chosen because it is a real, well known
  registry entry whose only distribution shape is a single npm package
  (`@sentry/mcp-server`), the npm backed case `registry check`'s command
  pipeline continues into the shared verification pipeline for. Committed
  verbatim (undisturbed field values; only whitespace differs from the live
  response), since `FetchRegistryEntry` decodes it leniently (a plain
  `json.Unmarshal`, matching how this codebase already treats every other
  foreign, community owned format it does not control the schema of: npm's
  packument and attestations responses above, package.json's `smithmark` key,
  SKILL.md frontmatter). It carries no attestation reference field, which is
  exactly the gap `REGISTRY_ATTESTATION_REF_PRESENT` demonstrates.
  - **Source request**:
    `GET https://registry.modelcontextprotocol.io/v0/servers/io.github.getsentry%2Fsentry-mcp/versions/latest`
- **`entry_remote.json`**: `com.notion/mcp` version `1.0.1` (Notion's
  official MCP server), chosen because it is a real, well known registry
  entry whose only distribution shape is two remote endpoints
  (`streamable-http` and `sse`) and no packages at all: the remote only case
  `HOSTED_ENDPOINT_UNSUPPORTED` demonstrates. Committed verbatim for the same
  lenient decode reason as `entry_npm.json` above.
  - **Source request**:
    `GET https://registry.modelcontextprotocol.io/v0/servers/com.notion%2Fmcp/versions/latest`
- **`sentry_packument.json`**: a real npm registry response for
  `@sentry/mcp-server`, trimmed down the same way `npm/packument.json` above
  is: only `dist.integrity` and `dist.tarball` are ever read by
  `pkg/discover/npm.go`, so the fixture keeps the top level `name`,
  `dist-tags`, and a handful of realistic noise fields (`author`, `license`,
  `homepage`, `keywords`, `maintainers`, a trimmed `time` block), and, for the
  single `0.25.0` version entry (the version `entry_npm.json` names), `name`,
  `version`, a trimmed `scripts` block, and the full `dist` block. This
  supports the npm continuation test only (`cmd/smithmark/registry_test.go`'s
  `TestRegistryCheckNPMBackedMissingAttestationExitsOne`): the npm
  attestations endpoint for this package version is served a canned 404 in
  that test regardless of whatever the real endpoint currently returns
  (matching how `cmd/smithmark/verify_test.go`'s own `npmMissingTransport`
  already serves a canned 404 for its unrelated npm fixture package), so the
  test exercises discovery and check merging against the standard missing
  attestation outcome rather than fabricating a full passing npm
  verification chain the committed fixtures were never signed to support.
  - **Source request**: `GET https://registry.npmjs.org/@sentry/mcp-server`

## First party server snapshots (M6)

`servers/better-call-claude/` and `servers/dear-claude/` are trimmed snapshots of the
real MCP servers, taken 2026-07-17 from the local checkouts at commit state of that date
(better-call-claude 3.1.1, dear-claude 1.1.0). Snapshot scope, approved by the maintainer:
`src/**/*.ts`, `server.json`, `package.json`, `bun.lock`, and `LICENSE` per repo.

Deliberately excluded and never committed: the `.mcpregistry_github_token` and
`.mcpregistry_registry_token` files, `node_modules`, `dist`, `.git`, `.idea`, `.claude`,
`.DS_Store`, the `mcp-publisher` binary, `assets/`, and `data/`. The staged snapshot was
scanned for secret shaped content, embedded credentials in the lockfiles, and local path
leakage before committing; all clean. `server.json` carries only environment variable
names, never values.
