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

## Fixture inventory

For each of two subjects, five variants are generated:

- `signature/skill/` attests the `skills/hello-skill` fixture: a `skill` kind,
  `local` source subject whose subject digest is the true canonical bundle
  digest of that directory.
- `signature/npm/` attests the synthetic `fake-caller` `1.0.0` identity: an
  `mcp-server` kind, `npm` source subject whose subject digest is a fabricated
  fixed sha512 hex string. No real tarball exists; verification consumes the
  bundle plus an expected digest, so a fabricated digest is sufficient.

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
