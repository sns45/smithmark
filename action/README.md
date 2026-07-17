# smithmark action

A GitHub composite action that runs `smithmark verify` against an agent tool artifact, an MCP server package or a skill bundle, as a supply chain check in CI.

## Quick start

```yaml
name: Verify MCP server

on:
  push:
    branches: [main]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify smithmark capability attestation
        uses: sns45/smithmark/action@v0.1
        with:
          ref: "@example-org/mcp-server-weather@1.4.0"
          attestation-base: "registry.example.com/attest"
          trust-root: "trust/smithmark-signing-key-pub.pem"
```

On every push, this resolves the named npm package, discovers its capability attestation, verifies the DSSE signature against the given trust root, and prints a report to the step log. The job fails whenever the artifact does not verify.

## Full workflow example

```yaml
name: Supply chain check

on:
  push:
    branches: [main]
  pull_request:
    branches: ["**"]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Verify smithmark capability attestation
        id: smithmark
        uses: sns45/smithmark/action@v0.1
        with:
          ref: "@example-org/mcp-server-weather@1.4.0"
          attestation-base: "registry.example.com/attest"
          trust-root: "trust/smithmark-signing-key-pub.pem"
          strict: "true"
          output: "json"
```

Because this is a composite action, the step's exit code propagates directly to the job. A failing verification or a strict lint flag fails the step, which fails the job unless you set `continue-on-error: true`.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `ref` | Yes | | The artifact to verify: an npm `name@version`, a local artifact directory, an OCI reference, or any value `smithmark verify` accepts as its positional argument. |
| `bundle` | No | | Verify this explicit attestation bundle file instead of discovering one. Maps to `--bundle`. |
| `strict` | No | `false` | Set to `true` to exit 2 when a passing verification carries any `UNDECLARED_` lint finding. Maps to `--strict`. |
| `attestation-base` | No | | Base OCI registry for attestation discovery. Falls back to `SMITHMARK_ATTESTATION_BASE` or `package.json` when unset. Maps to `--attestation-base`. |
| `trust-root` | No | | Path to a PEM public key to verify key based bundles against. Maps to `--trust-root`. |
| `certificate-identity` | No | | Expected signing certificate identity for keyless verification. Maps to `--certificate-identity`. See the M6 note below: this currently fails closed. |
| `certificate-oidc-issuer` | No | | Expected OIDC issuer for keyless verification. Maps to `--certificate-oidc-issuer`. See the M6 note below: this currently fails closed. |
| `output` | No | `summary` | Output format: `summary` or `json`. Maps to `--output`. |
| `install-from` | No | | Has two meanings, tried in this order. First: a path to an already built, executable `smithmark` binary, used directly with no download and no network call at all. This is the offline escape hatch this action's own test suite relies on (see below). Second, only when the value is not an executable file: a module version or ref, passed to `go install github.com/sns45/smithmark/cmd/smithmark@<value>`, a real network call to the Go module proxy. Either way, setting `install-from` skips the release download step entirely. |
| `version` | No | `latest` | `smithmark` release version to download (for example `v0.1.0`) when `install-from` is empty, or `latest`. See the caveat below: no release has shipped yet. |

## Exit code contract

`smithmark verify`, and this action, use exactly these exit codes. The action never remaps or masks any of them:

| Exit code | Meaning | Job outcome |
|---|---|---|
| `0` | Verification passed (every failing class check passed, or there was nothing to verify) | Job continues |
| `1` | Verification failed: at least one failing class check did not pass | Step fails with an `::error::` annotation, failing the job |
| `2` | Strict lint gate: a passing verification carried an `UNDECLARED_` finding under `strict: "true"` | Step fails with an `::error::` annotation, failing the job |
| `3` | Operational failure: bad configuration, an unusable binary, a network error, or a required input missing | Step fails with an `::error::` annotation, failing the job |

A CI author who wants to branch on the difference between a real verification failure (`1`), a strict lint flag (`2`), and an operational problem (`3`) can add a follow up step with `if: always()` that inspects `steps.<id>.outcome` or reruns the check with `continue-on-error: true` set on the verify step itself.

## Version caveat

As of this writing, `sns45/smithmark` has not published a release yet: `version: "latest"` currently resolves to nothing on the release download path, and the action falls back to `go install` (a real network call to the Go module proxy, not the release archive). Once a release ships, pin `version` to a specific tag such as `v0.1.0` for reproducible CI, rather than relying on `latest` or the `go install` fallback.

## Offline and air gapped use

Set `install-from` to skip the release download and the `go install` fallback entirely:

```yaml
- uses: sns45/smithmark/action@v0.1
  with:
    ref: "./my-skill"
    trust-root: "trust/smithmark-signing-key-pub.pem"
    install-from: "/usr/local/bin/smithmark"
```

`install-from` accepts either a path to an already built, executable `smithmark` binary, or (when the value is not an executable file) a version or ref string to pass to `go install github.com/sns45/smithmark/cmd/smithmark@<value>`.

This is exactly how `action/entrypoint_test.sh` exercises the action: it builds `smithmark` locally with `go build`, points `install-from` at that binary, and runs the entrypoint against the committed signed fixtures under `testdata/signature` and `testdata/skills`, asserting exit 0 on a validly signed skill and the appropriate nonzero exit on a tampered one and on a misdeclared one under `strict`. No network call is made anywhere in that test.

## Keyless verification: not yet supported (M6)

`certificate-identity` and `certificate-oidc-issuer` are accepted inputs, mapped straight through to `smithmark verify`, but `smithmark` fails closed on them today rather than silently ignoring them: keyless (Sigstore Fulcio and Rekor backed) verification needs the Sigstore TUF trust root wiring, which lands in milestone M6. Passing either input currently exits 3 with an explanation. Only key based verification (`trust-root` pointing at a PEM public key) is supported in v0.1.
