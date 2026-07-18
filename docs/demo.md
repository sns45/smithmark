# Demo: an agent runtime refusing a misdeclared MCP server, live

This is the spec section 11 self demonstrating launch: an agent runtime that
declines to load a misdeclared MCP server, with an explainable deny, and admits
a valid signed one. That is exactly the admission the trust as code family
enables. The trilogy verifies the supply chain; smithmark extends the same
discipline to the tools the agents themselves wield.

Everything below was run offline on 2026-07-18 and captured verbatim. Every
command, exit code, and line of output is real terminal output, pasted as it
happened. Nothing here is hand authored to look like a run. Where a step cannot
complete offline, that is stated plainly and the real failure is shown rather
than hidden. The only edit applied to any pasted output is cosmetic: the
machine specific absolute path of the checkout is shortened to `...` in section
4, so the reason strings fit the page; nothing else is altered.

The two servers under test are committed fixtures:

- `testdata/servers/misdeclared-server/` is a real, validly signed MCP server
  whose `smithmark.yaml` declares zero network egress, while its `src/index.ts`
  calls `fetch` to an exfiltration host. The signature and subject digest are
  entirely honest; only the capability declaration is a lie.
- `testdata/servers/better-call-claude/` is a real, validly signed MCP server
  (voice calls, SMS, and WhatsApp for Claude Code) whose `smithmark.yaml` was
  authored by reading its own vendored source, so every declared capability is
  one the code actually exercises.

Both attestations verify against the throwaway dogfood public key at
`testdata/servers/dogfood-signing-key-pub.pem`.

## The offline boundary, stated up front

One seam cannot be closed offline for these fixtures, and it matters for
reading the runs below honestly.

`smithmark verify` resolves an npm distributed MCP server's subject digest from
the npm registry, because verification must check the artifact a consumer would
actually install, not whatever sits on disk in a local checkout (this is a
deliberate design divergence from `attest`, documented in
`pkg/discover/resolve.go`). The two committed server fixtures carry deliberately
synthetic subject digests (`bad0...`, `bcc0...`) so that the pure verification
core can be exercised over them by direct injection, offline, with no network.
Those synthetic digests do not round trip through the CLI's own discovery, which
resolves the true npm digest instead. So the full CLI `verify` path cannot
stitch signature, digest, and capability lint into a single invocation offline
for a fixture that was never published to npm under its synthetic digest.

What that leaves is a demo assembled from real parts, each run through the real
tool offline:

1. the capability gap itself, live, through the real CLI (section 1);
2. the full admission decision over the real signed server bundles, end to end,
   offline, through the pure verification core the CLI and hook both consume
   (section 2);
3. the Claude Code hook emitting a real, explainable deny and a real allow
   (section 3);
4. the hook driven at the two real MCP server fixtures, showing exactly what
   happens and where the offline seam falls (section 4).

The binary under test is a plain `go build` of `./cmd/smithmark` (version
`dev`). Set once for the runs below:

```
$ SMITHMARK_BIN=$(mktemp -d)/smithmark
$ go build -o "$SMITHMARK_BIN" ./cmd/smithmark
```

## 1. The capability gap, live, offline

`smithmark lint` statically scans a server's own source for capabilities its
declaration does not cover, and names each as an `UNDECLARED_` finding. It never
executes the artifact. This is the substance of the deny: the misdeclared server
reaches out to the network from code its manifest swears it does not.

```
$ "$SMITHMARK_BIN" lint testdata/servers/misdeclared-server
high    UNDECLARED_NETWORK_EGRESS     network egress via fetch is not declared in capabilities.networkEgress  (src/index.ts:19)
1 finding(s)
EXIT=0
```

The same scan over the honestly declared server finds nothing:

```
$ "$SMITHMARK_BIN" lint testdata/servers/better-call-claude
0 finding(s)
EXIT=0
```

`lint` exits 0 in both cases by design: a finding is advisory, not a verdict.
Turning a finding into a block is a policy act, and it belongs to `verify
--strict` and to assayward, never to `lint` itself.

## 2. The full admission decision, end to end, offline

The decision the hook actually consumes is the pure verification core: verify
the DSSE signature against the trust root, confirm the attested subject digest,
validate the capability manifest, attach the capability lint findings, and apply
the decision D4 exit contract. The committed dogfood test drives exactly this,
over the real signed server bundles and the committed dogfood public key, with
no network and without ever executing a server:

```
$ go test ./cmd/smithmark/ -run 'TestDogfood' -v
=== RUN   TestDogfoodAttestationsVerifyOffline
=== RUN   TestDogfoodAttestationsVerifyOffline/better-call-claude
=== RUN   TestDogfoodAttestationsVerifyOffline/dear-claude
=== RUN   TestDogfoodAttestationsVerifyOffline/misdeclared-server
--- PASS: TestDogfoodAttestationsVerifyOffline (0.05s)
    --- PASS: TestDogfoodAttestationsVerifyOffline/better-call-claude (0.02s)
    --- PASS: TestDogfoodAttestationsVerifyOffline/dear-claude (0.02s)
    --- PASS: TestDogfoodAttestationsVerifyOffline/misdeclared-server (0.00s)
=== RUN   TestDogfoodMisdeclaredServerBlocksUnderStrict
--- PASS: TestDogfoodMisdeclaredServerBlocksUnderStrict (0.00s)
PASS
ok  	github.com/sns45/smithmark/cmd/smithmark	0.675s
GO_TEST_EXIT=0
```

For each server this proves, offline, against the committed dogfood key:

- `SIGNATURE_VALID`, `SUBJECT_DIGEST_MATCH`, and `MANIFEST_SCHEMA_VALID` all
  pass. The misdeclared server is a real, validly signed MCP server; its
  cryptography is honest.
- the capability lint over its source produces exactly the expected finding
  set: empty for the two honestly declared servers, and exactly
  `UNDECLARED_NETWORK_EGRESS` for the misdeclared one.
- the exit contract holds: a passing verification exits 0 without `--strict`,
  and the misdeclared server exits 2 under `--strict` on the capability gap
  alone, while the valid server stays at 0. Exit 2 is the block the hook keys
  off; exit 0 is the allow.

This is the whole claim, demonstrated: a validly signed server blocked on the
gap between what it declares and what its code can do, and a validly signed
server admitted. The signature caught nothing here, because nothing about the
signature was wrong; the capability manifest is what carried the lie, and the
capability layer is what caught it.

## 3. The Claude Code hook: a real, explainable deny and allow

`surfaces/claude-code-hook/verify-mcp.sh` is the reference runtime shim: a
Claude Code `PreToolUse` hook that runs `smithmark verify --strict` before an
MCP tool call and returns the structured `permissionDecision` JSON Claude Code
reads. Its own offline suite drives synthetic `PreToolUse` payloads through it
over committed, signed fixtures and asserts the real decisions:

```
$ bash surfaces/claude-code-hook/test.sh
=== Building smithmark binary ===
Binary built: /tmp/smithmark-hook-test-45478

=== Test 1: misdeclared skill as MCP server (expect deny, blocking) ===
  PASS: block path hook exit: exit code 0 (expected 0)
  PASS: block path decision: .hookSpecificOutput.permissionDecision = 'deny' (expected 'deny')
  PASS: block path reason names server: contains 'misdeclared'
  PASS: block path stderr names finding code: contains 'UNDECLARED_NETWORK_EGRESS'
  PASS: block path stderr says BLOCK: contains 'smithmark hook: BLOCK'

=== Test 2: valid hello skill as MCP server (expect allow) ===
  PASS: allow path hook exit: exit code 0 (expected 0)
  PASS: allow path decision: .hookSpecificOutput.permissionDecision = 'allow' (expected 'allow')
  PASS: allow path stderr says ALLOW: contains 'smithmark hook: ALLOW'

=== Test 3: non MCP tool call (expect exit 0, no decision) ===
  PASS: non mcp tool exit: exit code 0 (expected 0)
  PASS: non mcp tool: no decision JSON printed

=== Test 4: unconfigured MCP server (expect deny, fail closed) ===
  PASS: unconfigured server exit: exit code 0 (expected 0)
  PASS: unconfigured server decision: .hookSpecificOutput.permissionDecision = 'deny' (expected 'deny')
  PASS: unconfigured server stderr distinguishes could not verify: contains 'COULD NOT VERIFY'
  PASS: unconfigured server stderr says failing closed: contains 'failing closed'

=== Test 5: unconfigured MCP server with SMITHMARK_HOOK_ALLOW_ON_ERROR=true (expect allow) ===
  PASS: permissive override exit: exit code 0 (expected 0)
  PASS: permissive override decision: .hookSpecificOutput.permissionDecision = 'allow' (expected 'allow')
  PASS: permissive override stderr mentions the override: contains 'SMITHMARK_HOOK_ALLOW_ON_ERROR'

=== Test 6: real smithmark verify exit 3 (nonexistent artifact, no bundle), offline (expect deny naming DISCOVERY_FAILED) ===
  PASS: real exit 3 hook exit: exit code 0 (expected 0)
  PASS: real exit 3 decision: .hookSpecificOutput.permissionDecision = 'deny' (expected 'deny')
  PASS: real exit 3 stderr names DISCOVERY_FAILED: contains 'DISCOVERY_FAILED'
  PASS: real exit 3 stderr distinguishes could not verify: contains 'COULD NOT VERIFY'
  PASS: real exit 3 stderr says failing closed: contains 'failing closed'

=== Test 7: real smithmark verify exit 3 with SMITHMARK_HOOK_ALLOW_ON_ERROR=true (expect allow) ===
  PASS: real exit 3 override exit: exit code 0 (expected 0)
  PASS: real exit 3 override decision: .hookSpecificOutput.permissionDecision = 'allow' (expected 'allow')
  PASS: real exit 3 override stderr mentions the override: contains 'SMITHMARK_HOOK_ALLOW_ON_ERROR'

=== Test 8: jq missing on PATH (expect raw exit 2 block; ALLOW_ON_ERROR does not leak in) ===
  PASS: jq missing exit: exit code 2 (expected 2)
  PASS: jq missing stderr message: contains 'jq is required'
  PASS: jq missing: no JSON decision printed (raw exit code mechanism only)

========================================
Results: 28 passed, 0 failed
========================================
All tests passed.
HOOK_TEST_EXIT=0
```

Test 1 is the live, explainable deny: the hook runs `smithmark verify --strict`,
gets exit 2, and returns a `deny` decision whose stderr names
`UNDECLARED_NETWORK_EGRESS` by code. Test 2 is the allow. These drive the hook
over signed skill fixtures, because a skill's subject digest is recomputed
locally by the bundle walker, so the whole verification completes offline. An
npm distributed MCP server's subject digest is not (section 4). The hook logic
is identical for either artifact kind: `verify`'s report shape and exit contract
do not differ by kind, so the same block path that names
`UNDECLARED_NETWORK_EGRESS` for the signed skill above is the exact path a signed
MCP server takes once its digest resolves.

## 4. Driving the hook at the real MCP servers, and the offline seam

Pointing the same hook at the two real MCP server fixtures shows precisely where
the offline seam falls. The sidecar config maps each server name to its
committed artifact directory, attestation bundle, and the dogfood trust root,
then a synthetic `PreToolUse` payload is piped in, exactly as Claude Code would.

The misdeclared server:

```
$ printf '%s' "$PAYLOAD_misdeclared" | env \
    SMITHMARK_BIN="$SMITHMARK_BIN" SMITHMARK_HOOK_CONFIG="$CFG" \
    bash surfaces/claude-code-hook/verify-mcp.sh
--- HOOK EXIT: 0
--- HOOK STDOUT (the decision JSON Claude Code reads):
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "could not verify, denied by default (fail closed): smithmark verify exited 3 for MCP server 'misdeclared-server' (artifact .../testdata/servers/misdeclared-server), code=DISCOVERY_FAILED: DISCOVERY_FAILED: fetching packument for misdeclared-server: unexpected status 404 Not Found"
  }
}
--- HOOK STDERR (the human explanation):
smithmark hook: COULD NOT VERIFY (this is not the same as VERIFICATION FAILED), failing closed: smithmark verify exited 3 for MCP server 'misdeclared-server' (artifact .../testdata/servers/misdeclared-server), code=DISCOVERY_FAILED: DISCOVERY_FAILED: fetching packument for misdeclared-server: unexpected status 404 Not Found
smithmark hook: set SMITHMARK_HOOK_ALLOW_ON_ERROR=true to allow when a check cannot be completed instead.
```

The misdeclared server is denied. But read the reason honestly: this is a fail
closed deny, not the capability gap block. `smithmark verify` tried to resolve
the server's true published digest from the npm registry, the fixture was never
published, so discovery returned a 404 and exited 3. The hook names that plainly
as `COULD NOT VERIFY`, which it deliberately distinguishes from `VERIFICATION
FAILED`, and it fails closed, because an admission decision that could not run
should never look like an approval. A safe deny, but for an operational reason,
not the declared versus real capability gap.

The valid server does not admit cleanly either, and for an instructive reason:

```
$ printf '%s' "$PAYLOAD_better_call_claude" | env \
    SMITHMARK_BIN="$SMITHMARK_BIN" SMITHMARK_HOOK_CONFIG="$CFG" \
    bash surfaces/claude-code-hook/verify-mcp.sh
--- HOOK EXIT: 0
--- HOOK STDOUT (the decision JSON Claude Code reads):
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "smithmark verify blocked MCP server 'better-call-claude' (artifact .../testdata/servers/better-call-claude): SUBJECT_DIGEST_MATCH"
  }
}
--- HOOK STDERR (the human explanation):
smithmark hook: BLOCK: MCP server 'better-call-claude' (artifact .../testdata/servers/better-call-claude) failed smithmark verify (exit 1).
smithmark hook: failed checks and undeclared findings from the verify report:
  FAILED_CHECK  SUBJECT_DIGEST_MATCH: attested subject digest does not match the artifact: expected {sha512:5950c2f05c3936b8584b8989316a58b8dca86e4bfac00548b85e5a7b591f3198b66e759aa992440de6616f0acd351f26f5c79bd4c89dc16fa6a4e6742059e9ce}, attested {sha512:bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0bcc0}
```

`better-call-claude@3.1.1` is a genuinely published npm package, so here discovery
did resolve a true published digest, `5950c2...`. That true digest does not
match the fixture's synthetic attested digest, `bcc0...`, so
`SUBJECT_DIGEST_MATCH` fails and the hook blocks on exit 1. This is the hook
correctly refusing an attestation whose subject does not match the artifact on
the registry, which is exactly what a subject digest check is for. It is just
not the admission this fixture was built to show, because the fixture's synthetic
digest was minted for direct core verification (section 2), not for a round trip
through registry discovery.

So the offline seam is precisely this: the capability gap block of a signed MCP
server, driven all the way through the CLI and the hook in one invocation, needs
the server's attested digest to be the digest discovery resolves. For these
throwaway fixtures that means either publishing them to npm under their real
digest, or the M6 live trust root and registry wiring that verifies against a
pinned bundle without a registry round trip. Until one of those lands, the three
real parts stand on their own: the gap is real (section 1), the signed server's
capability block is real and proven offline (section 2), and the hook's
explainable deny and allow are real (section 3).

## What this demonstrates

An agent runtime can refuse to load an MCP server whose declared capabilities do
not match what its code can do, live, with a machine readable reason a person or
a policy engine can act on. The signature was never the whole story: a validly
signed server can still be misdeclared, and the capability layer is what closes
that gap. smithmark produces the evidence; assayward consumes it; the Claude Code
hook is the smallest faithful stand in for that admission loop inside an agent
runtime.

Reproduce every run above from a clean checkout:

```
$ go build -o /tmp/smithmark ./cmd/smithmark
$ /tmp/smithmark lint testdata/servers/misdeclared-server
$ /tmp/smithmark lint testdata/servers/better-call-claude
$ go test ./cmd/smithmark/ -run 'TestDogfood' -v
$ bash surfaces/claude-code-hook/test.sh
```
