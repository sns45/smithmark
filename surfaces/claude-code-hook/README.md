# Claude Code hook: verify MCP servers before use

This is the reference runtime shim spec section 7 calls for: "one shim, well
documented; the pattern generalizes, the repo does not chase every runtime."
It wires `smithmark verify` into Claude Code as a Claude Code hook, so an
agent runtime can refuse to load an unattested or misdeclared MCP server with
an explainable deny, live, rather than trusting it silently. This is the
admission demo named in requirements.md section 11: assayward is the policy
engine smithmark's report exists to feed, and this hook is the smallest
faithful stand in for that admission loop inside Claude Code itself.

## What it does

`verify-mcp.sh` is a Claude Code `PreToolUse` hook. On a matching call it:

1. Reads the tool call's `tool_name` from stdin and pulls out the MCP server
   name (the identity between `mcp__` and the following `__`).
2. Looks up which artifact that server maps to, plus its trust root and an
   optional bundle path, from a small JSON config (see below).
3. Runs `smithmark verify --strict --output json` against that artifact.
4. Allows the call when verify exits 0. Blocks it, with the failed checks and
   any `UNDECLARED_` findings named by code, when verify exits 1 (a failing
   check did not pass) or 2 (a passing verification carried an undeclared
   capability finding under `--strict`, decision D4 in `docs/decisions.md`).
5. Fails closed (blocks) when verify could not even complete, exit 3, or when
   this hook cannot resolve a configuration or a binary to run at all. This
   is deliberately distinct from a check that ran and failed; see "Fail
   closed by default" below.

`smithmark verify` never executes the artifact it checks (carried posture
U2, `docs/decisions.md`). It reads a signed attestation, verifies the
signature and subject digest, validates the declared capability manifest, and
statically lints the artifact's own source for capability gaps when one is
available locally. Nothing in this hook, and nothing in smithmark, ever runs
the MCP server's own code to decide whether to admit it. That is what makes
this admission, not sandboxing: it is a supply chain gate on what gets
loaded, not a runtime containment boundary around what a loaded server can
do. A misdeclared server that passes this gate (its capability lint has no
static detector for every code path, and secrets have no detector at all in
v0.1, per `docs/codes.md`) is a known limitation of static admission, not a
promise this hook does not make.

## The Claude Code hook contract this shim targets

Verified against the current Claude Code hooks documentation at
implementation time: `https://docs.claude.com/en/docs/claude-code/hooks`,
which redirects to `https://code.claude.com/docs/en/hooks`.

There is no hook event dedicated to "an MCP server's first use." The event
that fires before any tool call, built in or MCP, and that can block it, is
`PreToolUse`. This shim is wired to `PreToolUse` with a matcher scoped to MCP
tool calls (`mcp__.*`, see `settings.example.json`), the documented reference
pattern for gating MCP tools; it runs on every matching call rather than
strictly the first, which this reference shim accepts since `smithmark
verify` is read only and cheap.

Confirmed facts from that documentation, matched line for line by
`verify-mcp.sh`:

- **stdin**: a JSON object on the hook's standard input, including at least
  `session_id`, `cwd`, `permission_mode`, `hook_event_name` (`"PreToolUse"`),
  `tool_name`, and `tool_input`. This hook reads only `tool_name`.
- **MCP tool naming**: an MCP tool's `tool_name` has the shape
  `mcp__<server>__<tool>` (a plugin bundled server instead reads
  `mcp__plugin_<plugin>_<server>__<tool>`); either way the server identity is
  everything between the leading `mcp__` and the following `__`.
  `CLAUDE_PROJECT_DIR` is also guaranteed to be set in a hook's environment,
  which this shim uses to anchor its default config path.
  Both facts are documented in the hooks reference.
- **Blocking mechanism**: `PreToolUse` supports two, mutually exclusive
  mechanisms, and the documentation is explicit that a hook uses one or the
  other, never both in one invocation. Exit code 2 alone blocks the call,
  with stderr treated as the reason. Alternatively, exiting 0 and printing a
  JSON object to stdout carrying:
  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "deny",
      "permissionDecisionReason": "<why>"
    }
  }
  ```
  lets the hook return a structured decision, one of the four documented
  `permissionDecision` values, `allow`, `deny`, `ask`, or `defer`, with an
  explanation. This shim only ever emits two of the four: `allow` or `deny`;
  it never returns `ask` or `defer`, since every branch below resolves to a
  definite admission decision rather than deferring to the user or another
  layer. This shim uses the second mechanism for every decision it
  can actually make, since it wants the structured, explainable reason; the
  raw exit code 2 mechanism is reserved for the one situation where this
  hook cannot safely produce JSON at all (`jq` missing, see below). A hook
  process therefore normally exits 0 even when its decision is `deny`; the
  block happens through the JSON body, exactly as Claude Code's own
  documentation examples do it.

## Wiring it up

Merge `settings.example.json` into your project's `.claude/settings.json`
(or your user level `~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "\"${CLAUDE_PROJECT_DIR}/surfaces/claude-code-hook/verify-mcp.sh\""
          }
        ]
      }
    ]
  }
}
```

`${CLAUDE_PROJECT_DIR}` is a path placeholder Claude Code expands to the
project root before running the command, so the hook resolves correctly
regardless of the shell's own working directory when Claude Code launches
it. The braced, double quoted form matches the documentation's own
convention for a shell form path placeholder, so a project root containing
a space still resolves to one argument rather than splitting apart.

An adopter wiring this into a project other than smithmark itself must
account for one thing: `${CLAUDE_PROJECT_DIR}` resolves to the consuming
project's own root, not to smithmark's checkout, so the settings snippet
above only resolves as written when it runs from inside a checkout of
smithmark itself. Adopting it elsewhere means either vendoring
`verify-mcp.sh` into that project's own repository at the same relative
path, or pointing the command at an absolute path to wherever smithmark's
checkout actually lives.

## Configuring which artifact a server maps to

The hook needs to know, for a given MCP server name, which artifact to run
`smithmark verify` against. This lives in a small JSON sidecar, resolved in
this order:

1. `SMITHMARK_HOOK_CONFIG`, an explicit path to the sidecar file, when set.
2. Otherwise `${CLAUDE_PROJECT_DIR}/.smithmark/mcp-servers.json` (or, with
   `CLAUDE_PROJECT_DIR` unset, `./.smithmark/mcp-servers.json` relative to
   wherever the hook runs).

Shape, keyed by server name (the identity extracted from `tool_name`):

```json
{
  "weather": {
    "artifact": "@example-org/mcp-server-weather@1.4.0",
    "trustRoot": "trust/smithmark-signing-key-pub.pem",
    "bundle": "",
    "attestationBase": "registry.example.com/attest"
  }
}
```

- `artifact` (required): anything `smithmark verify`'s positional argument
  accepts: an npm `name@version`, a local artifact directory, or an OCI
  reference.
- `trustRoot` (optional): maps to `--trust-root`, a PEM public key path.
  Required whenever an attestation bundle is actually discovered or
  supplied; `smithmark verify` itself fails closed with a configuration
  error if bundles exist and no trust root was given.
- `bundle` (optional): maps to `--bundle`, an explicit attestation bundle
  file, bypassing discovery.
- `attestationBase` (optional): maps to `--attestation-base`, the OCI
  registry base for attestation discovery.

A plugin bundled server's `tool_name` carries the shape
`mcp__plugin_<plugin>_<server>__<tool>` (documented above), so the identity
this hook extracts for such a server is the full `plugin_<plugin>_<server>`
string, not the bare `<server>` name alone. A sidecar entry for a plugin
bundled server must therefore be keyed by that full string, for example
`"plugin_acme_weather"` for plugin `acme`'s server `weather`, never by
`"weather"` on its own; using the bare name would leave the entry unreached,
falling through to "no configured artifact" for that server. This follows
directly from the documentation's own matcher guidance for plugin scoped
MCP tools (`mcp__plugin_<plugin>_<server>__.*`), which addresses a plugin
bundled server the same, full way.

Relative paths inside the sidecar (`trustRoot`, `bundle`, a local `artifact`
directory) are passed straight through to `smithmark verify` and resolved
relative to the hook's own working directory, ordinarily the project root;
use absolute paths if that is not what you want.

A server absent from the sidecar (or no sidecar file at all) falls back to
plain environment variables, useful for a single server setup or a scripted
test: `SMITHMARK_HOOK_ARTIFACT`, `SMITHMARK_HOOK_TRUST_ROOT`,
`SMITHMARK_HOOK_BUNDLE`, `SMITHMARK_HOOK_ATTESTATION_BASE`. A server that
resolves no artifact from either source could not be checked at all (see
below).

## Security posture

**Fail closed by default.** A check that could not run to completion, an
operational failure (`smithmark verify` exit 3), an unresolved server
configuration, or a missing `smithmark` binary, is not the same thing as a
check that ran and reported a failure. This hook still denies by default in
that situation, because an unattested admission decision should never look
like an approval, but it names the distinction plainly on stderr: "COULD NOT
VERIFY" rather than "VERIFICATION FAILED."

**Permissive override.** Set `SMITHMARK_HOOK_ALLOW_ON_ERROR=true` to allow
instead of deny when a check could not be completed at all. This does not
relax verification itself; a completed verification that actually fails, or
that flags an undeclared finding under `--strict`, is still always denied
regardless of this variable. It only changes what happens when the gate
could not run.

**Admission, not sandboxing.** As noted above, verify never executes the
artifact under test; it is a supply chain gate on what gets loaded, not a
containment boundary around what a loaded server does once admitted. Pair
it with assayward policy and, for anything stronger than admission, an
actual runtime sandbox; this hook does not claim to be one (requirements.md
section 1.3 states the same non goal for smithmark itself).

**`jq` is required.** The hook parses both its own stdin and the verify JSON
report with `jq`. Without `jq` on `PATH` it cannot safely produce a JSON
decision at all, so it falls back to the raw exit code 2 block mechanism
with a stderr explanation, rather than risk emitting a malformed decision.
Install `jq` to get the full, explainable deny path.

## Exit code mapping

| `smithmark verify` exit | Meaning | Hook decision |
| --- | --- | --- |
| `0` | verification passed | `allow` |
| `1` | a failing class check did not pass | `deny`, checks named on stderr |
| `2` | `--strict` flagged an `UNDECLARED_` finding on an otherwise passing verification | `deny`, findings named on stderr |
| `3` (or unexpected) | operational failure, could not check | `deny` by default (fail closed); `allow` with `SMITHMARK_HOOK_ALLOW_ON_ERROR=true` |

## Running the test suite

```
bash surfaces/claude-code-hook/test.sh
```

`test.sh` builds `smithmark` locally with `go build` and drives
`verify-mcp.sh` with synthetic `PreToolUse` payloads over the repository's
own committed fixtures; nothing it does touches the network.

## The M6 note: no signed misdeclared MCP server fixture yet

`test.sh` demonstrates the block path against the signed, misdeclared
**skill** fixture (`testdata/skills/misdeclared-skill`, via `--bundle`), not
an MCP server, and the allow path against the valid `testdata/skills/hello-skill`
bundle. Both are configured in the test as if they were the artifact behind
a distinct MCP server name; the hook itself does not care about artifact
kind, only about whatever artifact reference its config points a server
name at.

This is a carried, binding M4 obligation, not an oversight:
`testdata/misdeclared` is an unsigned, npm shaped MCP server fixture whose
declaration cannot complete attestation discovery offline, and no signed
misdeclared MCP server fixture exists yet. See the M4 amendment in
`docs/decisions.md` ("the M6 Claude Code hook demo needs a SIGNED,
misdeclared `mcp-server` fixture to block, and that does not exist yet").
The real MCP server demo, an actual `smithmark attest`ed and signed server
package with a misdeclared capability, lands in milestone M6 once that
fixture is minted; this hook's logic already handles it identically to the
skill case today, since verify's report shape and exit contract do not
differ by artifact kind.
