#!/usr/bin/env bash
# verify-mcp.sh: reference Claude Code PreToolUse hook that gates MCP tool
# calls behind smithmark verify (spec 7, "one shim, well documented").
#
# Contract verified against the current Claude Code hooks documentation
# (code.claude.com/docs/en/hooks, redirected there from
# docs.claude.com/en/docs/claude-code/hooks) at implementation time. There is
# no event dedicated to "an MCP server's first use"; PreToolUse fires before
# every tool call, built in or MCP, and can block it, so this hook is wired to
# PreToolUse with a matcher scoped to MCP tool calls (see
# settings.example.json). It runs on every matching call, not only the first,
# which is fine here since smithmark verify is read only and cheap; nothing in
# this reference shim assumes "first" beyond that framing.
#
# stdin: the PreToolUse JSON payload. The field this hook reads is tool_name,
# which for an MCP tool carries the shape mcp__<server>__<tool> (a plugin
# bundled server instead reads mcp__plugin_<plugin>_<server>__<tool>; either
# way the server identity is everything between the leading "mcp__" and the
# next "__").
#
# Decision output: exactly one hookSpecificOutput JSON object on stdout,
# following exit 0, the shape Claude Code parses for a PreToolUse decision:
#   {"hookSpecificOutput": {"hookEventName": "PreToolUse",
#     "permissionDecision": "allow" | "deny",
#     "permissionDecisionReason": "<human readable reason>"}}
# Claude Code only reads this JSON when the hook exits 0; the documentation is
# explicit that exit 2 and a JSON decision are not combined in one invocation,
# so every branch of this script below that has something to decide exits 0.
# Exit 2 (the raw, non JSON block mechanism) is reserved for the one case this
# script cannot safely produce JSON for at all: jq missing from PATH.
#
# A human readable explanation always additionally goes to stderr: which
# checks failed, and which UNDECLARED_ findings fired with their codes, so a
# person watching the session (or this repo's own test.sh) sees the full
# reasoning, not just the compact reason string Claude Code surfaces.
#
# Configuration: which artifact a given MCP server name maps to, plus its
# trust root and optional bundle path, comes from a small JSON sidecar (see
# README.md, "Configuring which artifact a server maps to"), with a plain
# environment variable fallback for a single server setup. See README.md for
# the full posture: this hook fails closed by default when it cannot complete
# a check at all, distinct from a check that ran and failed.
set -euo pipefail

# ---------------------------------------------------------------------------
# Decision helpers. Each one prints the Claude Code decision JSON to stdout
# and exits 0; the caller never returns from these.
# ---------------------------------------------------------------------------

# allow_decision <reason>: emit an allow decision and exit 0.
allow_decision() {
  local reason="$1"
  echo "smithmark hook: ALLOW: ${reason}" >&2
  jq -n --arg reason "${reason}" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: $reason}}'
  exit 0
}

# deny_decision <reason>: emit a deny decision and exit 0. Callers are
# expected to have already printed the detailed, multi line explanation to
# stderr before calling this; it does not print anything of its own beyond
# the JSON decision itself.
deny_decision() {
  local reason="$1"
  jq -n --arg reason "${reason}" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: $reason}}'
  exit 0
}

# could_not_check <reason>: the operational case, smithmark verify itself
# could not run to completion (exit 3), or this hook could not even resolve
# what to verify (missing configuration, missing binary). This is distinct
# from a check that ran and failed: the artifact was never actually examined.
# Fails closed (deny) by default; set SMITHMARK_HOOK_ALLOW_ON_ERROR=true to
# allow instead when a check cannot be completed.
could_not_check() {
  local reason="$1"
  if [[ "${SMITHMARK_HOOK_ALLOW_ON_ERROR:-false}" == "true" ]]; then
    echo "smithmark hook: COULD NOT VERIFY (this is not the same as VERIFICATION FAILED): ${reason}" >&2
    echo "smithmark hook: SMITHMARK_HOOK_ALLOW_ON_ERROR is true, so allowing despite the unresolved check." >&2
    allow_decision "could not verify, allowed because SMITHMARK_HOOK_ALLOW_ON_ERROR is set: ${reason}"
  else
    echo "smithmark hook: COULD NOT VERIFY (this is not the same as VERIFICATION FAILED), failing closed: ${reason}" >&2
    echo "smithmark hook: set SMITHMARK_HOOK_ALLOW_ON_ERROR=true to allow when a check cannot be completed instead." >&2
    deny_decision "could not verify, denied by default (fail closed): ${reason}"
  fi
}

# block_decision <report_file> <server> <artifact> <verify_exit>: smithmark
# verify ran to completion and reported a nonzero, classified outcome (1,
# verification failed, or 2, the --strict undeclared finding gate). Prints the
# failed checks and any UNDECLARED_ findings, with their codes, to stderr,
# then denies with a compact reason.
block_decision() {
  local report_file="$1" server="$2" artifact="$3" verify_exit="$4"
  echo "smithmark hook: BLOCK: MCP server '${server}' (artifact ${artifact}) failed smithmark verify (exit ${verify_exit})." >&2
  echo "smithmark hook: failed checks and undeclared findings from the verify report:" >&2

  local printed=0
  local line
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    echo "  ${line}" >&2
    printed=1
  done < <(jq -r '
      (.checks // [])[]
      | select((.informational // false) == false and .passed == false)
      | "FAILED_CHECK  \(.code): \(.detail // "no detail provided")"
    ' "${report_file}" 2>/dev/null || true)
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    echo "  ${line}" >&2
    printed=1
  done < <(jq -r '
      (.findings // [])[]
      | select(.code | startswith("UNDECLARED_"))
      | "UNDECLARED_FINDING  \(.code) at \(.location // "unknown location"): \(.detail // "no detail provided")"
    ' "${report_file}" 2>/dev/null || true)
  if [[ "${printed}" -eq 0 ]]; then
    echo "  (the verify report carried no parseable failed check or undeclared finding detail)" >&2
  fi

  local codes
  codes="$(jq -r '
      ([(.checks // [])[] | select((.informational // false) == false and .passed == false) | .code]
       + [(.findings // [])[] | select(.code | startswith("UNDECLARED_")) | .code])
      | join(", ")
    ' "${report_file}" 2>/dev/null || true)"
  deny_decision "smithmark verify blocked MCP server '${server}' (artifact ${artifact}): ${codes:-see stderr for detail}"
}

# ---------------------------------------------------------------------------
# 0. jq is required to parse both the hook's stdin and the verify JSON report.
# Without it this hook cannot safely produce a JSON decision at all, so it
# falls back to the raw exit code block mechanism (exit 2) rather than risk
# a malformed or unparsed decision.
# ---------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
  echo "smithmark hook: jq is required but was not found on PATH; blocking (fail closed) because this hook cannot safely parse its input or the verify report without it." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# 1. Read the PreToolUse payload and pull out tool_name.
# ---------------------------------------------------------------------------
INPUT_JSON="$(cat)"
TOOL_NAME="$(printf '%s' "${INPUT_JSON}" | jq -r '.tool_name // empty' 2>/dev/null)" || TOOL_NAME=""

# Not an MCP tool call: this hook has nothing to say about it. A real
# deployment should scope the PreToolUse matcher to mcp__.* (see
# settings.example.json) so this branch is defensive, not load bearing.
if [[ "${TOOL_NAME}" != mcp__* ]]; then
  exit 0
fi

# ---------------------------------------------------------------------------
# 2. Extract the MCP server identity from tool_name. The format is exactly
# mcp__<server>__<tool>: everything between the leading "mcp__" and the next
# "__" is the server name, so long as the server name itself contains no
# double underscore, true of every example in the Claude Code documentation
# (plain server names, and the mcp__plugin_<plugin>_<server>__<tool> plugin
# scoped form, both use single underscores inside the server segment).
# ---------------------------------------------------------------------------
WITHOUT_PREFIX="${TOOL_NAME#mcp__}"
SERVER="${WITHOUT_PREFIX%%__*}"

if [[ -z "${SERVER}" ]]; then
  could_not_check "could not extract an MCP server name from tool_name '${TOOL_NAME}'"
fi

# ---------------------------------------------------------------------------
# 3. Resolve which artifact this server maps to, plus its trust root and
# optional bundle path, from the JSON sidecar (config precedence: an explicit
# SMITHMARK_HOOK_CONFIG path, else <project>/.smithmark/mcp-servers.json).
# A server missing from the sidecar falls back to the plain environment
# variable form, useful for a single server setup or a scripted test. See
# README.md for the full format.
# ---------------------------------------------------------------------------
CONFIG_FILE="${SMITHMARK_HOOK_CONFIG:-${CLAUDE_PROJECT_DIR:-.}/.smithmark/mcp-servers.json}"

ARTIFACT=""
TRUST_ROOT=""
BUNDLE=""
ATTESTATION_BASE=""

if [[ -f "${CONFIG_FILE}" ]]; then
  ARTIFACT="$(jq -r --arg s "${SERVER}" '.[$s].artifact // empty' "${CONFIG_FILE}" 2>/dev/null)" || ARTIFACT=""
  TRUST_ROOT="$(jq -r --arg s "${SERVER}" '.[$s].trustRoot // empty' "${CONFIG_FILE}" 2>/dev/null)" || TRUST_ROOT=""
  BUNDLE="$(jq -r --arg s "${SERVER}" '.[$s].bundle // empty' "${CONFIG_FILE}" 2>/dev/null)" || BUNDLE=""
  ATTESTATION_BASE="$(jq -r --arg s "${SERVER}" '.[$s].attestationBase // empty' "${CONFIG_FILE}" 2>/dev/null)" || ATTESTATION_BASE=""
fi

if [[ -z "${ARTIFACT}" ]]; then
  ARTIFACT="${SMITHMARK_HOOK_ARTIFACT:-}"
  if [[ -z "${TRUST_ROOT}" ]]; then
    TRUST_ROOT="${SMITHMARK_HOOK_TRUST_ROOT:-}"
  fi
  if [[ -z "${BUNDLE}" ]]; then
    BUNDLE="${SMITHMARK_HOOK_BUNDLE:-}"
  fi
  if [[ -z "${ATTESTATION_BASE}" ]]; then
    ATTESTATION_BASE="${SMITHMARK_HOOK_ATTESTATION_BASE:-}"
  fi
fi

if [[ -z "${ARTIFACT}" ]]; then
  could_not_check "no configured artifact for MCP server '${SERVER}'; add an entry to ${CONFIG_FILE} or set SMITHMARK_HOOK_ARTIFACT (see README.md)"
fi

# ---------------------------------------------------------------------------
# 4. Resolve the smithmark binary: SMITHMARK_BIN wins, else PATH.
# ---------------------------------------------------------------------------
if [[ -z "${SMITHMARK_BIN:-}" ]]; then
  if command -v smithmark >/dev/null 2>&1; then
    SMITHMARK_BIN="$(command -v smithmark)"
  fi
fi

if [[ -z "${SMITHMARK_BIN:-}" || ! -x "${SMITHMARK_BIN}" ]]; then
  could_not_check "the smithmark binary was not found; set SMITHMARK_BIN to its path or install smithmark on PATH"
fi

# ---------------------------------------------------------------------------
# 5. Run smithmark verify --strict --output json against the configured
# artifact. The report (on a completed run) and any operational error line
# (on exit 3) land in separate temp files so both are available to the
# branches below without capturing them a second time.
# ---------------------------------------------------------------------------
REPORT_FILE="$(mktemp)"
ERR_FILE="$(mktemp)"
trap 'rm -f "${REPORT_FILE}" "${ERR_FILE}"' EXIT

VERIFY_ARGS=("verify" "--strict" "--output" "json" "${ARTIFACT}")
if [[ -n "${BUNDLE}" ]]; then
  VERIFY_ARGS+=("--bundle" "${BUNDLE}")
fi
if [[ -n "${TRUST_ROOT}" ]]; then
  VERIFY_ARGS+=("--trust-root" "${TRUST_ROOT}")
fi
if [[ -n "${ATTESTATION_BASE}" ]]; then
  VERIFY_ARGS+=("--attestation-base" "${ATTESTATION_BASE}")
fi

VERIFY_EXIT=0
"${SMITHMARK_BIN}" "${VERIFY_ARGS[@]}" >"${REPORT_FILE}" 2>"${ERR_FILE}" || VERIFY_EXIT=$?

# ---------------------------------------------------------------------------
# 6. Classify the outcome (decision D4's exit contract, as consumed here):
#   0 -> allow
#   1 or 2 -> verify ran to completion and reported a failure or a strict
#             finding flag; block with the parsed explanation
#   anything else (3, or an unexpected code) -> operational, could not check,
#             fail closed by default
# ---------------------------------------------------------------------------
case "${VERIFY_EXIT}" in
  0)
    allow_decision "smithmark verify passed for MCP server '${SERVER}' (artifact ${ARTIFACT})"
    ;;
  1 | 2)
    block_decision "${REPORT_FILE}" "${SERVER}" "${ARTIFACT}" "${VERIFY_EXIT}"
    ;;
  *)
    OP_CODE="$(jq -r '.code // empty' "${ERR_FILE}" 2>/dev/null)" || OP_CODE=""
    OP_DETAIL="$(jq -r '.detail // empty' "${ERR_FILE}" 2>/dev/null)" || OP_DETAIL=""
    could_not_check "smithmark verify exited ${VERIFY_EXIT} for MCP server '${SERVER}' (artifact ${ARTIFACT}), code=${OP_CODE:-unknown}: ${OP_DETAIL:-no detail available}"
    ;;
esac
