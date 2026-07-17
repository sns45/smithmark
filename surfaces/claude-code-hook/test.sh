#!/usr/bin/env bash
# test.sh: offline, end to end test suite for verify-mcp.sh.
#
# Usage: bash surfaces/claude-code-hook/test.sh
# Exits 0 if all assertions pass; exits nonzero on any failure.
#
# There is no signed, misdeclared mcp-server fixture yet (see docs/decisions.md,
# the M4 amendment on the M6 hook demo fixture): testdata/misdeclared is
# unsigned and cannot complete attestation discovery offline, and the only
# signed misdeclared fixture today is a skill. This suite therefore drives the
# hook's block path against the signed misdeclared skill
# (testdata/skills/misdeclared-skill, via --bundle) and its allow path against
# the valid hello skill (testdata/skills/hello-skill), configured as if each
# were the artifact behind a distinct MCP server name. The hook itself does not
# care about artifact kind, only about the artifact reference its config
# points a server name at, so this exercises the real block and allow paths
# with no network call anywhere. The real mcp-server fixture lands in M6.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TESTDATA="${REPO_ROOT}/testdata"
HOOK="${SCRIPT_DIR}/verify-mcp.sh"

PASS=0
FAIL=0
ERRORS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; ERRORS+=("$1"); FAIL=$((FAIL + 1)); }

assert_exit() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${actual}" -eq "${expected}" ]]; then
    pass "${label}: exit code ${actual} (expected ${expected})"
  else
    fail "${label}: exit code ${actual} (expected ${expected})"
  fi
}

assert_contains() {
  local label="$1" needle="$2" haystack="$3"
  if echo "${haystack}" | grep -qF -- "${needle}"; then
    pass "${label}: contains '${needle}'"
  else
    fail "${label}: does NOT contain '${needle}'"
    echo "    --- actual ---"
    echo "${haystack}" | head -20
    echo "    --------------"
  fi
}

assert_json_field() {
  local label="$1" jq_filter="$2" expected="$3" json="$4"
  local actual
  actual="$(printf '%s' "${json}" | jq -r "${jq_filter}" 2>/dev/null || true)"
  if [[ "${actual}" == "${expected}" ]]; then
    pass "${label}: ${jq_filter} = '${actual}' (expected '${expected}')"
  else
    fail "${label}: ${jq_filter} = '${actual}' (expected '${expected}')"
    echo "    --- actual json ---"
    echo "${json}"
    echo "    -------------------"
  fi
}

# ---------------------------------------------------------------------------
# Step 0: build the binary this suite drives the hook with.
# ---------------------------------------------------------------------------
echo "=== Building smithmark binary ==="
SMITHMARK_BIN="/tmp/smithmark-hook-test-$$"
go build -o "${SMITHMARK_BIN}" "${REPO_ROOT}/cmd/smithmark" 2>&1
echo "Binary built: ${SMITHMARK_BIN}"

CONFIG_FILE="$(mktemp)"
# A PATH stub containing only a symlink to the real bash, and nothing else,
# so a hook run against this PATH can still find bash to execute the script
# under, but truly cannot find jq anywhere, regardless of where the host
# itself keeps it. Mirrors the PATH stub technique
# action/entrypoint_test.sh already uses for its own operational fallback
# tests (a directory prepended to PATH shadowing real tools).
NO_JQ_DIR="$(mktemp -d)"
ln -s "$(command -v bash)" "${NO_JQ_DIR}/bash"

# shellcheck disable=SC2329 # invoked indirectly through the EXIT trap below
cleanup() { rm -f "${SMITHMARK_BIN}" "${CONFIG_FILE}"; rm -rf "${NO_JQ_DIR}"; }
trap cleanup EXIT

TRUST_ROOT="${TESTDATA}/signature/test-signing-key-pub.pem"

# ---------------------------------------------------------------------------
# Step 1: the sidecar config this suite's synthetic MCP servers resolve
# through, exactly the format README.md documents. "gone" carries no bundle
# and points at a path that does not exist, so smithmark verify hits a real,
# purely local operational failure (no local directory, no "@" so it is not
# a parseable npm name@version, and no "/" beyond a plain path so it is not
# read as an oci reference either): DISCOVERY_FAILED, offline, in well under
# a second, exercising the hook's actual exit 3 branch end to end rather
# than the pre verify short circuit the unconfigured server test below hits.
# ---------------------------------------------------------------------------
jq -n \
  --arg misArtifact "${TESTDATA}/skills/misdeclared-skill" \
  --arg misBundle "${TESTDATA}/signature/misdeclared-skill/valid.sigstore.json" \
  --arg helloArtifact "${TESTDATA}/skills/hello-skill" \
  --arg helloBundle "${TESTDATA}/signature/skill/valid.sigstore.json" \
  --arg trustRoot "${TRUST_ROOT}" \
  --arg goneArtifact "${TESTDATA}/does-not-exist-artifact-for-hook-test" \
  '{
    "misdeclared": {"artifact": $misArtifact, "bundle": $misBundle, "trustRoot": $trustRoot},
    "hello": {"artifact": $helloArtifact, "bundle": $helloBundle, "trustRoot": $trustRoot},
    "gone": {"artifact": $goneArtifact}
  }' > "${CONFIG_FILE}"

# run_hook <tool_name>: builds a minimal, realistic PreToolUse payload for
# tool_name and runs the hook with SMITHMARK_BIN and SMITHMARK_HOOK_CONFIG
# pointed at this suite's fixtures. Prints "EXIT<tab>code" then the stdout
# then a separator then stderr, so the caller can pull all three back apart.
run_hook() {
  local tool_name="$1"
  local payload
  payload="$(jq -n --arg tn "${tool_name}" --arg cwd "${REPO_ROOT}" \
    '{session_id: "test-session", cwd: $cwd, permission_mode: "default",
      hook_event_name: "PreToolUse", tool_name: $tn, tool_input: {}}')"
  local stdout_file stderr_file
  stdout_file="$(mktemp)"
  stderr_file="$(mktemp)"
  local code=0
  printf '%s' "${payload}" | env \
    SMITHMARK_BIN="${SMITHMARK_BIN}" \
    SMITHMARK_HOOK_CONFIG="${CONFIG_FILE}" \
    SMITHMARK_HOOK_ALLOW_ON_ERROR="${SMITHMARK_HOOK_ALLOW_ON_ERROR:-}" \
    bash "${HOOK}" >"${stdout_file}" 2>"${stderr_file}" || code=$?
  HOOK_EXIT="${code}"
  HOOK_STDOUT="$(cat "${stdout_file}")"
  HOOK_STDERR="$(cat "${stderr_file}")"
  rm -f "${stdout_file}" "${stderr_file}"
}

# run_hook_no_jq <tool_name> <allow_on_error>: same idea as run_hook, but
# runs the hook with PATH replaced by NO_JQ_DIR, so jq is entirely
# unreachable no matter where the host itself installs it. Used to prove the
# jq missing fallback (raw exit code 2 block, never the JSON mechanism) and
# that SMITHMARK_HOOK_ALLOW_ON_ERROR cannot leak into that branch.
run_hook_no_jq() {
  local tool_name="$1" allow_on_error="$2"
  local payload
  payload="$(jq -n --arg tn "${tool_name}" --arg cwd "${REPO_ROOT}" \
    '{session_id: "test-session", cwd: $cwd, permission_mode: "default",
      hook_event_name: "PreToolUse", tool_name: $tn, tool_input: {}}')"
  local stdout_file stderr_file
  stdout_file="$(mktemp)"
  stderr_file="$(mktemp)"
  local code=0
  printf '%s' "${payload}" | env \
    PATH="${NO_JQ_DIR}" \
    SMITHMARK_BIN="${SMITHMARK_BIN}" \
    SMITHMARK_HOOK_CONFIG="${CONFIG_FILE}" \
    SMITHMARK_HOOK_ALLOW_ON_ERROR="${allow_on_error}" \
    bash "${HOOK}" >"${stdout_file}" 2>"${stderr_file}" || code=$?
  HOOK_EXIT="${code}"
  HOOK_STDOUT="$(cat "${stdout_file}")"
  HOOK_STDERR="$(cat "${stderr_file}")"
  rm -f "${stdout_file}" "${stderr_file}"
}

# ---------------------------------------------------------------------------
# Test 1: the signed, misdeclared skill, configured as MCP server
# "misdeclared" -> block. verify --strict exits 2 over it (a passing signature
# verification carrying the UNDECLARED_NETWORK_EGRESS finding, decision D4),
# which the hook classifies as block.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: misdeclared skill as MCP server (expect deny, blocking) ==="
run_hook "mcp__misdeclared__deploy"
assert_exit "block path hook exit" 0 "${HOOK_EXIT}"
assert_json_field "block path decision" ".hookSpecificOutput.permissionDecision" "deny" "${HOOK_STDOUT}"
assert_contains "block path reason names server" "misdeclared" "${HOOK_STDOUT}"
assert_contains "block path stderr names finding code" "UNDECLARED_NETWORK_EGRESS" "${HOOK_STDERR}"
assert_contains "block path stderr says BLOCK" "smithmark hook: BLOCK" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 2: the valid hello skill, configured as MCP server "hello" -> allow.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: valid hello skill as MCP server (expect allow) ==="
run_hook "mcp__hello__greet"
assert_exit "allow path hook exit" 0 "${HOOK_EXIT}"
assert_json_field "allow path decision" ".hookSpecificOutput.permissionDecision" "allow" "${HOOK_STDOUT}"
assert_contains "allow path stderr says ALLOW" "smithmark hook: ALLOW" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 3: a non MCP tool call is not this hook's concern; it must defer
# (exit 0, no decision JSON at all) even without a scoped matcher, since the
# matcher in settings.example.json is the primary guard and this is the
# defensive fallback inside the script itself.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: non MCP tool call (expect exit 0, no decision) ==="
run_hook "Bash"
assert_exit "non mcp tool exit" 0 "${HOOK_EXIT}"
if [[ -z "${HOOK_STDOUT}" ]]; then
  pass "non mcp tool: no decision JSON printed"
else
  fail "non mcp tool: unexpectedly printed a decision: ${HOOK_STDOUT}"
fi

# ---------------------------------------------------------------------------
# Test 4: an MCP server with no configured artifact could not be checked at
# all, distinct from a check that ran and failed. Default posture fails
# closed: deny.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: unconfigured MCP server (expect deny, fail closed) ==="
run_hook "mcp__unknown__do_something"
assert_exit "unconfigured server exit" 0 "${HOOK_EXIT}"
assert_json_field "unconfigured server decision" ".hookSpecificOutput.permissionDecision" "deny" "${HOOK_STDOUT}"
assert_contains "unconfigured server stderr distinguishes could not verify" "COULD NOT VERIFY" "${HOOK_STDERR}"
assert_contains "unconfigured server stderr says failing closed" "failing closed" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 5: the same unconfigured server, but with the documented permissive
# override set, allows instead.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 5: unconfigured MCP server with SMITHMARK_HOOK_ALLOW_ON_ERROR=true (expect allow) ==="
SMITHMARK_HOOK_ALLOW_ON_ERROR="true" run_hook "mcp__unknown__do_something"
assert_exit "permissive override exit" 0 "${HOOK_EXIT}"
assert_json_field "permissive override decision" ".hookSpecificOutput.permissionDecision" "allow" "${HOOK_STDOUT}"
assert_contains "permissive override stderr mentions the override" "SMITHMARK_HOOK_ALLOW_ON_ERROR" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 6: a real smithmark verify operational failure, exit 3, offline: the
# "gone" server's artifact does not exist and carries no bundle, so verify
# itself (not this hook) fails closed with DISCOVERY_FAILED before ever
# reaching a signature check. This exercises the hook's actual catch all
# branch that parses the operational code and detail out of verify's own
# stderr JSON, unlike Test 4 above, which never runs verify at all. Default
# posture still fails closed: deny, naming the real code.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 6: real smithmark verify exit 3 (nonexistent artifact, no bundle), offline (expect deny naming DISCOVERY_FAILED) ==="
run_hook "mcp__gone__something"
assert_exit "real exit 3 hook exit" 0 "${HOOK_EXIT}"
assert_json_field "real exit 3 decision" ".hookSpecificOutput.permissionDecision" "deny" "${HOOK_STDOUT}"
assert_contains "real exit 3 stderr names DISCOVERY_FAILED" "DISCOVERY_FAILED" "${HOOK_STDERR}"
assert_contains "real exit 3 stderr distinguishes could not verify" "COULD NOT VERIFY" "${HOOK_STDERR}"
assert_contains "real exit 3 stderr says failing closed" "failing closed" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 7: the same real exit 3, with the documented permissive override set,
# allows instead.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 7: real smithmark verify exit 3 with SMITHMARK_HOOK_ALLOW_ON_ERROR=true (expect allow) ==="
SMITHMARK_HOOK_ALLOW_ON_ERROR="true" run_hook "mcp__gone__something"
assert_exit "real exit 3 override exit" 0 "${HOOK_EXIT}"
assert_json_field "real exit 3 override decision" ".hookSpecificOutput.permissionDecision" "allow" "${HOOK_STDOUT}"
assert_contains "real exit 3 override stderr mentions the override" "SMITHMARK_HOOK_ALLOW_ON_ERROR" "${HOOK_STDERR}"

# ---------------------------------------------------------------------------
# Test 8: jq missing from PATH entirely. The hook cannot safely produce a
# JSON decision without jq, so it must fall back to the raw exit code 2
# block mechanism, and SMITHMARK_HOOK_ALLOW_ON_ERROR must never reach this
# branch at all: it is a jq missing bail out, not a could not check decision,
# so the override has nothing to act on and the call still blocks.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 8: jq missing on PATH (expect raw exit 2 block; ALLOW_ON_ERROR does not leak in) ==="
run_hook_no_jq "mcp__hello__greet" "true"
assert_exit "jq missing exit" 2 "${HOOK_EXIT}"
assert_contains "jq missing stderr message" "jq is required" "${HOOK_STDERR}"
if [[ -z "${HOOK_STDOUT}" ]]; then
  pass "jq missing: no JSON decision printed (raw exit code mechanism only)"
else
  fail "jq missing: unexpectedly printed a JSON decision: ${HOOK_STDOUT}"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
echo "========================================"

if [[ "${FAIL}" -gt 0 ]]; then
  echo ""
  echo "Failed assertions:"
  for err in "${ERRORS[@]}"; do
    echo "  - ${err}"
  done
  exit 1
fi

echo "All tests passed."
exit 0
