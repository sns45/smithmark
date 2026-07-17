#!/usr/bin/env bash
# entrypoint_test.sh: offline test suite for action/entrypoint.sh.
#
# Usage: bash action/entrypoint_test.sh
# Exits 0 if all assertions pass; exits nonzero on any failure.
#
# Every case below sets SMITHMARK_INSTALL_FROM to a freshly built local
# binary, so this suite never downloads a release and never touches the
# network: it exercises exactly the offline escape hatch install-from exists
# for, against the committed signed fixtures under testdata/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TESTDATA="${REPO_ROOT}/testdata"

PASS=0
FAIL=0
ERRORS=()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; ERRORS+=("$1"); FAIL=$((FAIL + 1)); }

assert_exit() {
  local label="$1"
  local expected="$2"
  local actual="$3"
  if [[ "${actual}" -eq "${expected}" ]]; then
    pass "${label}: exit code ${actual} (expected ${expected})"
  else
    fail "${label}: exit code ${actual} (expected ${expected})"
  fi
}

assert_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if echo "${haystack}" | grep -qF -- "${needle}"; then
    pass "${label}: output contains '${needle}'"
  else
    fail "${label}: output does NOT contain '${needle}'"
    echo "    --- actual output ---"
    echo "${haystack}" | head -20
    echo "    --------------------"
  fi
}

assert_not_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  if echo "${haystack}" | grep -qF -- "${needle}"; then
    fail "${label}: output unexpectedly contains '${needle}'"
  else
    pass "${label}: output does NOT contain '${needle}'"
  fi
}

# ---------------------------------------------------------------------------
# Step 0: build the binary this whole suite exercises through install-from.
# ---------------------------------------------------------------------------
echo "=== Building smithmark binary ==="
SMITHMARK_BIN="/tmp/smithmark-action-test-$$"
go build -o "${SMITHMARK_BIN}" "${REPO_ROOT}/cmd/smithmark" 2>&1
echo "Binary built: ${SMITHMARK_BIN}"

trap 'rm -f "${SMITHMARK_BIN}"' EXIT

# Fixture paths (committed, real signed bundles from Task 3.1/3.4).
SKILL_REF="${TESTDATA}/skills/hello-skill"
MISDECLARED_REF="${TESTDATA}/skills/misdeclared-skill"
VALID_BUNDLE="${TESTDATA}/signature/skill/valid.sigstore.json"
TAMPERED_BUNDLE="${TESTDATA}/signature/skill/tampered.sigstore.json"
MISDECLARED_BUNDLE="${TESTDATA}/signature/misdeclared-skill/valid.sigstore.json"
TRUST_ROOT="${TESTDATA}/signature/test-signing-key-pub.pem"

# ---------------------------------------------------------------------------
# Test 1: valid skill, valid bundle -> exit 0, VERIFIED
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 1: valid skill bundle (expect exit 0, VERIFIED) ==="
OUTPUT_1=""
EXIT_1=0
OUTPUT_1="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="${SKILL_REF}" \
  SMITHMARK_BUNDLE="${VALID_BUNDLE}" \
  SMITHMARK_TRUST_ROOT="${TRUST_ROOT}" \
  SMITHMARK_OUTPUT="summary" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_1=$?

assert_exit "valid bundle" 0 "${EXIT_1}"
assert_contains "valid bundle verdict" "VERIFIED" "${OUTPUT_1}"
assert_contains "install-from log line" "using prebuilt binary at ${SMITHMARK_BIN}" "${OUTPUT_1}"
assert_not_contains "no download attempted" "smithmark-action: downloading" "${OUTPUT_1}"

# ---------------------------------------------------------------------------
# Test 2: valid skill, tampered bundle -> exit 1, FAILED, annotated
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 2: tampered bundle (expect exit 1, FAILED) ==="
OUTPUT_2=""
EXIT_2=0
OUTPUT_2="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="${SKILL_REF}" \
  SMITHMARK_BUNDLE="${TAMPERED_BUNDLE}" \
  SMITHMARK_TRUST_ROOT="${TRUST_ROOT}" \
  SMITHMARK_OUTPUT="summary" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_2=$?

assert_exit "tampered bundle" 1 "${EXIT_2}"
assert_contains "tampered bundle verdict" "FAILED" "${OUTPUT_2}"
assert_contains "tampered bundle annotation" "::error::smithmark verify FAILED" "${OUTPUT_2}"

# ---------------------------------------------------------------------------
# Test 3: misdeclared skill with --strict -> exit 2, FLAGGED
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 3: strict lint gate on a misdeclared skill (expect exit 2, FLAGGED) ==="
OUTPUT_3=""
EXIT_3=0
OUTPUT_3="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="${MISDECLARED_REF}" \
  SMITHMARK_BUNDLE="${MISDECLARED_BUNDLE}" \
  SMITHMARK_TRUST_ROOT="${TRUST_ROOT}" \
  SMITHMARK_STRICT="true" \
  SMITHMARK_OUTPUT="summary" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_3=$?

assert_exit "strict flagged" 2 "${EXIT_3}"
assert_contains "strict flagged verdict" "FLAGGED" "${OUTPUT_3}"
assert_contains "strict flagged annotation" "::error::smithmark verify FLAGGED" "${OUTPUT_3}"

# The same misdeclared skill without --strict must exit 0: the gate must never
# fire unless the caller asked for it.
echo ""
echo "=== Test 3b: same misdeclared skill without --strict (expect exit 0) ==="
OUTPUT_3B=""
EXIT_3B=0
OUTPUT_3B="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="${MISDECLARED_REF}" \
  SMITHMARK_BUNDLE="${MISDECLARED_BUNDLE}" \
  SMITHMARK_TRUST_ROOT="${TRUST_ROOT}" \
  SMITHMARK_OUTPUT="summary" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_3B=$?

assert_exit "no strict, not flagged" 0 "${EXIT_3B}"
assert_not_contains "no strict verdict not flagged" "FLAGGED" "${OUTPUT_3B}"

# ---------------------------------------------------------------------------
# Test 4: missing ref input -> exit 3, operational, never masked as success
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 4: missing ref (expect exit 3, operational) ==="
OUTPUT_4=""
EXIT_4=0
OUTPUT_4="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_4=$?

assert_exit "missing ref" 3 "${EXIT_4}"
assert_contains "missing ref annotation" "::error::smithmark-action: the 'ref' input is required" "${OUTPUT_4}"

# ---------------------------------------------------------------------------
# Test 5: certificate-identity is accepted but fails closed (M6 caveat),
# proving exit 3 is never masked and the operational annotation still fires.
# ---------------------------------------------------------------------------
echo ""
echo "=== Test 5: certificate-identity fails closed (expect exit 3) ==="
OUTPUT_5=""
EXIT_5=0
OUTPUT_5="$(env \
  SMITHMARK_INSTALL_FROM="${SMITHMARK_BIN}" \
  SMITHMARK_REF="${SKILL_REF}" \
  SMITHMARK_CERTIFICATE_IDENTITY="someone@example.com" \
  SMITHMARK_OUTPUT="summary" \
  bash "${SCRIPT_DIR}/entrypoint.sh" 2>&1)" || EXIT_5=$?

assert_exit "certificate-identity fails closed" 3 "${EXIT_5}"
assert_contains "certificate-identity operational annotation" "::error::smithmark verify exited 3" "${OUTPUT_5}"

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
