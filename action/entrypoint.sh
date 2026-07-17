#!/usr/bin/env bash
# entrypoint.sh: the composite action entrypoint for smithmark verify.
# Called by action.yml with SMITHMARK_* environment variables set from the
# action's inputs.
#
# Exit codes mirror smithmark verify exactly and are never remapped:
#   0 = verification passed (or there was nothing to verify)
#   1 = verification failed a failing class check
#   2 = strict lint gate: a passing verification carried an UNDECLARED_ finding
#   3 = operational failure (bad configuration, an unusable binary, a network
#       error, or a missing required input)
set -euo pipefail

SMITHMARK_MODULE="github.com/sns45/smithmark/cmd/smithmark"
SMITHMARK_BIN=""

# ---------------------------------------------------------------------------
# 0. Validate the required input before spending any effort on the binary.
# ---------------------------------------------------------------------------
if [[ -z "${SMITHMARK_REF:-}" ]]; then
  echo "::error::smithmark-action: the 'ref' input is required" >&2
  exit 3
fi

# ---------------------------------------------------------------------------
# Helper: install smithmark with go install at the given version or ref. Sets
# SMITHMARK_BIN and returns 0 on success; returns 1 on any failure, letting the
# caller decide whether a further fallback exists rather than exiting here.
# ---------------------------------------------------------------------------
resolve_via_go_install() {
  local ref="$1"
  if ! command -v go >/dev/null 2>&1; then
    echo "::error::smithmark-action: go is required to install smithmark from a version or ref, but it is not on PATH" >&2
    return 1
  fi
  echo "smithmark-action: go install ${SMITHMARK_MODULE}@${ref}"
  local go_bin_dir
  go_bin_dir="$(mktemp -d)"
  if ! GOBIN="${go_bin_dir}" go install "${SMITHMARK_MODULE}@${ref}"; then
    rm -rf "${go_bin_dir}"
    echo "::error::smithmark-action: go install ${SMITHMARK_MODULE}@${ref} failed" >&2
    return 1
  fi
  trap 'rm -rf "${go_bin_dir}"' EXIT
  SMITHMARK_BIN="${go_bin_dir}/smithmark"
  return 0
}

# ---------------------------------------------------------------------------
# Helper: download the goreleaser release archive for the runner OS and arch
# at the given version (or resolve latest first). Sets SMITHMARK_BIN and
# returns 0 on success; returns 1 on any failure so the caller can fall back to
# resolve_via_go_install rather than failing outright.
# ---------------------------------------------------------------------------
download_release() {
  local version="$1"
  local raw_os="${RUNNER_OS:-Linux}"
  local raw_arch="${RUNNER_ARCH:-X64}"
  local goos goarch ext bin_name

  case "${raw_os}" in
    Linux|linux)     goos="linux"   ;;
    macOS|Darwin)    goos="darwin"  ;;
    Windows|windows) goos="windows" ;;
    *)               goos="${raw_os}" ;;
  esac
  case "${raw_arch}" in
    X64|x86_64|amd64)    goarch="amd64" ;;
    ARM64|arm64|aarch64) goarch="arm64" ;;
    *)                   goarch="${raw_arch}" ;;
  esac
  if [[ "${goos}" == "windows" ]]; then
    ext="zip"
    bin_name="smithmark.exe"
  else
    ext="tar.gz"
    bin_name="smithmark"
  fi

  if [[ "${version}" == "latest" ]]; then
    echo "smithmark-action: resolving the latest release tag"
    local api_response
    if ! api_response="$(curl -fsSL --connect-timeout 10 --max-time 30 "https://api.github.com/repos/sns45/smithmark/releases/latest")"; then
      echo "smithmark-action: could not reach the GitHub API to resolve the latest release" >&2
      return 1
    fi
    version="$(printf '%s' "${api_response}" | grep '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
    if [[ -z "${version}" ]]; then
      echo "smithmark-action: no smithmark release exists yet, so latest resolved to nothing" >&2
      return 1
    fi
    echo "smithmark-action: resolved version = ${version}"
  fi

  # smithmark's archive name template embeds the version with its leading v
  # stripped (goreleaser's .Version strips it; only the release tag in the
  # download URL keeps it), per .goreleaser.yaml archives.name_template.
  local version_num="${version#v}"
  local archive_name="smithmark_${version_num}_${goos}_${goarch}.${ext}"
  local download_url="https://github.com/sns45/smithmark/releases/download/${version}/${archive_name}"

  local tmp_dir
  tmp_dir="$(mktemp -d)"

  echo "smithmark-action: downloading ${download_url}"
  if ! curl -fsSL --connect-timeout 10 --max-time 120 "${download_url}" -o "${tmp_dir}/${archive_name}"; then
    echo "smithmark-action: failed to download ${download_url}" >&2
    rm -rf "${tmp_dir}"
    return 1
  fi

  if [[ "${ext}" == "zip" ]]; then
    unzip -q "${tmp_dir}/${archive_name}" -d "${tmp_dir}"
  else
    tar -xzf "${tmp_dir}/${archive_name}" -C "${tmp_dir}"
  fi

  trap 'rm -rf "${tmp_dir}"' EXIT
  SMITHMARK_BIN="${tmp_dir}/${bin_name}"
  chmod +x "${SMITHMARK_BIN}"
  echo "smithmark-action: installed ${version} at ${SMITHMARK_BIN}"
  return 0
}

# ---------------------------------------------------------------------------
# 1. Resolve the smithmark binary: install-from wins, else download the
#    release for the runner OS and arch, else go install as a documented
#    fallback (today's practical path, since no release has shipped yet).
# ---------------------------------------------------------------------------
if [[ -n "${SMITHMARK_INSTALL_FROM:-}" ]]; then
  if [[ -f "${SMITHMARK_INSTALL_FROM}" && -x "${SMITHMARK_INSTALL_FROM}" ]]; then
    SMITHMARK_BIN="${SMITHMARK_INSTALL_FROM}"
    echo "smithmark-action: using prebuilt binary at ${SMITHMARK_BIN}"
  else
    echo "smithmark-action: install-from '${SMITHMARK_INSTALL_FROM}' is not an executable file; treating it as a version to install with go install"
    if ! resolve_via_go_install "${SMITHMARK_INSTALL_FROM}"; then
      exit 3
    fi
  fi
else
  SMITHMARK_VERSION="${SMITHMARK_VERSION:-latest}"
  if ! download_release "${SMITHMARK_VERSION}"; then
    echo "smithmark-action: release download failed; falling back to go install (documented fallback)" >&2
    if ! resolve_via_go_install "${SMITHMARK_VERSION}"; then
      exit 3
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 2. Build the verify argument list from the inputs, one flag per mapped
#    input, matching cmd/smithmark/verify.go's flag surface exactly.
# ---------------------------------------------------------------------------
VERIFY_ARGS=("verify" "${SMITHMARK_REF}")

if [[ -n "${SMITHMARK_BUNDLE:-}" ]]; then
  VERIFY_ARGS+=("--bundle" "${SMITHMARK_BUNDLE}")
fi
if [[ "${SMITHMARK_STRICT:-false}" == "true" ]]; then
  VERIFY_ARGS+=("--strict")
fi
if [[ -n "${SMITHMARK_ATTESTATION_BASE:-}" ]]; then
  VERIFY_ARGS+=("--attestation-base" "${SMITHMARK_ATTESTATION_BASE}")
fi
if [[ -n "${SMITHMARK_TRUST_ROOT:-}" ]]; then
  VERIFY_ARGS+=("--trust-root" "${SMITHMARK_TRUST_ROOT}")
fi
if [[ -n "${SMITHMARK_CERTIFICATE_IDENTITY:-}" ]]; then
  VERIFY_ARGS+=("--certificate-identity" "${SMITHMARK_CERTIFICATE_IDENTITY}")
fi
if [[ -n "${SMITHMARK_CERTIFICATE_OIDC_ISSUER:-}" ]]; then
  VERIFY_ARGS+=("--certificate-oidc-issuer" "${SMITHMARK_CERTIFICATE_OIDC_ISSUER}")
fi
if [[ -n "${SMITHMARK_OUTPUT:-}" ]]; then
  VERIFY_ARGS+=("--output" "${SMITHMARK_OUTPUT}")
fi

echo "smithmark-action: running ${SMITHMARK_BIN} ${VERIFY_ARGS[*]}"

# ---------------------------------------------------------------------------
# 3. Run verify. Its own stdout and stderr stream straight to the step log;
#    the process exits with verify's exact code, never masked as success.
# ---------------------------------------------------------------------------
CODE=0
"${SMITHMARK_BIN}" "${VERIFY_ARGS[@]}" || CODE=$?

case "${CODE}" in
  1) echo "::error::smithmark verify FAILED (exit 1): a failing class check did not pass" >&2 ;;
  2) echo "::error::smithmark verify FLAGGED (exit 2): strict caught an UNDECLARED_ lint finding on an otherwise passing verification" >&2 ;;
  0) ;;
  *) echo "::error::smithmark verify exited ${CODE}: operational failure" >&2 ;;
esac

exit "${CODE}"
