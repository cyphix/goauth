#!/usr/bin/env bash
# Scan git commits for secrets. Usage:
#   scripts/betterleaks-scan.sh                 # @{upstream}..HEAD, or --pre-commit fallback
#   scripts/betterleaks-scan.sh abc123..def456  # explicit range
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"

BETTERLEAKS_IMAGE="${BETTERLEAKS_IMAGE:-ghcr.io/betterleaks/betterleaks@sha256:7a43a20d40be02a9c13801a6485f7bea9d9cdba512263440eae972103c5291f1}"
CONFIG="${BETTERLEAKS_CONFIG:-.betterleaks.toml}"

resolve_range() {
  if [ -n "${1:-}" ]; then
    echo "${1}"
    return
  fi
  if git rev-parse '@{upstream}' >/dev/null 2>&1; then
    echo "$(git rev-parse '@{upstream}')..$(git rev-parse HEAD)"
    return
  fi
  echo ""
}

run_local() {
  local -a args=("$@")
  if command -v betterleaks >/dev/null 2>&1; then
    betterleaks "${args[@]}"
    return
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo "error: install betterleaks (brew install betterleaks) or Docker to scan for secrets" >&2
    exit 1
  fi

  local git_common main_root
  git_common="$(git rev-parse --git-common-dir)"
  if [[ "${git_common}" != /* ]]; then
    git_common="${ROOT}/${git_common}"
  fi
  main_root="$(dirname "${git_common}")"

  docker run --rm \
    --user "$(id -u):$(id -g)" \
    -e GIT_CONFIG_COUNT=1 \
    -e GIT_CONFIG_KEY_0=safe.directory \
    -e GIT_CONFIG_VALUE_0="${ROOT}" \
    -v "${main_root}:${main_root}" \
    -v "${ROOT}:${ROOT}" \
    -w "${ROOT}" \
    "${BETTERLEAKS_IMAGE}" \
    "${args[@]}"
}

RANGE="$(resolve_range "${1:-}")"
COMMON_ARGS=(
  git .
  --config "${CONFIG}"
  --redact
  --no-banner
)

if [ -n "${RANGE}" ]; then
  echo "Scanning commits ${RANGE}"
  run_local "${COMMON_ARGS[@]}" --log-opts "${RANGE}"
else
  echo "No upstream configured; scanning working tree diff (--pre-commit)"
  run_local "${COMMON_ARGS[@]}" --pre-commit
fi
