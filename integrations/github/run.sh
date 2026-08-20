#!/usr/bin/env bash
set -euo pipefail
umask 077

require_env() {
  local name="$1"
  local label="$2"
  if [[ -z "${!name:-}" ]]; then
    printf 'OpenWorkProof GitHub Action error: missing %s\n' "$label" >&2
    exit 4
  fi
}

require_env OWP_COLLECTOR_PRIVATE_KEY_FILE "collector key file"
require_env OWP_COLLECTOR_ACTOR_ID "collector actor id"
require_env OWP_DELIVERY_PACKAGE "delivery package"
require_env OWP_TOOLCHAIN_LOCK_FILE "toolchain lock file"
require_env OWP_SANDBOX_POLICY_FILE "sandbox policy file"
require_env OWP_SURFACE_OUTPUT "surface output"
require_env GITHUB_STEP_SUMMARY "GitHub summary file"
require_env GITHUB_OUTPUT "GitHub output file"
require_env RUNNER_TEMP "runner temp directory"
if [[ ! -f "$OWP_COLLECTOR_PRIVATE_KEY_FILE" ]]; then
  printf 'OpenWorkProof GitHub Action error: collector key is not a file\n' >&2
  exit 4
fi

if [[ -z "${OWP_EXPECTED_SOURCE_REVISION:-}" ]]; then
  require_env GITHUB_WORKSPACE "GitHub workspace"
  OWP_EXPECTED_SOURCE_REVISION="$(
    git -C "$GITHUB_WORKSPACE" rev-parse HEAD
  )" || exit 4
  export OWP_EXPECTED_SOURCE_REVISION
fi

python -m openworkproof.github_action_cli build \
  --delivery-package "$OWP_DELIVERY_PACKAGE" \
  --collector-key-file "$OWP_COLLECTOR_PRIVATE_KEY_FILE" \
  --toolchain-lock-file "$OWP_TOOLCHAIN_LOCK_FILE" \
  --sandbox-policy-file "$OWP_SANDBOX_POLICY_FILE" \
  --output "$OWP_SURFACE_OUTPUT" \
  || exit 4

set +e
owp surface-verify "$OWP_SURFACE_OUTPUT" >"$RUNNER_TEMP/owp-result.json"
status=$?
set -e
case "$status" in 0|2|3|4) ;; *) status=4 ;; esac

python -m openworkproof.github_action_cli write-summary \
  "$RUNNER_TEMP/owp-result.json" "$GITHUB_STEP_SUMMARY" "$GITHUB_OUTPUT" \
  || exit 4

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
  --numeric-owner -czf openworkproof-evidence-bundle.tar.gz \
  -C "$(dirname "$OWP_SURFACE_OUTPUT")" "$(basename "$OWP_SURFACE_OUTPUT")" \
  || exit 4
exit "$status"
