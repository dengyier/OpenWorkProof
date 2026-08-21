#!/usr/bin/env bash
set -euo pipefail
umask 077

require_env() {
  local name="$1"
  local label="$2"
  if [[ -z "${!name:-}" ]]; then
    printf 'OpenWorkProof delivery-case Action error: missing %s\n' "$label" >&2
    exit 4
  fi
}

require_env OWP_CASE_DIRECTORY "case directory"
require_env OWP_CASE_OUTPUT "output directory"
require_env GITHUB_STEP_SUMMARY "GitHub summary file"
require_env GITHUB_OUTPUT "GitHub output file"
require_env RUNNER_TEMP "runner temp directory"

if [[ ! -d "$OWP_CASE_DIRECTORY" ]]; then
  printf 'OpenWorkProof delivery-case Action error: case directory is not a directory\n' >&2
  exit 4
fi

set +e
owp delivery-case verify "$OWP_CASE_DIRECTORY" >"$RUNNER_TEMP/owp-case-result.json"
status=$?
set -e
case "$status" in 0|2|3|4) ;; *) status=4 ;; esac

if [[ ! -e "$OWP_CASE_OUTPUT" ]]; then
  owp delivery-case export "$OWP_CASE_DIRECTORY" \
    --output-directory "$OWP_CASE_OUTPUT" || exit 4
fi

python -m openworkproof.github_action_cli write-delivery-case-summary \
  "$RUNNER_TEMP/owp-case-result.json" "$GITHUB_STEP_SUMMARY" "$GITHUB_OUTPUT" \
  || exit 4

exit "$status"
