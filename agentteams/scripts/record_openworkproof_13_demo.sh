#!/bin/sh
set -eu

fail() {
  printf '%s\n' "OpenWorkProof recording error: $1" >&2
  exit 4
}

[ "$#" -ge 3 ] || fail "usage: OUTPUT -- COMMAND [ARGS...]"
output=$1
shift
case "$output" in
  -*) fail "recording output must not begin with a dash" ;;
esac
[ "$1" = "--" ] || fail "command separator -- is required"
shift
[ "$#" -gt 0 ] || fail "demo command is required"

[ -n "${OWP_SCREEN_RECORD_INPUT:-}" ] || fail "OWP_SCREEN_RECORD_INPUT is required"
[ "${OWP_ELEMENT_TARGET_ROOM_ONLY:-}" = "1" ] || fail "target-room-only attestation is required"
[ "${OWP_DESKTOP_NOTIFICATIONS_OFF:-}" = "1" ] || fail "notification-off attestation is required"
[ "${OWP_NO_VISIBLE_SECRETS:-}" = "1" ] || fail "no-visible-secrets attestation is required"
command -v ffmpeg >/dev/null 2>&1 || fail "ffmpeg is unavailable"
command -v ffprobe >/dev/null 2>&1 || fail "ffprobe is unavailable"
[ ! -e "$output" ] || fail "recording output already exists"
mkdir -p "$(dirname "$output")"

fifo="${TMPDIR:-/tmp}/owp-record-$$.fifo"
mkfifo -m 600 "$fifo" || fail "cannot create recorder control fifo"
exec 3<>"$fifo"
recorder_pid=
cleanup() {
  if [ -n "$recorder_pid" ] && kill -0 "$recorder_pid" 2>/dev/null; then
    printf 'q\n' >&3 2>/dev/null || true
    wait "$recorder_pid" 2>/dev/null || true
  fi
  exec 3>&-
  rm -f "$fifo"
}
trap cleanup EXIT HUP INT TERM

ffmpeg -hide_banner -loglevel warning \
  -f avfoundation -i "$OWP_SCREEN_RECORD_INPUT" \
  -c:v libx264 -pix_fmt yuv420p "$output" <&3 &
recorder_pid=$!
sleep 2
kill -0 "$recorder_pid" 2>/dev/null || fail "screen recorder failed to start"

status=0
"$@" || status=$?
printf 'q\n' >&3
wait "$recorder_pid" || fail "screen recorder failed"
recorder_pid=

ffprobe -v error -show_entries stream=codec_type \
  -of default=noprint_wrappers=1:nokey=1 "$output" \
  | grep -qx video || fail "recording is not decodable video"
[ "$status" -eq 0 ] || exit "$status"
