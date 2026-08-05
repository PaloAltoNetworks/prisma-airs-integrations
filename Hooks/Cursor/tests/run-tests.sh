#!/usr/bin/env bash
# Validation harness for Cursor — runs the shared fixtures through all three
# runtimes and prints the wire format each emits (stdout AND Cursor's fd 3).
#
#   ./run-tests.sh          OFFLINE (default): credentials are unset, so input-side
#                           hooks fail CLOSED — you see each runtime's BLOCK render
#                           with no live tenant needed.
#   PRISMA_AIRS_API_KEY=... PRISMA_AIRS_PROFILE_NAME=... ./run-tests.sh live
#                           LIVE: benign fixture should allow, injection should block.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V="cursor"; EV="beforeSubmitPrompt"
if [ "${1:-}" != "live" ]; then unset PRISMA_AIRS_API_KEY PRISMA_AIRS_PROFILE_NAME PRISMA_AIRS_PROFILE_ID; MODE="offline (fail-closed)"; else MODE="live"; fi
run() {
  local flavor="$1"; shift
  for fx in "$HERE/fixtures/"*.json; do
    local fd; fd="$(mktemp)"
    out="$(cat "$fx" | "$@" 3>"$fd" 2>/dev/null)"; rc=$?
    f3="$(cat "$fd")"; rm -f "$fd"
    printf '  %-11s %-22s rc=%-2s %s%s\n' "$flavor" "$(basename "$fx")" "$rc" "${out:+stdout=${out:0:58} }" "${f3:+fd3=${f3:0:58}}"
  done
}
echo "== Cursor: fixtures x 3 runtimes [$MODE] =="
command -v node >/dev/null && run nodejs     node      "$HERE/../nodejs/.cursor/hooks/hooks.mjs"     --vendor "$V" --event "$EV"
command -v bash >/dev/null && run bash       bash      "$HERE/../bash/.cursor/hooks/airs-hooks.sh"   --vendor "$V" --event "$EV"
command -v pwsh >/dev/null && run powershell pwsh -File "$HERE/../powershell/.cursor/hooks/airs-hooks.ps1" -Vendor "$V" -EventName "$EV"
