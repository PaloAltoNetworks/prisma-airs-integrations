#!/usr/bin/env bash
# Validation harness for GeminiCLI — runs the shared fixtures through all three
# runtimes and prints the wire format each emits on stdout.
#
#   ./run-tests.sh          OFFLINE (default): credentials are unset, so input-side
#                           hooks fail CLOSED — you see each runtime's BLOCK render
#                           with no live tenant needed.
#   PRISMA_AIRS_API_KEY=... PRISMA_AIRS_PROFILE_NAME=... ./run-tests.sh live
#                           LIVE: benign fixture should allow, injection should block.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V="gemini"; EV="BeforeAgent"
if [ "${1:-}" != "live" ]; then unset PRISMA_AIRS_API_KEY PRISMA_AIRS_PROFILE_NAME PRISMA_AIRS_PROFILE_ID; MODE="offline (fail-closed)"; else MODE="live"; fi
run() {
  local flavor="$1"; shift
  for fx in "$HERE/fixtures/"*.json; do
    out="$(cat "$fx" | "$@" 2>/dev/null)"; rc=$?
    printf '  %-11s %-22s rc=%-2s %s\n' "$flavor" "$(basename "$fx")" "$rc" "${out:+stdout=${out:0:70} }"
  done
}
echo "== GeminiCLI: fixtures x 3 runtimes [$MODE] =="
command -v node >/dev/null && run nodejs     node      "$HERE/../nodejs/.gemini/hooks/hooks.mjs"     --vendor "$V" --event "$EV"
command -v bash >/dev/null && run bash       bash      "$HERE/../bash/.gemini/hooks/airs-hooks.sh"   --vendor "$V" --event "$EV"
command -v pwsh >/dev/null && run powershell pwsh -File "$HERE/../powershell/.gemini/hooks/airs-hooks.ps1" -Vendor "$V" -EventName "$EV"
