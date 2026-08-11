#!/usr/bin/env bash
# Validation harness for ClaudeCode — ASSERTS each runtime's decision and exits non-zero on
# failure. Three modes:
#   ./run-tests.sh            offline: creds unset -> input-side fails CLOSED; asserts the
#                             input hook does NOT silently allow, for every runtime (parity).
#   ./run-tests.sh stub       stub AIRS: a local fake tenant blocks on the injection
#                             sentinel; asserts benign ALLOWS and injection is stopped -> this
#                             is what actually proves detection wiring (needs python3).
#   PRISMA_AIRS_API_KEY=... PRISMA_AIRS_PROFILE_NAME=... ./run-tests.sh live
#                             live: injection is stopped against a real tenant.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V="claude"; EV="UserPromptSubmit"; CFG=".claude"
MODE="${1:-offline}"; FAILED=0; STUB_PID=""

verdict() { # <stdout> <rc> -> ALLOW | BLOCK | ADVISE
  local out="$1" rc="$2"
  [ "$rc" = "2" ] && { echo BLOCK; return; }
  case "$out" in
    *'"decision":"block"'*|*'permissionDecision":"deny"'*|*'"permission":"deny"'*|*'"cancel":true'*|*'"continue":false'*) echo BLOCK ;;
    *additionalContext*|*contextModification*) echo ADVISE ;;
    *) echo ALLOW ;;
  esac
}
scan_one() { # runtime fixture -> verdict class
  local rt="$1" fx="$2" out rc
  case "$rt" in
    nodejs)     out="$(cat "$fx" | node "$HERE/../nodejs/$CFG/hooks/hooks.mjs" --vendor "$V" --event "$EV" 2>/dev/null)"; rc=$? ;;
    bash)       out="$(cat "$fx" | bash "$HERE/../bash/$CFG/hooks/airs-hooks.sh" --vendor "$V" --event "$EV" 2>/dev/null)"; rc=$? ;;
    powershell) out="$(cat "$fx" | pwsh -NoProfile -File "$HERE/../powershell/$CFG/hooks/airs-hooks.ps1" -Vendor "$V" -EventName "$EV" 2>/dev/null)"; rc=$? ;;
  esac
  verdict "$out" "$rc"
}
RUNTIMES=()
command -v node >/dev/null && RUNTIMES+=(nodejs)
command -v bash >/dev/null && RUNTIMES+=(bash)
command -v pwsh >/dev/null && RUNTIMES+=(powershell)
assert_all() { # label fixture want(ALLOW|NOT_ALLOW) — every runtime must satisfy it (parity)
  local label="$1" fx="$2" want="$3" got seen="" ok=1
  for rt in "${RUNTIMES[@]}"; do
    got="$(scan_one "$rt" "$fx")"; seen="$seen $rt=$got"
    if [ "$want" = "NOT_ALLOW" ]; then [ "$got" = "ALLOW" ] && ok=0; else [ "$got" != "$want" ] && ok=0; fi
  done
  if [ "$ok" = 1 ]; then printf '  ok   %s ->%s\n' "$label" "$seen"; else printf '  FAIL %s: want %s, got%s\n' "$label" "$want" "$seen"; FAILED=1; fi
}

echo "== ClaudeCode [$MODE] runtimes: ${RUNTIMES[*]:-none} =="
[ ${#RUNTIMES[@]} -eq 0 ] && { echo "no runtimes available"; exit 2; }
case "$MODE" in
  offline)
    unset PRISMA_AIRS_API_KEY PRISMA_AIRS_PROFILE_NAME PRISMA_AIRS_PROFILE_ID
    assert_all "offline input fail-closed (benign)"    "$HERE/fixtures/prompt-benign.json"    NOT_ALLOW
    assert_all "offline input fail-closed (injection)" "$HERE/fixtures/prompt-injection.json" NOT_ALLOW ;;
  stub)
    command -v python3 >/dev/null || { echo "python3 required for stub mode"; exit 2; }
    PORT=8770; python3 "$HERE/stub-airs.py" "$PORT" & STUB_PID=$!
    trap '[ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null' EXIT
    sleep 1
    export PRISMA_AIRS_URL="http://127.0.0.1:$PORT" PRISMA_AIRS_API_KEY="stub" PRISMA_AIRS_PROFILE_NAME="stub"
    assert_all "stub benign -> ALLOW"           "$HERE/fixtures/prompt-benign.json"    ALLOW
    assert_all "stub injection -> not allowed"  "$HERE/fixtures/prompt-injection.json" NOT_ALLOW ;;
  live)
    : "${PRISMA_AIRS_API_KEY:?set PRISMA_AIRS_API_KEY for live}"; : "${PRISMA_AIRS_PROFILE_NAME:?set PRISMA_AIRS_PROFILE_NAME for live}"
    assert_all "live injection -> not allowed" "$HERE/fixtures/prompt-injection.json" NOT_ALLOW
    printf '  info benign -> %s (profile-dependent; not asserted)\n' "$(scan_one "${RUNTIMES[0]}" "$HERE/fixtures/prompt-benign.json")" ;;
  *) echo "usage: run-tests.sh [offline|stub|live]"; exit 2 ;;
esac
[ "$FAILED" = 0 ] && echo "== PASS ==" || echo "== FAIL =="
exit $FAILED
