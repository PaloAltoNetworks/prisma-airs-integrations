#!/usr/bin/env bash
# Validation harness for Codex — runs the SAME fixtures through node + bash + powershell,
# ASSERTS each runtime's decision, requires them to AGREE (parity), and exits non-zero on any
# failure. All three runtimes must be present or the suite refuses to report PASS (set
# ALLOW_MISSING_RUNTIMES=1 to override on a dev box, with a loud warning — NOT a full validation).
#   ./run-tests.sh            offline: creds unset -> the prompt AND pre-tool input gates fail CLOSED.
#   ./run-tests.sh stub       stub AIRS tenant: benign ALLOWS, injection is BLOCKED at the pre-tool
#                             hard gate (payload nested deep, so it also guards the collector depth
#                             fix), and malformed input fails closed -> proves detection wiring.
#   PRISMA_AIRS_API_KEY=... PRISMA_AIRS_PROFILE_NAME=... ./run-tests.sh live
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V="codex"; UPS_EV="UserPromptSubmit"; PRE_EV="PreToolUse"; CFG=".codex"
MODE="${1:-offline}"; FAILED=0; STUB_PID=""

verdict() { # <stdout> <rc> -> ALLOW | BLOCK | ADVISE
  local out="$1" rc="$2"
  [ "$rc" = "2" ] && { echo BLOCK; return; }   # exit 2 = hard block (codex/devin/gemini, claude pre-tool)
  case "$out" in
    # HARD blocks that actually stop the action:
    *'permissionDecision":"deny"'*|*'"permission":"deny"'*|*'"cancel":true'*|*'"decision":"block"'*|*'"stopReason"'*) echo BLOCK ;;
    # ADVISORY only (does NOT stop the action): injected context, Cursor record-only continue:false, post-tool redact.
    *additionalContext*|*contextModification*|*'"continue":false'*|*updated_mcp_tool_output*) echo ADVISE ;;
    *) echo ALLOW ;;
  esac
}
scan_one() { # runtime fixture event -> verdict class
  local rt="$1" fx="$2" ev="$3" out rc
  case "$rt" in
    nodejs)     out="$(cat "$fx" | node "$HERE/../nodejs/$CFG/hooks/hooks.mjs" --vendor "$V" --event "$ev" 2>/dev/null)"; rc=$? ;;
    bash)       out="$(cat "$fx" | bash "$HERE/../bash/$CFG/hooks/airs-hooks.sh" --vendor "$V" --event "$ev" 2>/dev/null)"; rc=$? ;;
    powershell) out="$(cat "$fx" | pwsh -NoProfile -File "$HERE/../powershell/$CFG/hooks/airs-hooks.ps1" -Vendor "$V" -EventName "$ev" 2>/dev/null)"; rc=$? ;;
  esac
  verdict "$out" "$rc"
}
RUNTIMES=(); MISSING=()
command -v node >/dev/null && RUNTIMES+=(nodejs)     || MISSING+=(node)
command -v bash >/dev/null && RUNTIMES+=(bash)       || MISSING+=(bash)
command -v pwsh >/dev/null && RUNTIMES+=(powershell) || MISSING+=(pwsh)
assert_all() { # label fixture event want(ALLOW|NOT_ALLOW|BLOCK|ADVISE) — every runtime must satisfy it
  local label="$1" fx="$2" ev="$3" want="$4" got seen="" ok=1
  for rt in "${RUNTIMES[@]}"; do
    got="$(scan_one "$rt" "$fx" "$ev")"; seen="$seen $rt=$got"
    case "$want" in
      NOT_ALLOW) [ "$got" = "ALLOW" ] && ok=0 ;;
      *)         [ "$got" != "$want" ] && ok=0 ;;
    esac
  done
  if [ "$ok" = 1 ]; then printf '  ok   %s ->%s\n' "$label" "$seen"; else printf '  FAIL %s: want %s, got%s\n' "$label" "$want" "$seen"; FAILED=1; fi
}

echo "== Codex [$MODE] runtimes: ${RUNTIMES[*]:-none} =="
if [ ${#MISSING[@]} -gt 0 ]; then
  echo "   MISSING RUNTIME(S): ${MISSING[*]}"
  if [ "${ALLOW_MISSING_RUNTIMES:-0}" != "1" ]; then
    echo "   Refusing to report PASS without all three runtimes (parity is the point). Install them,"
    echo "   or set ALLOW_MISSING_RUNTIMES=1 to run only what's present (NOT a full validation)."
    exit 2
  fi
  echo "   WARNING: ALLOW_MISSING_RUNTIMES=1 — parity NOT enforced for [${MISSING[*]}]."
fi
[ ${#RUNTIMES[@]} -eq 0 ] && { echo "no runtimes available"; exit 2; }

case "$MODE" in
  offline)
    unset PRISMA_AIRS_API_KEY PRISMA_AIRS_PROFILE_NAME PRISMA_AIRS_PROFILE_ID
    assert_all "offline prompt   fail-closed (injection)" "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" NOT_ALLOW
    assert_all "offline pre-tool fail-closed (injection)" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" NOT_ALLOW ;;
  stub)
    command -v python3 >/dev/null || { echo "python3 required for stub mode"; exit 2; }
    PORT=8770; python3 "$HERE/stub-airs.py" "$PORT" & STUB_PID=$!
    trap '[ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null' EXIT
    sleep 1
    export PRISMA_AIRS_URL="http://127.0.0.1:$PORT" PRISMA_AIRS_API_KEY="stub" PRISMA_AIRS_PROFILE_NAME="stub"
    assert_all "stub prompt   benign    -> ALLOW"        "$HERE/fixtures/prompt-benign.json"     "$UPS_EV" ALLOW
    assert_all "stub prompt   injection -> stopped"      "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" BLOCK
    assert_all "stub pre-tool benign    -> ALLOW"        "$HERE/fixtures/pretool-benign.json"    "$PRE_EV" ALLOW
    assert_all "stub pre-tool injection -> BLOCK (hard gate; payload nested deep reaches AIRS)" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" BLOCK
    assert_all "stub malformed  input   -> fail-closed"  "$HERE/fixtures/malformed.json"         "$PRE_EV" NOT_ALLOW
    assert_all "stub non-string  prompt injection -> stopped"        "$HERE/fixtures/prompt-structured.json"  "$UPS_EV" BLOCK
    assert_all "stub primitive tool_input injection -> not allowed"  "$HERE/fixtures/pretool-primitive.json"  "$PRE_EV" NOT_ALLOW
    assert_all "stub built-in tool deep field injection -> not allowed" "$HERE/fixtures/pretool-builtin-deep.json" "$PRE_EV" NOT_ALLOW
    assert_all "stub very-deep injection (past jq encoder limit) -> BLOCK"  "$HERE/fixtures/pretool-verydeep.json" "$PRE_EV" BLOCK
    assert_all "stub post-tool deep injection -> not allowed (output collector depth)" "$HERE/fixtures/posttool-injection.json" "PostToolUse" NOT_ALLOW
    ;;
  live)
    : "${PRISMA_AIRS_API_KEY:?set PRISMA_AIRS_API_KEY for live}"; : "${PRISMA_AIRS_PROFILE_NAME:?set PRISMA_AIRS_PROFILE_NAME for live}"
    assert_all "live pre-tool injection -> BLOCK"        "$HERE/fixtures/pretool-injection.json" "$PRE_EV" BLOCK
    assert_all "live prompt   injection -> not allowed"  "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" NOT_ALLOW ;;
  *) echo "usage: run-tests.sh [offline|stub|live]"; exit 2 ;;
esac
[ "$FAILED" = 0 ] && echo "== PASS ==" || echo "== FAIL =="
exit $FAILED
