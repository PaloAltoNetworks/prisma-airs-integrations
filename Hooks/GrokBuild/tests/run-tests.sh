#!/usr/bin/env bash
# Validation harness for GrokBuild — runs the SAME fixtures through node + bash + powershell,
# ASSERTS each runtime's decision, requires them to AGREE (parity), and exits non-zero on any
# failure. All three runtimes must be present or the suite refuses to report PASS (set
# ALLOW_MISSING_RUNTIMES=1 to override on a dev box, with a loud warning — NOT a full validation).
#   ./run-tests.sh            offline: creds unset -> UNCONFIGURED passes through by default (loud warn);
#                             AIRS_REQUIRE_CONFIG=1 fails every gate CLOSED; unknown vendor blocks.
#   ./run-tests.sh stub       stub AIRS tenant: benign ALLOWS; injection is stopped at every checkpoint
#                             (prompt, built-in + MCP pre-tool, Bash / ReadFile / MCP post-tool, Stop);
#                             MCP output is REPLACED; the session-end Stop never blocks; malformed input
#                             and content cut by Grok's payload cap or past the scan budget fail closed
#                             -> proves detection wiring on Grok's real payload shapes.
#   PRISMA_AIRS_API_KEY=... PRISMA_AIRS_PROFILE_NAME=... ./run-tests.sh live
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
V="grok"; UPS_EV="UserPromptSubmit"; PRE_EV="PreToolUse"; CFG=".grok"
MODE="${1:-offline}"; FAILED=0; STUB_PID=""
# The grok default log path is ABSOLUTE ($HOME/.grok/hooks/prisma-airs.log); keep test runs out of it.
[ -n "${SECURITY_LOG_PATH:-}" ] || export SECURITY_LOG_PATH="${TMPDIR:-/tmp}/prisma-airs-grok-tests.log"

verdict() { # <stdout> <rc> -> ALLOW | BLOCK | ADVISE
  local out="$1" rc="$2"
  [ "$rc" = "2" ] && { echo BLOCK; return; }   # exit 2 = hard block (codex/devin/gemini, claude pre-tool)
  case "$out" in
    # HARD blocks that actually stop the action (grok: decision deny on PreToolUse, continue:false+stopReason on Stop):
    *'permissionDecision":"deny"'*|*'"permission":"deny"'*|*'"cancel":true'*|*'"decision":"block"'*|*'"decision":"deny"'*|*'"stopReason"'*) echo BLOCK ;;
    # ADVISORY only (does NOT stop the action): injected context, Cursor record-only continue:false, post-tool redact.
    *additionalContext*|*contextModification*|*'"continue":false'*|*updated_mcp_tool_output*|*updatedMCPToolOutput*) echo ADVISE ;;
    *) echo ALLOW ;;
  esac
}
run_one() { # runtime fixture event [vendorOverride] -> stdout; sets RC
  local rt="$1" fx="$2" ev="$3" vv="${4:-$V}" out
  case "$rt" in
    nodejs)     out="$(cat "$fx" | node "$HERE/../nodejs/$CFG/hooks/hooks.mjs" --vendor "$vv" --event "$ev" 2>/dev/null)"; RC=$? ;;
    bash)       out="$(cat "$fx" | bash "$HERE/../bash/$CFG/hooks/airs-hooks.sh" --vendor "$vv" --event "$ev" 2>/dev/null)"; RC=$? ;;
    powershell) out="$(cat "$fx" | pwsh -NoProfile -File "$HERE/../powershell/$CFG/hooks/airs-hooks.ps1" -Vendor "$vv" -EventName "$ev" 2>/dev/null)"; RC=$? ;;
  esac
  printf '%s' "$out"
}
scan_one() { # runtime fixture event [vendorOverride] -> verdict class
  local out; RC=0
  out="$(run_one "$@"; echo "~$RC")"
  verdict "${out%~*}" "${out##*~}"
}
RUNTIMES=(); MISSING=()
command -v node >/dev/null && RUNTIMES+=(nodejs)     || MISSING+=(node)
command -v bash >/dev/null && RUNTIMES+=(bash)       || MISSING+=(bash)
command -v pwsh >/dev/null && RUNTIMES+=(powershell) || MISSING+=(pwsh)
assert_all() { # label fixture event want(ALLOW|NOT_ALLOW|BLOCK|ADVISE) [vendorOverride] — every runtime must satisfy it
  local label="$1" fx="$2" ev="$3" want="$4" vv="${5:-$V}" got seen="" ok=1
  for rt in "${RUNTIMES[@]}"; do
    got="$(scan_one "$rt" "$fx" "$ev" "$vv")"; seen="$seen $rt=$got"
    case "$want" in
      NOT_ALLOW) [ "$got" = "ALLOW" ] && ok=0 ;;              # must not plainly proceed (BLOCK or ADVISE ok)
      NOT_BLOCK) [ "$got" = "BLOCK" ] && ok=0 ;;              # must proceed (ALLOW or in-band ADVISE ok)
      *)         [ "$got" != "$want" ] && ok=0 ;;
    esac
  done
  if [ "$ok" = 1 ]; then printf '  ok   %s ->%s\n' "$label" "$seen"; else printf '  FAIL %s: want %s, got%s\n' "$label" "$want" "$seen"; FAILED=1; fi
}
assert_stdout() { # label fixture event has|lacks <literal> — every runtime's stdout must (not) contain it
  local label="$1" fx="$2" ev="$3" mode="$4" needle="$5" out seen="" ok=1
  for rt in "${RUNTIMES[@]}"; do
    out="$(run_one "$rt" "$fx" "$ev")"
    case "$out" in *"$needle"*) [ "$mode" = lacks ] && ok=0; seen="$seen $rt=has" ;;
                   *)           [ "$mode" = has ]   && ok=0; seen="$seen $rt=lacks" ;; esac
  done
  if [ "$ok" = 1 ]; then printf '  ok   %s ->%s\n' "$label" "$seen"; else printf '  FAIL %s: stdout must %s %s, got%s\n' "$label" "$mode" "$needle" "$seen"; FAILED=1; fi
}

# ----------------------------------------------------------------------------
# Config gate — Grok FAILS OPEN on every hook failure (timeout, crash, missing
# file), so a wiring mistake is a silent bypass the engine tests below cannot
# see. Assert the shipped prisma-airs.json in every cell before anything runs.
# ----------------------------------------------------------------------------
if command -v node >/dev/null; then
  for cell in nodejs bash powershell; do
    msg="$(node -e '
      const fs = require("fs"), path = require("path");
      const [dir, cell] = process.argv.slice(1), bad = [];
      const jsons = fs.readdirSync(dir).filter((f) => f.endsWith(".json"));
      if (jsons.join() !== "prisma-airs.json") bad.push("hooks dir must hold exactly one .json (Grok loads them all): " + jsons.join(" "));
      let cfg = {}; try { cfg = JSON.parse(fs.readFileSync(path.join(dir, "prisma-airs.json"), "utf8")); } catch (e) { bad.push("prisma-airs.json does not parse: " + e.message); }
      const engine = { nodejs: "hooks.mjs", bash: "airs-hooks.sh", powershell: "airs-hooks.ps1" }[cell];
      const home = cell === "powershell" ? "${USERPROFILE}" : "${HOME}";
      // quoted: an unquoted path with a space in the home dir splits, the hook cannot start, and Grok allows
      const enginePath = "\"" + home + "/.grok/hooks/" + engine + "\"";
      const want = { UserPromptSubmit: 30, PreToolUse: 30, PostToolUse: 60, Stop: 60 };
      if (Object.keys(cfg).join() !== "hooks") bad.push("only the top-level key \"hooks\" is allowed");
      const hooks = cfg.hooks || {};
      if (Object.keys(hooks).sort().join() !== Object.keys(want).sort().join()) bad.push("events must be exactly " + Object.keys(want).join(","));
      for (const [ev, t] of Object.entries(want)) for (const g of hooks[ev] || []) {
        if ("matcher" in g) bad.push(ev + ": no matcher allowed");
        for (const h of g.hooks || []) {
          const c = String(h.command || ""), env = h.env || {};
          const flags = cell === "powershell" ? "-Vendor grok -EventName " + ev : "--vendor grok --event " + ev;
          if (h.type !== "command") bad.push(ev + ": type must be command");
          if (!c.includes(" " + enginePath + " ") || !c.endsWith(flags)) bad.push(ev + ": command must run " + enginePath + " ... " + flags);
          if (h.timeout !== t) bad.push(ev + ": timeout must be " + t);
          if (env.AIRS_REQUIRE_CONFIG !== "1") bad.push(ev + ": env AIRS_REQUIRE_CONFIG must be \"1\"");
          if (env.AIRS_FAIL_MODE !== "closed") bad.push(ev + ": env AIRS_FAIL_MODE must be \"closed\" (a stray AIRS_FAIL_MODE=open in the shell would otherwise allow every scan error)");
          if (!(Number(env.AIRS_DEADLINE_MS) > 0 && Number(env.AIRS_DEADLINE_MS) < t * 1000)) bad.push(ev + ": env AIRS_DEADLINE_MS must be below the hook timeout");
          if (Object.keys(env).some((k) => /^PRISMA_AIRS_/.test(k))) bad.push(ev + ": credentials never go in env");
        }
      }
      if (!fs.existsSync(path.join(dir, engine))) bad.push("engine " + engine + " missing next to prisma-airs.json");
      console.log(bad.join("; "));
    ' "$HERE/../$cell/$CFG/hooks" "$cell")"
    if [ -n "$msg" ]; then echo "  FAIL config gate $cell: $msg"; FAILED=1; else echo "  ok   config gate $cell: prisma-airs.json wiring"; fi
  done
fi

echo "== GrokBuild [$MODE] runtimes: ${RUNTIMES[*]:-none} | $(jq --version 2>/dev/null || echo 'jq missing') =="
# The bash engine's behaviour depends on the jq it finds: jq 1.7.x (Ubuntu 24.04's default) refuses to parse
# past 256 levels (only 128 nested objects), jq 1.8.x allows ~10000. Run stub mode under BOTH (put the other
# jq first on PATH) — posttool-mcp-deep.json is past 1.7's limit, so it takes the unparseable path there.
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
    # DEFAULT for a genuinely UNCONFIGURED install (no key): pass traffic through with a loud warning,
    # so copying the folder in before .env exists does NOT brick the agent. The input gate ALLOWS here
    # (even the injection fixture — the control is unarmed, and says so on stderr every call).
    unset AIRS_REQUIRE_CONFIG
    assert_all "offline unconfigured pass-through (prompt)"   "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" NOT_BLOCK
    assert_all "offline unconfigured pass-through (pre-tool)" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" NOT_BLOCK
    # STRICT opt-out: AIRS_REQUIRE_CONFIG=1 restores hard fail-closed on the input side (block render path).
    # The shipped Grok configs pin it on every handler; for grok it renders each event's block form.
    export AIRS_REQUIRE_CONFIG=1
    assert_all "offline strict prompt   fail-closed (injection)" "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" NOT_ALLOW
    assert_all "offline strict pre-tool fail-closed (injection)" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" NOT_ALLOW
    assert_all "offline strict MCP pre-tool fail-closed"         "$HERE/fixtures/pretool-mcp-injection.json" "$PRE_EV" NOT_ALLOW
    assert_all "offline strict MCP post-tool fail-closed"        "$HERE/fixtures/posttool-mcp-injection.json" "PostToolUse" NOT_ALLOW
    assert_all "offline strict Stop (end_turn) fail-closed"      "$HERE/fixtures/stop-injection.json" "Stop" NOT_ALLOW
    unset AIRS_REQUIRE_CONFIG
    # UNKNOWN vendor must never silently alias to Claude (that would fail OPEN on a stdout-reading
    # client). Run each runtime with a bogus vendor; it must fail closed, not ALLOW. (Vendor comes from
    # the install wiring, not scannable content — this guards operator-misconfig, not an attacker path.)
    assert_all "offline unknown vendor -> fail-closed" "$HERE/fixtures/prompt-benign.json" "$UPS_EV" NOT_ALLOW "bogusvendor" ;;
  stub)
    command -v python3 >/dev/null || { echo "python3 required for stub mode"; exit 2; }
    PORT=8770; python3 "$HERE/stub-airs.py" "$PORT" & STUB_PID=$!
    trap '[ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null' EXIT
    sleep 1
    export PRISMA_AIRS_URL="http://127.0.0.1:$PORT" PRISMA_AIRS_API_KEY="stub" PRISMA_AIRS_PROFILE_NAME="stub"
    assert_all "stub prompt   benign    -> ALLOW"        "$HERE/fixtures/prompt-benign.json"     "$UPS_EV" ALLOW
    assert_all "stub prompt   injection -> stopped"      "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" BLOCK
    assert_all "stub pre-tool benign (run_terminal_command) -> ALLOW" "$HERE/fixtures/pretool-benign.json" "$PRE_EV" ALLOW
    assert_all "stub pre-tool injection (run_terminal_command) -> BLOCK" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" BLOCK
    assert_all "stub pre-tool MCP injection (wrapped tool_input) -> BLOCK" "$HERE/fixtures/pretool-mcp-injection.json" "$PRE_EV" BLOCK
    assert_stdout "stub pre-tool deny carries permissionDecision" "$HERE/fixtures/pretool-injection.json" "$PRE_EV" has '"permissionDecision":"deny"'
    assert_all "stub malformed  input   -> fail-closed"  "$HERE/fixtures/malformed.json"         "$PRE_EV" NOT_ALLOW
    # Grok drops an allowing hook's stderr, so an unscannable OUTPUT renders as that event's block too.
    assert_all "stub malformed  post-tool -> fail-closed"  "$HERE/fixtures/malformed.json"       "PostToolUse" NOT_ALLOW
    assert_all "stub malformed  Stop    -> turn halted"    "$HERE/fixtures/malformed.json"       "Stop" NOT_ALLOW
    # Grok cuts an oversized payload to a plain string (toolInputTruncated / toolResultTruncated): the tool
    # runs with, and the model reads, the WHOLE thing, so a clean head never allows the unscanned tail.
    assert_all "stub pre-tool truncated input (clean head) -> BLOCK" "$HERE/fixtures/pretool-truncated.json" "$PRE_EV" BLOCK
    assert_all "stub post-tool truncated MCP result (clean head) -> not allowed" "$HERE/fixtures/posttool-truncated.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool truncated MCP result is REPLACED" "$HERE/fixtures/posttool-truncated.json" "PostToolUse" has 'updatedMCPToolOutput'
    # The truncation FLAG decides, whatever the payload's shape: an object-form (MCP-wrapped) input flagged
    # as cut, and a cut payload whose visible head is empty, are never read as clean / nothing-to-scan.
    assert_all "stub pre-tool truncated MCP input in OBJECT form (clean head) -> BLOCK" "$HERE/fixtures/pretool-mcp-truncated-object.json" "$PRE_EV" BLOCK
    assert_all "stub pre-tool truncated input with an EMPTY head -> BLOCK" "$HERE/fixtures/pretool-truncated-empty-head.json" "$PRE_EV" BLOCK
    assert_all "stub post-tool truncated MCP result with an EMPTY head -> not allowed" "$HERE/fixtures/posttool-truncated-empty-head.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool truncated MCP result with an EMPTY head is REPLACED" "$HERE/fixtures/posttool-truncated-empty-head.json" "PostToolUse" has 'updatedMCPToolOutput'
    assert_all "stub pre-tool truncated input, flag only in snake_case -> BLOCK" "$HERE/fixtures/pretool-truncated-snake-flag.json" "$PRE_EV" BLOCK
    # A result cut to a string keeps its MCP identity through the call: a call Grok also cut to a string,
    # or one with no args, is still MCP, so the output is withheld rather than merely flagged.
    assert_stdout "stub post-tool cut MCP result + cut call is REPLACED" "$HERE/fixtures/posttool-mcp-cut-result-cut-call.json" "PostToolUse" has 'updatedMCPToolOutput'
    assert_stdout "stub post-tool cut MCP result + no-args call is REPLACED" "$HERE/fixtures/posttool-mcp-cut-result-null-args.json" "PostToolUse" has 'updatedMCPToolOutput'
    # An MCP output the engine cannot PARSE (here: cut mid-document or garbled; in the field: nested past
    # jq 1.7's parse limit of 128 objects, or ConvertFrom-Json's depth limit) must still be WITHHELD, not
    # merely flagged next to the raw content — whichever envelope marker survives. Every engine's
    # unparseable-input path, on any jq; garbled = jq cannot even stream it (bash's raw-text fallback).
    for fx in posttool-mcp-unparseable-result posttool-mcp-unparseable-call posttool-mcp-garbled; do
      assert_all "stub post-tool UNPARSEABLE MCP ($fx) -> not allowed" "$HERE/fixtures/$fx.json" "PostToolUse" NOT_ALLOW
      assert_stdout "stub post-tool UNPARSEABLE MCP ($fx) is REPLACED" "$HERE/fixtures/$fx.json" "PostToolUse" has 'updatedMCPToolOutput'
    done
    # ...but an unparseable BUILT-IN output is only flagged: no MCP replacement for a non-MCP tool.
    assert_all "stub post-tool UNPARSEABLE built-in output -> not allowed" "$HERE/fixtures/posttool-builtin-unparseable.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool UNPARSEABLE built-in output is NOT given an MCP replacement" "$HERE/fixtures/posttool-builtin-unparseable.json" "PostToolUse" lacks 'updatedMCPToolOutput'
    OVER="${TMPDIR:-/tmp}/grok-posttool-mcp-overflow-$$.json"
    node -e 'const fs=require("fs"),o=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));for(const k of ["toolResult","tool_response"])o[k].output.OkayOutput="x".repeat(125000);fs.writeFileSync(process.argv[2],JSON.stringify(o))' "$HERE/fixtures/posttool-mcp-injection.json" "$OVER"
    assert_all "stub post-tool MCP output past the scan budget -> not allowed" "$OVER" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool MCP output past the scan budget is REPLACED" "$OVER" "PostToolUse" has 'updatedMCPToolOutput'
    rm -f "$OVER"
    assert_all "stub post-tool Bash output_for_prompt injection -> not allowed" "$HERE/fixtures/posttool-bash-injection.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool Bash: reason only, no output replacement" "$HERE/fixtures/posttool-bash-injection.json" "PostToolUse" lacks 'updatedMCPToolOutput'
    assert_all "stub post-tool ReadFile raw_output injection -> not allowed" "$HERE/fixtures/posttool-readfile-injection.json" "PostToolUse" NOT_ALLOW
    # Field precision: the scan reads what the MODEL reads (raw_output / output_for_prompt), not a sibling.
    assert_all "stub post-tool ReadFile injection ONLY in raw_output -> not allowed" "$HERE/fixtures/posttool-readfile-rawonly.json" "PostToolUse" NOT_ALLOW
    assert_all "stub post-tool ReadFile injection ONLY in numbered content -> ALLOW" "$HERE/fixtures/posttool-readfile-content-ignored.json" "PostToolUse" ALLOW
    assert_all "stub post-tool Bash empty output_for_prompt -> bytes decoded + scanned" "$HERE/fixtures/posttool-bash-bytes.json" "PostToolUse" NOT_ALLOW
    assert_all "stub post-tool Bash injection ONLY in the byte array -> ALLOW" "$HERE/fixtures/posttool-bash-bytes-ignored.json" "PostToolUse" ALLOW
    assert_all "stub post-tool unknown result type nested past 64 -> not allowed" "$HERE/fixtures/posttool-unknown-deep.json" "PostToolUse" NOT_ALLOW
    assert_all "stub post-tool MCP OkayOutput injection -> not allowed" "$HERE/fixtures/posttool-mcp-injection.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool MCP output is REPLACED for the model" "$HERE/fixtures/posttool-mcp-injection.json" "PostToolUse" has 'updatedMCPToolOutput'
    assert_all "stub post-tool MCP structured output nested past 100 -> not allowed" "$HERE/fixtures/posttool-mcp-deep.json" "PostToolUse" NOT_ALLOW
    assert_stdout "stub post-tool MCP structured output nested past 100 is REPLACED" "$HERE/fixtures/posttool-mcp-deep.json" "PostToolUse" has 'updatedMCPToolOutput'
    assert_all "stub Stop end_turn injection -> turn halted" "$HERE/fixtures/stop-injection.json" "Stop" NOT_ALLOW
    assert_stdout "stub Stop halt is continue:false (never decision:block, which loops)" "$HERE/fixtures/stop-injection.json" "Stop" lacks '"decision":"block"'
    assert_all "stub Stop shutdown (session-end fire) -> never blocks" "$HERE/fixtures/stop-shutdown.json" "Stop" ALLOW
    assert_all "stub Stop channel_closed (session-end fire) -> never blocks" "$HERE/fixtures/stop-channel-closed.json" "Stop" ALLOW
    assert_all "stub Stop empty reason -> scanned, turn halted" "$HERE/fixtures/stop-empty-reason.json" "Stop" NOT_ALLOW
    ;;
  live)
    : "${PRISMA_AIRS_API_KEY:?set PRISMA_AIRS_API_KEY for live}"; : "${PRISMA_AIRS_PROFILE_NAME:?set PRISMA_AIRS_PROFILE_NAME for live}"
    assert_all "live pre-tool injection -> BLOCK"        "$HERE/fixtures/pretool-injection.json" "$PRE_EV" BLOCK
    assert_all "live prompt   injection -> not allowed"  "$HERE/fixtures/prompt-injection.json"  "$UPS_EV" NOT_ALLOW
    assert_all "live Stop shutdown -> never blocks"      "$HERE/fixtures/stop-shutdown.json"     "Stop" ALLOW ;;
  *) echo "usage: run-tests.sh [offline|stub|live]"; exit 2 ;;
esac
[ "$FAILED" = 0 ] && echo "== PASS ==" || echo "== FAIL =="
exit $FAILED
