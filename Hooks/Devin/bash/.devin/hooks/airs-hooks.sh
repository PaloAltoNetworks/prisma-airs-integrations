#!/usr/bin/env bash
# =============================================================================
# Prisma AIRS security hook — BASH core engine (core-parity port of hooks-x).
#
# One script, all six vendors (via --vendor), all four checkpoints (via --event).
# Delegates every judgment to Prisma AIRS. Core parity with the Node.js engine:
#   • 4 checkpoints: UserPromptSubmit / PreToolUse / PostToolUse / Stop
#   • correct AIRS content-types, incl. tool_event (method "tools/call") so
#     tool I/O is scanned for INDIRECT prompt injection, not as a plain response
#   • per-tool input field mapping + full recursive string capture on tool output
#   • fail-closed on the input side, fail-open on the output side (Stop never loops)
#   • portable hashing (no macOS-only `md5`), no silent truncation
# NOT ported (Node.js only): DLP mask-in-place, multi-chunk scanning.
#
# Dependencies: bash, jq, curl.  (The nodejs flavor needs none of these.)
# =============================================================================
set -o pipefail

# ----------------------------------------------------------------------------
# args
# ----------------------------------------------------------------------------
VENDOR="claude"; EVENT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vendor)   VENDOR="${2:-}"; shift 2 ;;
    --event)    EVENT="${2:-}";  shift 2 ;;
    --vendor=*) VENDOR="${1#*=}"; shift ;;
    --event=*)  EVENT="${1#*=}";  shift ;;
    *) shift ;;
  esac
done
VENDOR="$(printf '%s' "$VENDOR" | tr '[:upper:]' '[:lower:]')"

# ----------------------------------------------------------------------------
# config (all from environment — identical behaviour per-machine)
# ----------------------------------------------------------------------------
BASE_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}"
BASE_URL="${BASE_URL%/}"
API_URL="$BASE_URL/v1/scan/sync/request"
API_KEY="${PRISMA_AIRS_API_KEY:-}"
PROFILE_ID="${PRISMA_AIRS_PROFILE_ID:-}"
PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/prisma-airs.log}"
TIMEOUT_MS="${AIRS_TIMEOUT_MS:-10000}"
RETRIES="${AIRS_RETRIES:-1}"
FAIL_MODE="${AIRS_FAIL_MODE:-open}"
SUFFIX="${AIRS_APP_SUFFIX:-${CLAUDE_CODE_APP_SUFFIX:-}}"
DEBUG="${AIRS_DEBUG:-0}"
case "${AIRS_CODE_AWARE:-1}" in 1|true|yes) CODE_AWARE=1 ;; *) CODE_AWARE=0 ;; esac
case "$TIMEOUT_MS" in ''|*[!0-9]*) TIMEOUT_MS=10000 ;; esac
TIMEOUT_S=$(( (TIMEOUT_MS + 999) / 1000 )); [ "$TIMEOUT_S" -lt 1 ] && TIMEOUT_S=1
case "$RETRIES" in ''|*[!0-9]*) RETRIES=1 ;; esac

# vendor -> app_name for AIRS metadata
case "$VENDOR" in
  claude)      APP_NAME="Claude Code" ;;
  codex)       APP_NAME="Codex CLI" ;;
  cursor)      APP_NAME="Cursor" ;;
  cline)       APP_NAME="Cline" ;;
  devin)       APP_NAME="Devin CLI" ;;
  antigravity) APP_NAME="Antigravity" ;;
  gemini)      APP_NAME="Gemini CLI" ;;
  *)           APP_NAME="Claude Code" ;;
esac
[ -n "$SUFFIX" ] && APP_NAME="$APP_NAME-$SUFFIX"

dbg() { [ "$DEBUG" = "1" ] || [ "$DEBUG" = "true" ] && printf '[airs-hooks] %s\n' "$1" >&2; return 0; }

# ----------------------------------------------------------------------------
# read stdin once
# ----------------------------------------------------------------------------
INPUT="$(cat)"
j()  { jq -r  "$1" <<<"$INPUT" 2>/dev/null; }   # raw string
jc() { jq -c  "$1" <<<"$INPUT" 2>/dev/null; }   # compact JSON

# ----------------------------------------------------------------------------
# event mapping: vendor event -> internal event (UPS/Pre/Post/Stop)
# ----------------------------------------------------------------------------
RAW_EVENT="$EVENT"
[ -z "$RAW_EVENT" ] && RAW_EVENT="$(j '.hook_event_name // empty')"

case "$VENDOR" in
  cursor)
    case "$RAW_EVENT" in
      beforeSubmitPrompt)   IEVENT="UserPromptSubmit" ;;
      beforeShellExecution) IEVENT="PreToolUse" ;;
      beforeMCPExecution)   IEVENT="PreToolUse" ;;
      postToolUse)          IEVENT="PostToolUse" ;;
      afterAgentResponse)   IEVENT="Stop" ;;
      *) IEVENT="" ;;
    esac ;;
  cline)
    case "$RAW_EVENT" in
      UserPromptSubmit) IEVENT="UserPromptSubmit" ;;
      PreToolUse)       IEVENT="PreToolUse" ;;
      PostToolUse)      IEVENT="PostToolUse" ;;
      TaskComplete)     IEVENT="Stop" ;;
      *) IEVENT="" ;;
    esac ;;
  antigravity|gemini)
    case "$RAW_EVENT" in
      BeforeAgent|UserPromptSubmit|PreInvocation) IEVENT="UserPromptSubmit" ;;
      BeforeTool|PreToolUse)                      IEVENT="PreToolUse" ;;
      AfterTool|PostToolUse)                      IEVENT="PostToolUse" ;;
      AfterAgent|Stop|SubagentStop|PostInvocation) IEVENT="Stop" ;;
      *) IEVENT="" ;;
    esac ;;
  *) # claude / codex — native names
    case "$RAW_EVENT" in
      UserPromptSubmit) IEVENT="UserPromptSubmit" ;;
      PreToolUse)       IEVENT="PreToolUse" ;;
      PostToolUse)      IEVENT="PostToolUse" ;;
      Stop|SubagentStop) IEVENT="Stop" ;;
      *) IEVENT="" ;;
    esac ;;
esac

# side of the loop
case "$IEVENT" in
  UserPromptSubmit|PreToolUse) SIDE="input" ;;
  PostToolUse|Stop)            SIDE="output" ;;
  *) SIDE="output" ;;
esac

# ----------------------------------------------------------------------------
# render — turn a neutral decision into this vendor's wire format, then EXIT.
#   render <allow|warn|block> <text>
# ----------------------------------------------------------------------------
render() {
  local kind="$1" text="$2" out="" err="" code=0
  case "$kind" in
    warn)  err="[Prisma AIRS] $text"$'\n' ;;
    block) err=$'\n🚫 '"$text"$'\n\n' ;;
  esac

  case "$VENDOR" in
    claude)
      if [ "$kind" = "block" ]; then
        case "$IEVENT" in
          PreToolUse)       out="$(jq -nc --arg r "$text" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}')" ;;
          UserPromptSubmit) out="$(jq -nc --arg r "$text" '{decision:"block",reason:$r,hookSpecificOutput:{hookEventName:"UserPromptSubmit"}}')" ;;
          PostToolUse)      out="$(jq -nc --arg r "$text" '{decision:"block",reason:$r,hookSpecificOutput:{hookEventName:"PostToolUse"}}')" ;;
          Stop)             out="$(jq -nc --arg r "$text" '{decision:"block",reason:$r}')" ;;
        esac
      fi ;;
    codex)
      if [ "$kind" = "block" ]; then
        case "$IEVENT" in
          UserPromptSubmit|PreToolUse) code=2 ;;
          PostToolUse) out="$(jq -nc --arg r "$text" '{decision:"block",reason:$r,hookSpecificOutput:{hookEventName:"PostToolUse"}}')" ;;
          Stop)        out="$(jq -nc --arg r "$text" '{continue:false,stopReason:$r}')" ;;
        esac
      else
        [ "$IEVENT" = "Stop" ] && out='{"continue": true}'
      fi ;;
    cursor)
      # Cursor reads decisions from STDOUT. Pre-tool (beforeShell/beforeMCP) HARD-blocks
      # via {"permission":"deny"}. postToolUse can't hard-block — for MCP tools it REDACTS
      # the model-visible output (updated_mcp_tool_output) + warns (additional_context);
      # for non-MCP it can only warn. beforeSubmitPrompt {"continue":false} is advisory
      # (record-only); afterAgentResponse can't block.
      if [ "$kind" = "block" ]; then
        case "$IEVENT" in
          UserPromptSubmit) out="$(jq -nc --arg r "$text" '{continue:false,user_message:$r}')" ;;
          PreToolUse)       out="$(jq -nc --arg r "$text" '{permission:"deny",user_message:$r,agent_message:$r}')" ;;
          # updated_mcp_tool_output redacts the model-visible output (Cursor applies it
          # for MCP tools, ignores it for non-MCP); additional_context warns for any tool.
          PostToolUse)      out="$(jq -nc --arg r "$text" '{updated_mcp_tool_output:("[Prisma AIRS blocked this tool output: "+$r+"]"),additional_context:("⚠️ Prisma AIRS flagged this tool output: "+$r)}')" ;;
          Stop)             err=$'\n⚠️  ALERT (Cursor cannot block the model answer) — '"$text"$'\n\n' ;;
        esac
      else
        case "$IEVENT" in
          UserPromptSubmit) out='{"continue":true}' ;;
          PreToolUse)       out='{"permission":"allow"}' ;;
          PostToolUse)      out='{}' ;;
        esac
      fi ;;
    cline)
      if [ "$kind" = "block" ]; then
        if [ "$IEVENT" = "Stop" ]; then
          out="$(jq -nc --arg r "$text" '{cancel:false,contextModification:$r}')"   # TaskComplete is non-cancellable
        else
          out="$(jq -nc --arg r "$text" '{cancel:true,errorMessage:$r}')"
        fi
      elif [ "$kind" = "warn" ]; then
        out="$(jq -nc --arg m "$text" '{cancel:false,contextModification:("Prisma AIRS: "+$m)}')"
      else
        out='{"cancel": false}'
      fi ;;
    devin)
      # Devin CLI: PreToolUse is the ONLY hard block (exit 2). UserPromptSubmit can
      # only inject additionalContext (advisory). PostToolUse/Stop are advisory too.
      if [ "$kind" = "block" ]; then
        case "$IEVENT" in
          PreToolUse) code=2 ;;   # reason already on stderr ($err)
          UserPromptSubmit)
            out="$(jq -nc --arg r "$text" '{hookSpecificOutput:{hookEventName:"UserPromptSubmit",additionalContext:("⚠️ Prisma AIRS flagged this prompt: "+$r)}}')"
            err=$'\n⚠️  ALERT (Devin UserPromptSubmit cannot block; enforcement is at the tool gate) — '"$text"$'\n\n' ;;
          PostToolUse|Stop) code=0; err=$'\n⚠️  ALERT (Devin '"$IEVENT"' is advisory) — '"$text"$'\n\n' ;;
        esac
      fi ;;
    antigravity|gemini)
      # Gemini CLI blocks via exit code 2 (stderr = reason) on BeforeAgent/BeforeTool/
      # AfterTool. AfterAgent(Stop) is advisory — exit 2 there triggers a model RETRY
      # (loop risk), so we scan + alert instead of hard-blocking the answer.
      if [ "$kind" = "block" ]; then
        case "$IEVENT" in
          UserPromptSubmit|PreToolUse|PostToolUse) code=2 ;;
          Stop) code=0; err=$'\n⚠️  ALERT (Gemini response scanned; not hard-blocked to avoid retry loop) — '"$text"$'\n\n' ;;
        esac
      fi ;;
  esac

  [ -n "$out" ] && printf '%s' "$out"
  [ -n "$err" ] && printf '%s' "$err" >&2
  exit "$code"
}

# ----------------------------------------------------------------------------
# logging
# ----------------------------------------------------------------------------
log_line() {
  local label="$1" tag="$2" ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null)"
  mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null
  printf '[%s] %s %s: %s\n' "$ts" "$IEVENT" "$label" "$tag" >>"$LOG_FILE" 2>/dev/null
  return 0
}

# ----------------------------------------------------------------------------
# unknown / unhandled event -> allow silently
# ----------------------------------------------------------------------------
[ -z "$IEVENT" ] && { dbg "unhandled event '$RAW_EVENT' for vendor '$VENDOR'"; render allow ""; }

# ----------------------------------------------------------------------------
# jq helpers shared across content extraction
# ----------------------------------------------------------------------------
# stringify a value like the Node `s()` helper: string as-is, null -> "", else JSON
JQ_S='def s: if type=="string" then . elif .==null then "" else tojson end;'
# join non-empty stringified fields with newline
JQ_JOIN='def joinf: map(if .==null then empty elif type=="string" then . else tojson end) | map(select(.!="")) | join("\n");'
flatten() { printf '%s' "$1" | tr '\r\n' '  '; }

# resolve tool_event identity (server_name, tool_invoked) — sets SERVER, TOOL
tool_identity() {
  local name="$1" ti="$2"
  if [[ "$name" == mcp__* ]]; then
    SERVER="$(printf '%s' "$name" | awk -F'__' '{print $2}')"
    TOOL="$(printf '%s' "$name" | awk -F'__' '{ if (NF>=3){ s=$3; for(i=4;i<=NF;i++) s=s"__"$i; print s } else print $2 }')"
    [ -z "$SERVER" ] && SERVER="unknown"
    [ -z "$TOOL" ] && TOOL="$name"
  elif [ "$name" = "ReadMcpResourceTool" ] || [ "$name" = "ReadMcpResourceDirTool" ] || [ "$name" = "ListMcpResourcesTool" ]; then
    SERVER="$(jq -r '.server // "unknown"' <<<"$ti" 2>/dev/null)"; [ -z "$SERVER" ] && SERVER="unknown"
    TOOL="$(jq -r '.uri // .path // empty' <<<"$ti" 2>/dev/null)"; [ -z "$TOOL" ] && TOOL="$name"
  else
    SERVER="claude-code/${name:-unknown}"
    TOOL="${name:-unknown}"
  fi
}

# what to scan on the INPUT side, per built-in tool (mirrors content.ts)
tool_input_text() {
  local name="$1" ti="$2"
  case "$name" in
    Bash)         jq -r "$JQ_JOIN"' [.command, .description]|joinf' <<<"$ti" 2>/dev/null ;;
    WebFetch)     jq -r "$JQ_JOIN"' [.url, .prompt]|joinf' <<<"$ti" 2>/dev/null ;;
    WebSearch)    jq -r '.query // ""' <<<"$ti" 2>/dev/null ;;
    Write)        jq -r "$JQ_JOIN"' [.file_path, .content]|joinf' <<<"$ti" 2>/dev/null ;;
    Edit)         jq -r "$JQ_JOIN"' [.file_path, .old_string, .new_string]|joinf' <<<"$ti" 2>/dev/null ;;
    Read)         jq -r '.file_path // ""' <<<"$ti" 2>/dev/null ;;
    Glob)         jq -r "$JQ_JOIN"' [.pattern, .path]|joinf' <<<"$ti" 2>/dev/null ;;
    Grep)         jq -r "$JQ_JOIN"' [.pattern, .path]|joinf' <<<"$ti" 2>/dev/null ;;
    Task)         jq -r "$JQ_JOIN"' [.description, .subagent_type, .prompt]|joinf' <<<"$ti" 2>/dev/null ;;
    NotebookEdit) jq -r "$JQ_JOIN"' [.notebook_path, .new_source]|joinf' <<<"$ti" 2>/dev/null ;;
    TodoWrite)    jq -r "$JQ_S"' (.todos|s)' <<<"$ti" 2>/dev/null ;;
    ExitPlanMode) jq -r '.plan // ""' <<<"$ti" 2>/dev/null ;;
    ReadMcpResourceTool|ReadMcpResourceDirTool) jq -r "$JQ_JOIN"' [.server, .uri, .path]|joinf' <<<"$ti" 2>/dev/null ;;
    ListMcpResourcesTool) jq -r '.server // ""' <<<"$ti" 2>/dev/null ;;
    *)            jq -rc '.' <<<"$ti" 2>/dev/null ;;   # mcp__* and unknown -> whole input
  esac
}

# extract EVERY string from a tool result, recursively (mirrors collectStrings)
tool_output_text() { jq -r '[.. | strings] | join("\n")' <<<"$1" 2>/dev/null; }

# ----------------------------------------------------------------------------
# normalize per vendor + build the ScanPlan (KIND, TEXT, SERVER, TOOL, INTEXT)
# ----------------------------------------------------------------------------
KIND=""; TEXT=""; SERVER=""; TOOL=""; INTEXT=""; TOOL_NAME=""; STOP_ACTIVE="false"
SESSION=""; LABEL=""

norm_tool_name() { # cursor: "MCP:server:tool" -> "mcp__server__tool" (colons only)
  local n="$1"
  if [[ "$n" == MCP:* ]]; then printf 'mcp__%s' "$(printf '%s' "${n#MCP:}" | sed 's/:/__/g')"
  else printf '%s' "$n"; fi
}

case "$IEVENT" in
  UserPromptSubmit)
    LABEL="user prompt"; KIND="prompt"
    case "$VENDOR" in
      cline)    TEXT="$(j '.userPromptSubmit.prompt // empty')" ;;
      *)        TEXT="$(j '.prompt // empty')" ;;
    esac ;;

  PreToolUse)
    KIND="toolInput"
    case "$VENDOR" in
      cline)    TOOL_NAME="$(j '.preToolUse.toolName // empty')"; TI="$(jc '.preToolUse.parameters // {}')" ;;
      cursor)
        if [ "$RAW_EVENT" = "beforeShellExecution" ]; then
          TOOL_NAME="Shell"; TI="$(jc '{command: (.command // "")}')"
        else
          TOOL_NAME="$(norm_tool_name "$(j '.tool_name // empty')")"; TI="$(jc '.tool_input // {}')"
        fi ;;
      antigravity|gemini) TOOL_NAME="$(j '.tool_name // .toolCall.name // empty')"; TI="$(jc '.tool_input // .toolCall.args // {}')" ;;
      *)        TOOL_NAME="$(j '.tool_name // empty')"; TI="$(jc '.tool_input // {}')" ;;
    esac
    [ -z "$TI" ] && TI="{}"
    LABEL="${TOOL_NAME:-tool} input"
    TEXT="$(tool_input_text "$TOOL_NAME" "$TI")"
    tool_identity "$TOOL_NAME" "$TI" ;;

  PostToolUse)
    KIND="toolOutput"
    case "$VENDOR" in
      cline)    TOOL_NAME="$(j '.postToolUse.toolName // empty')"; TI="$(jc '.postToolUse.parameters // {}')"; TR="$(jc '.postToolUse.result // null')" ;;
      cursor)   TOOL_NAME="$(norm_tool_name "$(j '.tool_name // empty')")"; TI="$(jc '.tool_input // {}')"; TR="$(jc '.tool_response // .tool_output // null')" ;;
      antigravity|gemini) TOOL_NAME="$(j '.tool_name // .toolCall.name // empty')"; TI="$(jc '.tool_input // .toolCall.args // {}')"; TR="$(jc '.tool_response // .tool_result // null')" ;;
      *)        TOOL_NAME="$(j '.tool_name // empty')"; TI="$(jc '.tool_input // {}')"; TR="$(jc '.tool_response // .tool_result // null')" ;;
    esac
    [ -z "$TI" ] && TI="{}"; [ -z "$TR" ] && TR="null"
    LABEL="${TOOL_NAME:-tool} output"
    TEXT="$(tool_output_text "$TR")"
    INTEXT="$(tool_input_text "$TOOL_NAME" "$TI")"
    tool_identity "$TOOL_NAME" "$TI" ;;

  Stop)
    LABEL="model answer"; KIND="response"
    case "$VENDOR" in
      cline)    TEXT="$(j '.taskComplete.task // empty')" ;;
      cursor)   TEXT="$(j '.text // .response // .message // .content // .output // empty')" ;;
      antigravity|gemini) TEXT="$(j '.last_assistant_message // .prompt_response // .response // .agent_response // empty')"; STOP_ACTIVE="$(j '.stop_hook_active // false')" ;;
      *)        TEXT="$(j '.last_assistant_message // empty')"; STOP_ACTIVE="$(j '.stop_hook_active // false')" ;;
    esac ;;
esac

# Stop loop guard: never block twice in one turn.
if [ "$IEVENT" = "Stop" ] && { [ "$STOP_ACTIVE" = "true" ] || [ "$STOP_ACTIVE" = "1" ]; }; then
  dbg "stop_hook_active set — allowing (loop guard)"; render allow ""
fi

TEXT="$(flatten "$TEXT")"
INTEXT="$(flatten "$INTEXT")"

# ----------------------------------------------------------------------------
# config error -> fail-closed on input, warn on output
# ----------------------------------------------------------------------------
CFG_ERR=""
[ -z "$API_KEY" ] && CFG_ERR="PRISMA_AIRS_API_KEY not set"
[ -z "$CFG_ERR" ] && [ -z "$PROFILE_ID" ] && [ -z "$PROFILE_NAME" ] && CFG_ERR="PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set"
if [ -n "$CFG_ERR" ]; then
  log_line "$LABEL" "config_error ($CFG_ERR)"
  if [ "$SIDE" = "input" ]; then
    render block "Prisma AIRS not configured ($CFG_ERR) — blocking (fail-closed)"
  else
    render warn "Prisma AIRS not configured ($CFG_ERR) — content NOT scanned"
  fi
fi

# nothing scannable -> allow silently
if [ -z "$(printf '%s' "$TEXT" | tr -d '[:space:]')" ]; then
  dbg "no scannable content for $LABEL — allowing"; render allow ""
fi

# ----------------------------------------------------------------------------
# build AIRS request body (content type depends on KIND)
# ----------------------------------------------------------------------------
if [ -n "$PROFILE_ID" ]; then AI_PROFILE="$(jq -nc --arg id "$PROFILE_ID" '{profile_id:$id}')"
else AI_PROFILE="$(jq -nc --arg n "$PROFILE_NAME" '{profile_name:$n}')"; fi

# transaction id (per-event) + session id, portable (no macOS `md5`)
SESSION="$(j '.session_id // .taskId // .trajectory_id // .conversation_id // .conversationId // empty')"
if [ -z "$SESSION" ]; then
  CWD="$(j '.cwd // empty')"; [ -z "$CWD" ] && CWD="$PWD"
  SESSION="$(printf '%s' "$CWD" | { command -v sha256sum >/dev/null 2>&1 && sha256sum || shasum -a 256; } 2>/dev/null | cut -c1-32)"
fi
TXN="$(j '.tool_use_id // .prompt_id // .turn_id // empty')"; [ -z "$TXN" ] && TXN="$SESSION"

build_content() {
  case "$KIND" in
    prompt)   jq -nc --arg t "$TEXT" --argjson ca "$CODE_AWARE" '{prompt:$t} + (if $ca==1 then {code_prompt:$t} else {} end)' ;;
    response) jq -nc --arg t "$TEXT" --argjson ca "$CODE_AWARE" '{response:$t} + (if $ca==1 then {code_response:$t} else {} end)' ;;
    toolInput)
      jq -nc --arg t "$TEXT" --arg s "$SERVER" --arg tl "$TOOL" --argjson ca "$CODE_AWARE" \
        '{tool_event: ({metadata:{ecosystem:"mcp",method:"tools/call",server_name:$s,tool_invoked:$tl}}
                       + (if ($t|length)>0 then {input:$t} else {} end))}
         + (if $ca==1 then {code_prompt:$t} else {} end)' ;;
    toolOutput)
      jq -nc --arg t "$TEXT" --arg i "$INTEXT" --arg s "$SERVER" --arg tl "$TOOL" --argjson ca "$CODE_AWARE" \
        '{tool_event: ({metadata:{ecosystem:"mcp",method:"tools/call",server_name:$s,tool_invoked:$tl}}
                       + (if ($i|length)>0 then {input:$i} else {} end)
                       + {output:$t})}
         + (if $ca==1 then ({code_response:$t} + (if ($i|length)>0 then {code_prompt:$i} else {} end)) else {} end)' ;;
  esac
}
CONTENT="$(build_content)"

BODY="$(jq -nc \
  --arg txn "$TXN" --arg sid "$SESSION" --argjson prof "$AI_PROFILE" \
  --arg app_user "claude-code-user" --arg app_name "$APP_NAME" \
  --arg tool_name "$TOOL_NAME" --arg source "$IEVENT" --argjson content "$CONTENT" \
  '{transaction_id:$txn, session_id:$sid, ai_profile:$prof,
    metadata:{app_user:$app_user, app_name:$app_name, source:$source}
      + (if $tool_name!="" then {tool_name:$tool_name} else {} end),
    contents:[$content]}')"

# ----------------------------------------------------------------------------
# call AIRS (bounded retries + hard timeout)
# ----------------------------------------------------------------------------
SCAN=""; SCAN_ERR=""
attempt=0
while [ "$attempt" -le "$RETRIES" ]; do
  RESP="$(curl -s -L --max-time "$TIMEOUT_S" \
    -H "Content-Type: application/json" -H "Accept: application/json" \
    -H "x-pan-token: $API_KEY" -w $'\n%{http_code}' -d "$BODY" "$API_URL" 2>/dev/null)"
  CURL_RC=$?
  HTTP_CODE="${RESP##*$'\n'}"; BODY_TEXT="${RESP%$'\n'*}"
  if [ "$CURL_RC" -ne 0 ]; then SCAN_ERR="curl failed (rc=$CURL_RC, timeout ${TIMEOUT_S}s)";
  elif [ "${HTTP_CODE:0:1}" != "2" ]; then SCAN_ERR="HTTP $HTTP_CODE: $(printf '%s' "$BODY_TEXT" | head -c 200)";
  else SCAN="$BODY_TEXT"; SCAN_ERR=""; break; fi
  attempt=$((attempt+1))
done

# ----------------------------------------------------------------------------
# scan error -> fail policy
# ----------------------------------------------------------------------------
if [ -n "$SCAN_ERR" ] || [ -z "$SCAN" ]; then
  [ -z "$SCAN_ERR" ] && SCAN_ERR="empty response"
  log_line "$LABEL" "error($SCAN_ERR)"
  if [ "$IEVENT" = "Stop" ]; then
    render warn "AIRS scan error at Stop ($SCAN_ERR) — allowing"
  elif [ "$FAIL_MODE" = "closed" ] && [ "$SIDE" = "input" ]; then
    render block "Prisma AIRS scan failed ($SCAN_ERR) — blocking (fail-closed)"
  else
    render warn "AIRS scan error ($SCAN_ERR) — allowing (fail-open)"
  fi
fi

# ----------------------------------------------------------------------------
# parse verdict
# ----------------------------------------------------------------------------
ACTION="$(jq -r '.action // "unknown"' <<<"$SCAN" 2>/dev/null)"
CATEGORY="$(jq -r '.category // "unknown"' <<<"$SCAN" 2>/dev/null)"
SCAN_ID="$(jq -r '.scan_id // "unknown"' <<<"$SCAN" 2>/dev/null)"
DETS="$(jq -r '
  def truekeys: (. // {}) | [paths(.==true) as $p | $p[-1] | select(type=="string")];
  ((.prompt_detected|truekeys)+(.response_detected|truekeys)+(.tool_detected|truekeys)) | unique | join(", ")' <<<"$SCAN" 2>/dev/null)"

if [ "$ACTION" = "block" ]; then
  REASON="Blocked by Prisma AIRS: $CATEGORY"
  [ -n "$DETS" ] && REASON="$REASON [$DETS]"
  REASON="$REASON (scan_id: $SCAN_ID)"
  log_line "$LABEL" "BLOCK $REASON"
  render block "$REASON"
else
  TAG="allow"; [ -n "$DETS" ] && TAG="allow [$DETS]"; TAG="$TAG [scan:$SCAN_ID]"
  log_line "$LABEL" "$TAG"
  render allow ""
fi
