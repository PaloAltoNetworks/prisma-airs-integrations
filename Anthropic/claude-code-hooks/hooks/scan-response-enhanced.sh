#!/bin/bash

LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/prisma-airs.log}"

# Ensure log file exists before anything writes to it
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Prisma AIRS API Configuration
PRISMA_AIRS_API_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
PRISMA_AIRS_PROFILE_ID="${PRISMA_AIRS_PROFILE_ID:-}"

# Build ai_profile JSON: prefer profile_id over profile_name
build_ai_profile() {
    if [[ -n "$PRISMA_AIRS_PROFILE_ID" ]]; then
        echo "{\"profile_id\": \"$PRISMA_AIRS_PROFILE_ID\"}"
    elif [[ -n "$PRISMA_AIRS_PROFILE_NAME" ]]; then
        echo "{\"profile_name\": \"$PRISMA_AIRS_PROFILE_NAME\"}"
    else
        echo ""
    fi
}

has_profile() {
    [[ -n "$PRISMA_AIRS_PROFILE_ID" || -n "$PRISMA_AIRS_PROFILE_NAME" ]]
}

# Set app name with optional custom suffix
if [[ -n "$CLAUDE_CODE_APP_SUFFIX" ]]; then
    APP_NAME="Claude Code-${CLAUDE_CODE_APP_SUFFIX}"
else
    APP_NAME="Claude Code"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Parse the hook input
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
TOOL_RESPONSE=$(echo "$INPUT_JSON" | jq -r '.tool_response // ""')

# MCP tool responses are handled by scan-mcp-response.sh so they can use
# AIRS tool_event semantics without generic response duplication.
if [[ "$TOOL_NAME" == mcp__* ]]; then
    echo "[$(date)] $TOOL_NAME: Skipping MCP response in generic response hook" >> "$LOG_FILE"
    exit 0
fi

# Use Claude Code session_id as the AIRS transaction_id for session-level tracing.
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi
TRANSACTION_ID="$SESSION_ID"

# Log that we're processing this tool
echo "[$(date)] 🔍 $TOOL_NAME: PostToolUse hook triggered" >> "$LOG_FILE"

# Enhanced response content extraction - try multiple approaches
RESPONSE_CONTENT=""

# First attempt: Enhanced extraction
RESPONSE_CONTENT="$(echo "$INPUT_JSON" \
  | jq -r '
      .tool_response
      | if type=="object" then
          # try common fields first, else collect strings
          (.result // .content // .text // .body // .message // .data // .output // .response // .value)
          // (.. | strings | join("\n"))
        elif type=="string" then
          .
        else
          ""
        end
    ' \
  | sed -e 's/\r//g')"

# Fallback: If extraction failed, try simpler approach
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    # Try extracting all strings from tool_response
    RESPONSE_CONTENT="$(echo "$INPUT_JSON" | jq -r '.tool_response | .. | strings' 2>/dev/null | tr '\n' ' ' | head -c 20000)"
fi

# Final fallback: Convert entire tool_response to string if it's not null
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    TOOL_RESP_RAW="$(echo "$INPUT_JSON" | jq -r '.tool_response // empty')"
    if [[ -n "$TOOL_RESP_RAW" && "$TOOL_RESP_RAW" != "null" ]]; then
        RESPONSE_CONTENT="$TOOL_RESP_RAW"
    fi
fi

# Log content extraction result
echo "[$(date)] 🔍 $TOOL_NAME: Extracted content length: ${#RESPONSE_CONTENT}" >> "$LOG_FILE"

# Skip if no content to scan
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    echo "[$(date)] 🔍 $TOOL_NAME: Skipping - insufficient content (${#RESPONSE_CONTENT} chars)" >> "$LOG_FILE"
    exit 0
fi

# Fail-closed: block if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking response (fail-closed)" >&2
    exit 2
fi

# Scan tool output as a tool_event (NOT a model response).
#
# WebFetch / WebSearch / Bash return external, untrusted content - the classic
# indirect-prompt-injection (IPI) vector. AIRS only runs prompt-injection / AI-agent /
# context-poisoning detection on the `prompt` and `tool_event` content types, NOT on
# `response`. Scanning this output as `response` therefore silently MISSES IPI (the
# response data type only evaluates dlp / toxic_content / url_cats / malicious_code /
# db_security / ungrounded / topic_violation). Submitting it as `tool_event` runs the
# full suite and flags "context poisoning", mirroring scan-mcp-response.sh.
#
# NOTE: AIRS currently requires tool_event `ecosystem` to be "mcp" (other values return
# HTTP error "unsupported ecosystem"). We label the source via server_name/tool_invoked.
TRUNCATED_CONTENT="$(echo "$RESPONSE_CONTENT" | head -c 20000 | tr '\n' ' ')"
if [[ ${#TRUNCATED_CONTENT} -ge 10 ]]; then
    # Use jq for safe JSON construction (no raw variable interpolation)
    AI_PROFILE_JSON=$(build_ai_profile)
    if [[ -z "$AI_PROFILE_JSON" ]]; then
        AI_PROFILE_JSON="{}"
    fi
    # Tool input (URL / query / command) enriches detection; default to {} if absent.
    TOOL_INPUT_STR=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}' 2>/dev/null)
    if [[ -z "$TOOL_INPUT_STR" || "$TOOL_INPUT_STR" == "null" ]]; then
        TOOL_INPUT_STR="{}"
    fi
    CONTENT_PAYLOAD=$(jq -n \
      --arg session_id "$SESSION_ID" \
      --arg transaction_id "$TRANSACTION_ID" \
      --argjson ai_profile "$AI_PROFILE_JSON" \
      --arg app_user "claude-code-user" \
      --arg app_name "$APP_NAME" \
      --arg tool_name "$TOOL_NAME" \
      --arg input "$TOOL_INPUT_STR" \
      --arg output "$TRUNCATED_CONTENT" \
      '{
        session_id: $session_id,
        transaction_id: $transaction_id,
        ai_profile: $ai_profile,
        metadata: {app_user: $app_user, app_name: $app_name, tool_name: $tool_name, source: "tool-output"},
        contents: [{
          tool_event: {
            metadata: {
              ecosystem: "mcp",
              method: "tools/call",
              server_name: ("claude-code/" + $tool_name),
              tool_invoked: $tool_name
            },
            input: $input,
            output: $output
          }
        }]
      }')

    # Curl with timeouts and retries
    CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
    CONTENT_RESULT=$(curl "${CURL_OPTS[@]}" "$PRISMA_AIRS_API_URL" \
      -H "Content-Type: application/json" -H "Accept: application/json" -H "x-pan-token: $PRISMA_AIRS_API_KEY" -d "$CONTENT_PAYLOAD")
    CONTENT_ACTION=$(echo "$CONTENT_RESULT" | jq -r '.action // "unknown"')
    CONTENT_CATEGORY=$(echo "$CONTENT_RESULT" | jq -r '.category // "unknown"')
    CONTENT_SCAN_ID=$(echo "$CONTENT_RESULT" | jq -r '.scan_id // "unknown"')
    TOOL_VERDICT=$(echo "$CONTENT_RESULT" | jq -r '.tool_detected.verdict // empty')

    # Collect true detections from tool_detected (summary + per-entry input/output)
    # plus prompt_detected/response_detected as a safety net.
    RESP_DETECTIONS=$(echo "$CONTENT_RESULT" | jq -r '
      [
        (.tool_detected.summary.detections // {} | to_entries[]? | select(.value == true) | .key),
        (.tool_detected.input_detected.detection_entries // [] | .[]? | (.detections // {}) | to_entries[]? | select(.value == true) | .key),
        (.tool_detected.output_detected.detection_entries // [] | .[]? | (.detections // {}) | to_entries[]? | select(.value == true) | .key),
        (.prompt_detected // {} | to_entries[]? | select(.value == true) | .key),
        (.response_detected // {} | to_entries[]? | select(.value == true) | .key)
      ] | unique | join(",")
    ')

    if [[ "$CONTENT_ACTION" == "block" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME tool output: $CONTENT_CATEGORY - verdict:${TOOL_VERDICT:-unknown} detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
        BLOCK_MSG="🚫 Blocked by Prisma AIRS: $TOOL_NAME output contained $CONTENT_CATEGORY content (detected: $RESP_DETECTIONS)"
      else
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME tool output: $CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
        BLOCK_MSG="🚫 Blocked by Prisma AIRS: $TOOL_NAME output contained $CONTENT_CATEGORY content"
      fi
      # Show user message on stderr (visible in Claude Code terminal)
      echo "" >&2
      echo "$BLOCK_MSG" >&2
      echo "" >&2
      # Output blocking JSON on stdout (the only thing Claude Code reads from this pipe)
      printf '%s' "$(jq -n --arg msg "$BLOCK_MSG" '{
  "continue": false,
  "stopReason": "Prisma AIRS blocked tool output",
  "systemMessage": $msg,
  "hookSpecificOutput": { "hookEventName": "PostToolUse" }
}')"
      exit 0
    elif [[ "$CONTENT_ACTION" != "allow" && "$CONTENT_ACTION" != "unknown" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] ⚠️  $TOOL_NAME tool output warning: $CONTENT_ACTION/$CONTENT_CATEGORY - detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      else
        echo "[$(date)] ⚠️  $TOOL_NAME tool output warning: $CONTENT_ACTION/$CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      fi
    else
      # allow (or unknown verdict): still log the scan id so every web/tool scan is
      # mappable back to SCM, even with no detection.
      echo "[$(date)] ✓ $TOOL_NAME tool output $CONTENT_ACTION [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
    fi
fi

exit 0
