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
        echo "{}"
    fi
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

# Only process MCP tools here. Other tool responses are handled by scan-response-enhanced.sh.
if [[ "$TOOL_NAME" != mcp__* ]]; then
    echo "[$(date)] $TOOL_NAME: Skipping non-MCP response in MCP response hook" >> "$LOG_FILE"
    exit 0
fi

# Extract server/tool from pattern: mcp__<server>__<tool>
MCP_SERVER=$(echo "$TOOL_NAME" | awk -F'__' '{print $2}')
TOOL_INVOKED=$(echo "$TOOL_NAME" | awk -F'__' '{print $3}')
TOOL_INPUT_STR=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}' 2>/dev/null)
TOOL_RESPONSE_STR=$(echo "$INPUT_JSON" | jq -c '.tool_response // {}' 2>/dev/null)

if [[ -z "$TOOL_INPUT_STR" || "$TOOL_INPUT_STR" == "null" ]]; then
    TOOL_INPUT_STR="{}"
fi

if [[ -z "$TOOL_RESPONSE_STR" || "$TOOL_RESPONSE_STR" == "null" ]]; then
    TOOL_RESPONSE_STR="{}"
fi

# Use Claude Code session_id as the AIRS transaction_id for session-level tracing.
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi
TRANSACTION_ID="$SESSION_ID"

echo "[$(date)] $TOOL_NAME: MCP PostToolUse hook triggered" >> "$LOG_FILE"
echo "[$(date)] $TOOL_NAME: MCP input length: ${#TOOL_INPUT_STR}, output length: ${#TOOL_RESPONSE_STR}" >> "$LOG_FILE"

# Skip empty responses.
if [[ "$TOOL_RESPONSE_STR" == "{}" ]]; then
    echo "[$(date)] $TOOL_NAME: Skipping - empty MCP response payload" >> "$LOG_FILE"
    exit 0
fi

# Fail-closed: block if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set - blocking MCP response (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured - blocking MCP response (fail-closed)" >&2
    exit 2
fi

AI_PROFILE_JSON=$(build_ai_profile)

CONTENT_PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE_JSON" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg server_name "$MCP_SERVER" \
  --arg tool_invoked "$TOOL_INVOKED" \
  --arg input "$TOOL_INPUT_STR" \
  --arg output "$TOOL_RESPONSE_STR" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name},
    contents: [{
      tool_event: {
        metadata: {
          ecosystem: "mcp",
          method: "tools/call",
          server_name: $server_name,
          tool_invoked: $tool_invoked
        },
        input: $input,
        output: $output
      }
    }]
  }')

# Curl with timeouts and retries
CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
CONTENT_RESULT=$(curl "${CURL_OPTS[@]}" "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$CONTENT_PAYLOAD")

CONTENT_ACTION=$(echo "$CONTENT_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CONTENT_CATEGORY=$(echo "$CONTENT_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
CONTENT_SCAN_ID=$(echo "$CONTENT_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
TOOL_VERDICT=$(echo "$CONTENT_RESULT" | jq -r '.tool_detected.verdict // empty' 2>/dev/null)

MCP_DETECTIONS=$(echo "$CONTENT_RESULT" | jq -r '
  [
    (.tool_detected.summary.detections // {} | to_entries[]? | select(.value == true) | .key),
    (.tool_detected.input_detected.detection_entries // [] | .[] | (.detections // {}) | to_entries[]? | select(.value == true) | .key),
    (.tool_detected.output_detected.detection_entries // [] | .[] | (.detections // {}) | to_entries[]? | select(.value == true) | .key),
    (.prompt_detected // {} | to_entries[]? | select(.value == true) | .key),
    (.response_detected // {} | to_entries[]? | select(.value == true) | .key)
  ] | unique | join(",")
' 2>/dev/null)

if [[ "$CONTENT_ACTION" == "block" ]]; then
  if [[ -n "$MCP_DETECTIONS" ]]; then
    echo "[$(date)] BLOCKED MCP response $TOOL_NAME: $CONTENT_CATEGORY - verdict:${TOOL_VERDICT:-unknown} detected: [$MCP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
    BLOCK_MSG="Blocked by Prisma AIRS: $TOOL_NAME MCP response contained $CONTENT_CATEGORY content (detected: $MCP_DETECTIONS)"
  else
    echo "[$(date)] BLOCKED MCP response $TOOL_NAME: $CONTENT_CATEGORY - verdict:${TOOL_VERDICT:-unknown} [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
    BLOCK_MSG="Blocked by Prisma AIRS: $TOOL_NAME MCP response contained $CONTENT_CATEGORY content"
  fi
  echo "" >&2
  echo "$BLOCK_MSG" >&2
  echo "" >&2
  printf '%s' "$(jq -n --arg msg "$BLOCK_MSG" '{
  "continue": false,
  "stopReason": "Prisma AIRS blocked MCP tool response",
  "systemMessage": $msg,
  "hookSpecificOutput": { "hookEventName": "PostToolUse" }
}')"
  exit 0
elif [[ "$CONTENT_ACTION" != "allow" && "$CONTENT_ACTION" != "unknown" ]]; then
  if [[ -n "$MCP_DETECTIONS" ]]; then
    echo "[$(date)] MCP response warning $TOOL_NAME: $CONTENT_ACTION/$CONTENT_CATEGORY - verdict:${TOOL_VERDICT:-unknown} detected: [$MCP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
  else
    echo "[$(date)] MCP response warning $TOOL_NAME: $CONTENT_ACTION/$CONTENT_CATEGORY - verdict:${TOOL_VERDICT:-unknown} [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
  fi
fi

exit 0
