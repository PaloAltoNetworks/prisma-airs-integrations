#!/bin/bash

# Prisma AIRS MCP Request Security Scanner Hook for Codex CLI
# Scans MCP tool inputs BEFORE the tool call is executed.
# Hook Event: PreToolUse (matcher: mcp__.*)

LOG_FILE="${SECURITY_LOG_PATH:-.codex/hooks/prisma-airs.log}"
PRISMA_AIRS_API_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
PRISMA_AIRS_PROFILE_ID="${PRISMA_AIRS_PROFILE_ID:-}"

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

extract_session_id() {
    local input_json="$1"
    local session_id
    session_id=$(echo "$input_json" | jq -r '.session_id // empty' 2>/dev/null)

    if [[ -n "$session_id" ]]; then
        echo "$session_id"
        return
    fi

    local transcript_path
    transcript_path=$(echo "$input_json" | jq -r '.transcript_path // empty' 2>/dev/null)
    if [[ -n "$transcript_path" ]]; then
        session_id=$(echo "$transcript_path" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
        if [[ -z "$session_id" || "$session_id" == "$transcript_path" ]]; then
            session_id=$(echo "$transcript_path" | md5 | cut -c1-32)
        fi
        echo "$session_id"
        return
    fi

    echo "$PWD" | md5 | cut -c1-32
}

extract_tool_transaction_id() {
    local input_json="$1"
    local session_id="$2"
    local turn_id
    local tool_use_id
    turn_id=$(echo "$input_json" | jq -r '.turn_id // empty' 2>/dev/null)
    tool_use_id=$(echo "$input_json" | jq -r '.tool_use_id // empty' 2>/dev/null)

    if [[ -n "$turn_id" && -n "$tool_use_id" ]]; then
        echo "${turn_id}:${tool_use_id}"
    elif [[ -n "$tool_use_id" ]]; then
        echo "$tool_use_id"
    elif [[ -n "$turn_id" ]]; then
        echo "$turn_id"
    else
        echo "$session_id"
    fi
}

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

if [[ -n "$CODEX_APP_SUFFIX" ]]; then
    APP_NAME="Codex CLI-${CODEX_APP_SUFFIX}"
else
    APP_NAME="Codex CLI"
fi

INPUT_JSON=$(cat)

TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"' 2>/dev/null)
TOOL_INPUT=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}' 2>/dev/null)
MODEL=$(echo "$INPUT_JSON" | jq -r '.model // "unknown"' 2>/dev/null)
SESSION_ID=$(extract_session_id "$INPUT_JSON")
TRANSACTION_ID=$(extract_tool_transaction_id "$INPUT_JSON" "$SESSION_ID")

if [[ "$TOOL_NAME" != mcp__* ]]; then
    exit 0
fi

MCP_SERVER=$(echo "$TOOL_NAME" | awk -F'__' '{print $2}')
TOOL_INVOKED=$(echo "$TOOL_NAME" | awk -F'__' '{print $3}')

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking MCP request (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking MCP request (fail-closed)" >&2
    exit 2
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set — blocking MCP request (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: profile not configured — blocking MCP request (fail-closed)" >&2
    exit 2
fi

if [[ -z "$TOOL_INPUT" || "$TOOL_INPUT" == "null" ]]; then
    TOOL_INPUT="{}"
fi

echo "[$(date)] MCP REQUEST: Scanning $TOOL_NAME input (${#TOOL_INPUT} chars)" >> "$LOG_FILE"

AI_PROFILE=$(build_ai_profile)

PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "codex-cli-user" \
  --arg app_name "$APP_NAME" \
  --arg ai_model "$MODEL" \
  --arg server_name "$MCP_SERVER" \
  --arg tool_invoked "$TOOL_INVOKED" \
  --arg input "$TOOL_INPUT" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, ai_model: $ai_model, tool_name: ($server_name + "/" + $tool_invoked)},
    contents: [{
      prompt: $input,
      tool_event: {
        metadata: {
          ecosystem: "mcp",
          method: "tools/call",
          server_name: $server_name,
          tool_invoked: $tool_invoked
        },
        input: $input
      }
    }]
  }')

SCAN_RESULT=$(curl -s -L --max-time 10 --retry 1 "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

if [[ -z "$SCAN_RESULT" ]]; then
    echo "[$(date)] ERROR: Empty response from AIRS API for $TOOL_NAME request — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: empty API response — blocking MCP request (fail-closed)" >&2
    exit 2
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
REPORT_ID=$(echo "$SCAN_RESULT" | jq -r '.report_id // empty' 2>/dev/null)

DETECTIONS=$(echo "$SCAN_RESULT" | jq -r '
  [.prompt_detected // {}, .response_detected // {}]
  | add
  | to_entries
  | map(select(.value == true) | .key)
  | unique
  | join(",")
' 2>/dev/null)

if [[ "$ACTION" == "block" ]]; then
    LOG_ENTRY="[$(date)] BLOCKED MCP REQUEST: $TOOL_NAME - $CATEGORY"
    [[ -n "$DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$DETECTIONS]"
    LOG_ENTRY="$LOG_ENTRY [scan:$SCAN_ID]"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY [report:$REPORT_ID]"
    echo "$LOG_ENTRY" >> "$LOG_FILE"

    BLOCK_MSG="Blocked by Prisma AIRS: $TOOL_NAME request contained $CATEGORY content"
    [[ -n "$DETECTIONS" ]] && BLOCK_MSG="$BLOCK_MSG (detected: $DETECTIONS)"
    echo "$BLOCK_MSG" >&2
    exit 2
fi

if [[ "$ACTION" != "allow" ]]; then
    LOG_ENTRY="[$(date)] ERROR: Unexpected AIRS action for MCP request: $TOOL_NAME - $ACTION/$CATEGORY — blocking (fail-closed)"
    LOG_ENTRY="$LOG_ENTRY [scan:$SCAN_ID]"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY [report:$REPORT_ID]"
    echo "$LOG_ENTRY" >> "$LOG_FILE"

    BLOCK_MSG="Prisma AIRS: unexpected API response for $TOOL_NAME request — blocking (fail-closed)"
    echo "$BLOCK_MSG" >&2
    exit 2
fi

LOG_ENTRY="[$(date)] ALLOWED MCP REQUEST: $TOOL_NAME"
[[ -n "$DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY: $CATEGORY - detected: [$DETECTIONS]"
LOG_ENTRY="$LOG_ENTRY [scan:$SCAN_ID]"
echo "$LOG_ENTRY" >> "$LOG_FILE"
exit 0
