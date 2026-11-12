#!/bin/bash

# Prisma AIRS Tool Request Security Scanner for Google Antigravity
# Hook type: PreToolUse
#
# Scans tool arguments before execution. Supports all Antigravity built-in tools.
# Hard blocks via JSON { "decision": "deny" } — the tool call is never executed.
#
# Tools scanned:
#   read_url_content  — URL intel + prompt scan on the target URL
#   search_web        — prompt scan on the query string
#   run_command       — prompt scan on the command line (detects malicious commands)
#   write_to_file     — prompt scan on file content (detects DLP / malicious code)
#   replace_file_content / multi_replace_file_content — same as write_to_file
#   invoke_subagent   — prompt scan on subagent prompt (detects IPI via delegation)
#   send_message      — prompt scan on outbound message content
#
# Output (stdout): JSON { "decision": "allow"|"deny", "reason": "..." }

LOG_FILE="${SECURITY_LOG_PATH:-${HOME}/.gemini/hooks/prisma-airs.log}"
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

mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Fail-closed on missing config
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking tool call (fail-closed)" >> "$LOG_FILE"
    echo '{"decision": "deny", "reason": "Prisma AIRS: API key not configured. Tool call blocked (fail-closed)."}'
    exit 0
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS profile not set — blocking tool call (fail-closed)" >> "$LOG_FILE"
    echo '{"decision": "deny", "reason": "Prisma AIRS: security profile not configured. Tool call blocked (fail-closed)."}'
    exit 0
fi

INPUT_JSON=$(cat)
CONVERSATION_ID=$(echo "$INPUT_JSON" | jq -r '.conversationId // empty')
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.toolCall.name // empty')
TOOL_ARGS=$(echo "$INPUT_JSON" | jq -c '.toolCall.args // {}')

TRANSACTION_ID="${CONVERSATION_ID:-$(date +%s%N | sha256sum | cut -c1-32)}"
AI_PROFILE=$(build_ai_profile)

# Extract content to scan and set scan type based on tool
SCAN_CONTENT=""
SCAN_TYPE="prompt"   # "prompt" or "url"

case "$TOOL_NAME" in
    read_url_content)
        URL=$(echo "$TOOL_ARGS" | jq -r '.Url // empty')
        SCAN_CONTENT="$URL"
        SCAN_TYPE="url"
        ;;
    search_web)
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.query // empty')
        ;;
    run_command)
        # Scan command line; also extract any embedded URL for URL intel
        CMD=$(echo "$TOOL_ARGS" | jq -r '.CommandLine // empty')
        SCAN_CONTENT="$CMD"
        # Opportunistically extract an embedded URL (curl/wget/fetch patterns)
        EMBEDDED_URL=$(printf '%s' "$CMD" | grep -oE 'https?://[^[:space:]"'"'"';|`<>]+' | head -1)
        if [[ -n "$EMBEDDED_URL" ]]; then
            SCAN_TYPE="url"
            SCAN_CONTENT="$EMBEDDED_URL"
        fi
        ;;
    write_to_file)
        # Scan code/file content for DLP or malicious payload
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.CodeContent // empty' | head -c 20000)
        ;;
    replace_file_content)
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.ReplacementContent // empty' | head -c 20000)
        ;;
    multi_replace_file_content)
        # Concatenate all replacement chunks for scanning
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.ReplacementChunks[]?.ReplacementContent // empty' | head -c 20000)
        ;;
    invoke_subagent)
        # Scan subagent prompts — prevents IPI from propagating through delegation
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.Subagents[]?.Prompt // empty' | head -c 20000)
        ;;
    send_message)
        SCAN_CONTENT=$(echo "$TOOL_ARGS" | jq -r '.Message // empty' | head -c 10000)
        ;;
    *)
        # Unknown tool — allow without scanning
        echo '{"decision": "allow"}'
        exit 0
        ;;
esac

# Nothing to scan — allow
if [[ -z "$SCAN_CONTENT" ]]; then
    echo '{"decision": "allow"}'
    exit 0
fi

echo "[$(date)] 🔍 SCANNING [$TOOL_NAME] (type=$SCAN_TYPE, conv=$CONVERSATION_ID)" >> "$LOG_FILE"

# Build AIRS payload
if [[ "$SCAN_TYPE" == "url" ]]; then
    PAYLOAD=$(jq -n \
      --arg session_id "$CONVERSATION_ID" \
      --arg transaction_id "$TRANSACTION_ID" \
      --argjson ai_profile "$AI_PROFILE" \
      --arg app_user "antigravity-user" \
      --arg app_name "Google Antigravity" \
      --arg source "pre-tool-use" \
      --arg tool_name "$TOOL_NAME" \
      --arg url "$SCAN_CONTENT" \
      '{
        session_id: $session_id,
        transaction_id: $transaction_id,
        ai_profile: $ai_profile,
        metadata: {app_user: $app_user, app_name: $app_name, source: $source, tool: $tool_name},
        contents: [{prompt: $url}]
      }')
else
    PAYLOAD=$(jq -n \
      --arg session_id "$CONVERSATION_ID" \
      --arg transaction_id "$TRANSACTION_ID" \
      --argjson ai_profile "$AI_PROFILE" \
      --arg app_user "antigravity-user" \
      --arg app_name "Google Antigravity" \
      --arg source "pre-tool-use" \
      --arg tool_name "$TOOL_NAME" \
      --arg content "$SCAN_CONTENT" \
      '{
        session_id: $session_id,
        transaction_id: $transaction_id,
        ai_profile: $ai_profile,
        metadata: {app_user: $app_user, app_name: $app_name, source: $source, tool: $tool_name},
        contents: [{prompt: $content}]
      }')
fi

SCAN_RESULT=$(curl -s -L --max-time 10 "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')

DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | \
  jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | join(",")' 2>/dev/null)

if [[ "$ACTION" == "block" ]]; then
    echo "[$(date)] 🚫 BLOCKED TOOL [$TOOL_NAME]: $CATEGORY - detected: [$DETECTED_CATEGORIES] (scan_id: $SCAN_ID)" >> "$LOG_FILE"
    REASON="🚫 Prisma AIRS blocked [$TOOL_NAME]: $CATEGORY [$DETECTED_CATEGORIES] (scan_id: $SCAN_ID)"
    jq -n --arg reason "$REASON" '{"decision": "deny", "reason": $reason}'
    exit 0
fi

echo "[$(date)] ✅ ALLOWED TOOL [$TOOL_NAME] (scan_id: $SCAN_ID)" >> "$LOG_FILE"
echo '{"decision": "allow"}'
exit 0
