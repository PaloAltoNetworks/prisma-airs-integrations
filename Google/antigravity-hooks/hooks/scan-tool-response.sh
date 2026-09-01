#!/bin/bash

# Prisma AIRS Tool Response Security Scanner for Google Antigravity
# Hook type: PostToolUse
#
# Scans the output of web-fetching tools for indirect prompt injection (IPI)
# and malicious content. Reads the tool result from the transcript since
# Antigravity's PostToolUse hook does not include output in its stdin payload.
#
# LIMITATION: PostToolUse in Antigravity does not support blocking —
# output must be exactly {}. This hook provides detection and logging only.
# Use scan-tool-request.sh (PreToolUse) for hard blocking.
#
# Tools scanned:  read_url_content, search_web
#
# Output (stdout): Always {} (Antigravity requirement for PostToolUse)

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

# Always output {} — PostToolUse cannot block in Antigravity
# We run this hook for detection/logging only.
CLEANUP='echo "{}"'
trap "$CLEANUP" EXIT

# Skip if config not set (fail open — can't block here anyway)
if [[ -z "$PRISMA_AIRS_API_KEY" ]] || ! has_profile; then
    exit 0
fi

INPUT_JSON=$(cat)
CONVERSATION_ID=$(echo "$INPUT_JSON" | jq -r '.conversationId // empty')
STEP_IDX=$(echo "$INPUT_JSON" | jq -r '.stepIdx // empty')
TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcriptPath // empty')

# Cannot scan without transcript
if [[ -z "$TRANSCRIPT_PATH" || ! -f "$TRANSCRIPT_PATH" ]]; then
    exit 0
fi

# Read the tool output for this stepIdx from the transcript.
# Antigravity writes tool results as JSONL records. We search for the
# record matching our stepIdx with a tool-result role.
# Supported formats:
#   { "role": "tool",   "stepIdx": N, "output": "..." }
#   { "type": "tool_result", "stepIdx": N, "content": "..." }
TOOL_OUTPUT=$(grep -m1 "\"stepIdx\":${STEP_IDX}" "$TRANSCRIPT_PATH" 2>/dev/null | \
    jq -r '
      if .output then .output
      elif .content then
        if (.content | type) == "string" then .content
        elif (.content | type) == "array" then
          (.content | map(if type == "object" then (.text // "") else . end) | join(""))
        else (.content | tostring)
        end
      else empty
      end
    ' 2>/dev/null | head -c 20000)

if [[ -z "$TOOL_OUTPUT" ]]; then
    exit 0
fi

# Also get the tool name + input from transcript for tool_event payload
TRANSCRIPT_RECORD=$(grep -m1 "\"stepIdx\":${STEP_IDX}" "$TRANSCRIPT_PATH" 2>/dev/null)
TOOL_NAME=$(echo "$TRANSCRIPT_RECORD" | jq -r '.toolName // .name // "unknown"' 2>/dev/null)
TOOL_INPUT=$(echo "$TRANSCRIPT_RECORD" | jq -r '.input // .args // {}' 2>/dev/null | head -c 2000)

TRANSACTION_ID="${CONVERSATION_ID:-$(echo "$TRANSCRIPT_PATH$STEP_IDX" | sha256sum | cut -c1-32)}"
AI_PROFILE=$(build_ai_profile)

# Scan as tool_event — required for IPI / context-poisoning detection.
# AIRS runs indirect prompt injection detection on tool_event content type,
# not on response, so scanning as tool_event is essential here.
PAYLOAD=$(jq -n \
  --arg session_id "$CONVERSATION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "antigravity-user" \
  --arg app_name "Google Antigravity" \
  --arg source "post-tool-use" \
  --arg tool_name "$TOOL_NAME" \
  --arg tool_input "$TOOL_INPUT" \
  --arg tool_output "$TOOL_OUTPUT" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {
      app_user: $app_user,
      app_name: $app_name,
      source: $source,
      ecosystem: "mcp",
      server_name: ("antigravity/" + $tool_name),
      tool_invoked: $tool_name
    },
    contents: [{
      tool_event: {
        input: $tool_input,
        output: $tool_output
      }
    }]
  }')

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
    # Cannot hard-block here — log the detection for audit/SIEM
    echo "[$(date)] ⚠️  DETECTED (post-tool, cannot block) [$TOOL_NAME]: $CATEGORY - [$DETECTED_CATEGORIES] (scan_id: $SCAN_ID, conv: $CONVERSATION_ID, step: $STEP_IDX)" >> "$LOG_FILE"
else
    echo "[$(date)] ✅ CLEAN RESPONSE [$TOOL_NAME] (scan_id: $SCAN_ID, step: $STEP_IDX)" >> "$LOG_FILE"
fi

exit 0
