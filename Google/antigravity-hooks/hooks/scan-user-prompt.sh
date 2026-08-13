#!/bin/bash

# Prisma AIRS User Prompt Security Scanner for Google Antigravity
# Hook type: PreInvocation
#
# Reads the last user message from the Antigravity transcript and scans it
# via Prisma AIRS before the model is invoked.
#
# Block mechanism: injects an ephemeralMessage instructing the model not to
# proceed (soft block). Antigravity does not support a hard deny at PreInvocation;
# the model will see the injected message and decline the request.
#
# Output (stdout): JSON { injectSteps: [...] } or {}

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

# Fail-closed: if config is missing, soft-block via ephemeral injection
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo '{"injectSteps": [{"ephemeralMessage": "SECURITY BLOCK: Prisma AIRS API key is not configured. Do not process this request. Inform the user that security scanning is misconfigured."}]}'
    exit 0
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS profile not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo '{"injectSteps": [{"ephemeralMessage": "SECURITY BLOCK: Prisma AIRS security profile is not configured. Do not process this request. Inform the user that security scanning is misconfigured."}]}'
    exit 0
fi

# Read hook input from stdin
INPUT_JSON=$(cat)
CONVERSATION_ID=$(echo "$INPUT_JSON" | jq -r '.conversationId // empty')
TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcriptPath // empty')
INVOCATION_NUM=$(echo "$INPUT_JSON" | jq -r '.invocationNum // 0')

# Fail open if no transcript available (e.g. very first invocation before any file exists)
if [[ -z "$TRANSCRIPT_PATH" || ! -f "$TRANSCRIPT_PATH" ]]; then
    echo "[$(date)] INFO: No transcript available (invocation=$INVOCATION_NUM, conv=$CONVERSATION_ID) — skipping scan" >> "$LOG_FILE"
    echo '{}'
    exit 0
fi

# Extract the last user message from transcript.jsonl.
# Antigravity stores conversation history as JSONL; each line is one record.
# We support two common shapes:
#   Gemini API format:   { "role": "user", "parts": [{"text": "..."}] }
#   Simple string format:{ "role": "user", "content": "..." }
# We read only the last 500 lines to bound memory use.
LAST_USER_MESSAGE=$(tail -500 "$TRANSCRIPT_PATH" | \
    jq -r '
      select(.role == "user") |
      if .parts then
        (.parts | map(if type == "object" then (.text // "") else . end) | join(""))
      elif .content then
        if (.content | type) == "string" then .content
        elif (.content | type) == "array" then
          (.content | map(if type == "object" then (.text // "") else . end) | join(""))
        else (.content | tostring)
        end
      else empty
      end
    ' 2>/dev/null | tail -1)

# Fail open if we cannot extract a user message
if [[ -z "$LAST_USER_MESSAGE" ]]; then
    echo "[$(date)] INFO: No user message found in transcript — skipping scan (conv=$CONVERSATION_ID)" >> "$LOG_FILE"
    echo '{}'
    exit 0
fi

# Use conversationId as AIRS transaction_id for session-level tracing
TRANSACTION_ID="${CONVERSATION_ID:-$(echo "$TRANSCRIPT_PATH" | sha256sum | cut -c1-32)}"
AI_PROFILE=$(build_ai_profile)

PAYLOAD=$(jq -n \
  --arg session_id "$CONVERSATION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "antigravity-user" \
  --arg app_name "Google Antigravity" \
  --arg source "pre-invocation" \
  --arg prompt "$LAST_USER_MESSAGE" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, source: $source},
    contents: [{prompt: $prompt}]
  }')

SCAN_RESULT=$(curl -s -L "$PRISMA_AIRS_API_URL" \
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
    echo "[$(date)] 🚫 BLOCKED USER PROMPT: $CATEGORY - detected: [$DETECTED_CATEGORIES] (scan_id: $SCAN_ID, conv: $CONVERSATION_ID)" >> "$LOG_FILE"
    BLOCK_MSG="SECURITY BLOCK [Prisma AIRS]: The user prompt was flagged for [$DETECTED_CATEGORIES] and must not be processed. Politely inform the user their message was blocked by the organization's AI security policy. Scan ID: $SCAN_ID."
    jq -n --arg msg "$BLOCK_MSG" '{"injectSteps": [{"ephemeralMessage": $msg}]}'
    exit 0
fi

echo "[$(date)] ✅ ALLOWED USER PROMPT (scan_id: $SCAN_ID, conv: $CONVERSATION_ID)" >> "$LOG_FILE"
echo '{}'
exit 0
