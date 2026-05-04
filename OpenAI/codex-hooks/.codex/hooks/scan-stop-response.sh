#!/bin/bash

# Prisma AIRS Stop Response Security Scanner Hook for Codex CLI
# Scans the final assistant response when a conversation turn stops
# Hook Event: Stop
# NOTE: Response has already been streamed/displayed — this is detection + audit only

LOG_FILE="${SECURITY_LOG_PATH:-.codex/hooks/prisma-airs.log}"

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
if [[ -n "$CODEX_APP_SUFFIX" ]]; then
    APP_NAME="Codex CLI-${CODEX_APP_SUFFIX}"
else
    APP_NAME="Codex CLI"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Check if API key is configured — Stop hook fails open to avoid disrupting turns
if [[ -z "$PRISMA_AIRS_API_KEY" ]] || ! has_profile; then
    printf '%s' '{"continue": true}'
    exit 0
fi

# Codex Stop provides: session_id, turn_id, stop_hook_active, last_assistant_message
# If this turn was already continued by a Stop hook, don't scan again
STOP_HOOK_ACTIVE=$(echo "$INPUT_JSON" | jq -r '.stop_hook_active // false' 2>/dev/null)
if [[ "$STOP_HOOK_ACTIVE" == "true" ]]; then
    printf '%s' '{"continue": true}'
    exit 0
fi

# Extract the last assistant message (can be null)
LATEST_RESPONSE=$(echo "$INPUT_JSON" | jq -r '.last_assistant_message // empty' 2>/dev/null)

if [[ -z "$LATEST_RESPONSE" ]]; then
    printf '%s' '{"continue": true}'
    exit 0
fi

# Codex provides session_id natively; fall back to cwd hash
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi

TURN_ID=$(echo "$INPUT_JSON" | jq -r '.turn_id // empty' 2>/dev/null)
TOOL_USE_ID=$(echo "$INPUT_JSON" | jq -r '.tool_use_id // empty' 2>/dev/null)
if [[ -n "$TURN_ID" ]]; then
    TRANSACTION_ID="$TURN_ID"
elif [[ -n "$TOOL_USE_ID" ]]; then
    TRANSACTION_ID="$TOOL_USE_ID"
else
    TRANSACTION_ID="$SESSION_ID"
fi

# Extract model from Codex input for AIRS metadata
MODEL=$(echo "$INPUT_JSON" | jq -r '.model // "unknown"' 2>/dev/null)

# Truncate to 20000 chars for scanning
RESPONSE_TO_SCAN="$LATEST_RESPONSE"
if [[ ${#LATEST_RESPONSE} -gt 20000 ]]; then
    RESPONSE_TO_SCAN=$(echo "$LATEST_RESPONSE" | head -c 20000)
    echo "[$(date)] Scanning truncated Codex response (${#LATEST_RESPONSE} chars -> 20000 chars)" >> "$LOG_FILE"
fi

AI_PROFILE_JSON=$(build_ai_profile)

# Scan the assistant response — use both response and code_response for malicious code detection
STOP_PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE_JSON" \
  --arg app_user "codex-cli-user" \
  --arg app_name "$APP_NAME" \
  --arg ai_model "$MODEL" \
  --arg response "$RESPONSE_TO_SCAN" \
  --arg code_response "$RESPONSE_TO_SCAN" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, ai_model: $ai_model},
    contents: [{response: $response, code_response: $code_response}]
  }')

SCAN_RESULT=$(curl -s -L --max-time 10 --retry 1 "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$STOP_PAYLOAD")

# Fail-open on empty response for Stop hook (don't disrupt turns)
if [[ -z "$SCAN_RESULT" ]]; then
    echo "[$(date)] ERROR: Empty response from AIRS API for Stop hook — allowing (fail-open)" >> "$LOG_FILE"
    printf '%s' '{"continue": true}'
    exit 0
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // empty' 2>/dev/null)
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // empty' 2>/dev/null)
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // empty' 2>/dev/null)
REPORT_ID=$(echo "$SCAN_RESULT" | jq -r '.report_id // empty' 2>/dev/null)

# Build ALL detections dynamically — check response_detected first, then prompt_detected
STOP_DETECTIONS=""

DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.response_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    STOP_DETECTIONS="${STOP_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

if [[ -z "$STOP_DETECTIONS" ]]; then
    DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)
    while IFS= read -r category; do
        [[ -z "$category" ]] && continue
        STOP_DETECTIONS="${STOP_DETECTIONS}$category,"
    done <<< "$DETECTED_CATEGORIES"
fi

STOP_DETECTIONS=$(echo "$STOP_DETECTIONS" | sed 's/,$//')

# Extract DLP pattern details if available
DLP_PATTERNS=$(echo "$SCAN_RESULT" | jq -r '
  [.response_masked_data.pattern_detections[]?.pattern, .prompt_masked_data.pattern_detections[]?.pattern]
  | map(select(. != null)) | unique | join(",")
' 2>/dev/null)

if [[ "$ACTION" == "block" && -n "$SCAN_ID" && "$SCAN_ID" != "null" ]]; then
    LOG_ENTRY="[$(date)] BLOCKED Codex response: $CATEGORY"
    [[ -n "$STOP_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$STOP_DETECTIONS]"
    [[ -n "$DLP_PATTERNS" ]] && LOG_ENTRY="$LOG_ENTRY - dlp_patterns: [$DLP_PATTERNS]"
    LOG_ENTRY="$LOG_ENTRY [scan:$SCAN_ID]"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY [report:$REPORT_ID]"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
    # continue:false stops the session after the (already-displayed) response
    printf '%s' "$(jq -n \
      --arg reason "Prisma AIRS blocked response: $CATEGORY content detected" \
      '{
        "continue": false,
        "stopReason": $reason
      }')"
    exit 0
elif [[ "$ACTION" != "allow" && -n "$ACTION" ]]; then
    LOG_ENTRY="[$(date)] Codex response warning: $ACTION/$CATEGORY"
    [[ -n "$STOP_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$STOP_DETECTIONS]"
    LOG_ENTRY="$LOG_ENTRY [scan:$SCAN_ID]"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
else
    LOG_ENTRY="[$(date)] ALLOWED Codex response"
    [[ -n "$STOP_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY: $CATEGORY - detected: [$STOP_DETECTIONS]"
    LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
fi

# Allow the turn to complete normally
printf '%s' '{"continue": true}'
exit 0
