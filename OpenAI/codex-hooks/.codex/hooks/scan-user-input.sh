#!/bin/bash

# Prisma AIRS User Input Security Scanner Hook for Codex CLI
# Scans user messages BEFORE they reach Codex
# This provides first-line defense against prompt injection and malicious content

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.codex/hooks/prisma-airs.log}"
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

# Create log file if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Check if required environment variables are configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking prompt (fail-closed)" >&2
    exit 2
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: profile not configured — blocking prompt (fail-closed)" >&2
    exit 2
fi

# Set app name with optional custom suffix
if [[ -n "$CODEX_APP_SUFFIX" ]]; then
    APP_NAME="Codex CLI-${CODEX_APP_SUFFIX}"
else
    APP_NAME="Codex CLI"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the user prompt from the input
USER_MESSAGE=$(echo "$INPUT_JSON" | jq -r '.prompt // empty' 2>/dev/null)

# If no prompt found, exit (nothing to scan)
if [[ -z "$USER_MESSAGE" ]]; then
    exit 0  # Allow if no prompt found
fi

# Codex provides session_id natively; fall back to transcript_path or cwd hash
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcript_path // empty' 2>/dev/null)
    if [[ -n "$TRANSCRIPT_PATH" ]]; then
        SESSION_ID=$(echo "$TRANSCRIPT_PATH" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
        if [[ -z "$SESSION_ID" || "$SESSION_ID" == "$TRANSCRIPT_PATH" ]]; then
            SESSION_ID=$(echo "$TRANSCRIPT_PATH" | md5 | cut -c1-32)
        fi
    else
        SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
    fi
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

AI_PROFILE=$(build_ai_profile)

# Create payload — session_id groups the conversation; transaction_id identifies this turn.
PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "codex-cli-user" \
  --arg app_name "$APP_NAME" \
  --arg ai_model "$MODEL" \
  --arg source "user-prompt-submit" \
  --arg prompt "$USER_MESSAGE" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, ai_model: $ai_model},
    contents: [{prompt: $prompt}]
  }')

# Call Prisma AIRS API
SCAN_RESULT=$(curl -s -L --max-time 10 --retry 1 "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

# Fail-closed on empty response (network error, timeout, etc.)
if [[ -z "$SCAN_RESULT" ]]; then
    echo "[$(date)] ERROR: Empty response from AIRS API — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: empty API response — blocking prompt (fail-closed)" >&2
    exit 2
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
REPORT_ID=$(echo "$SCAN_RESULT" | jq -r '.report_id // empty')

# Parse ALL detection flags that were triggered
PROMPT_DETECTIONS=""
DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    PROMPT_DETECTIONS="${PROMPT_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

PROMPT_DETECTIONS=$(echo "$PROMPT_DETECTIONS" | sed 's/,$//')

# Extract DLP pattern details if available
DLP_PATTERNS=$(echo "$SCAN_RESULT" | jq -r '.prompt_masked_data.pattern_detections[]?.pattern' 2>/dev/null | paste -sd, -)

# Check if user input should be blocked
if [[ "$ACTION" == "block" ]]; then
    echo "BLOCKED: Malicious content detected in user input ($CATEGORY)" >&2
    LOG_ENTRY="[$(date)] BLOCKED USER INPUT: $CATEGORY"
    [[ -n "$PROMPT_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$PROMPT_DETECTIONS]"
    [[ -n "$DLP_PATTERNS" ]] && LOG_ENTRY="$LOG_ENTRY - dlp_patterns: [$DLP_PATTERNS]"
    LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY (report_id: $REPORT_ID)"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
    exit 2  # Block the prompt
fi

if [[ "$ACTION" != "allow" ]]; then
    LOG_ENTRY="[$(date)] ERROR: Unexpected AIRS action for user input: $ACTION/$CATEGORY — blocking (fail-closed)"
    LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY (report_id: $REPORT_ID)"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
    echo "Prisma AIRS: unexpected API response — blocking prompt (fail-closed)" >&2
    exit 2
fi

# Log allowed prompt and proceed
LOG_ENTRY="[$(date)] ALLOWED USER INPUT"
[[ -n "$PROMPT_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY: $CATEGORY - detected: [$PROMPT_DETECTIONS]"
LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
echo "$LOG_ENTRY" >> "$LOG_FILE"
exit 0
