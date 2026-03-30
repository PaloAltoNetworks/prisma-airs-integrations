#!/bin/bash

# Prisma AIRS User Input Security Scanner Hook for Claude Code
# Scans URLs in user messages BEFORE they reach Claude
# This provides first-line defense against malicious URLs

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/prisma-airs.log}"
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
if [[ -n "$CLAUDE_CODE_APP_SUFFIX" ]]; then
    APP_NAME="Claude Code-${CLAUDE_CODE_APP_SUFFIX}"
else
    APP_NAME="Claude Code"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the user prompt from the input
USER_MESSAGE=$(echo "$INPUT_JSON" | jq -r '.prompt // empty' 2>/dev/null)

# If no prompt found, exit (nothing to scan)
if [[ -z "$USER_MESSAGE" ]]; then
    exit 0  # Allow if no prompt found
fi

# Extract transcript_path for session ID (if available)
TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcript_path // empty' 2>/dev/null)

# Generate session UUID
if [[ -n "$TRANSCRIPT_PATH" ]]; then
    SESSION_ID=$(echo "$TRANSCRIPT_PATH" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
    if [[ -z "$SESSION_ID" || "$SESSION_ID" == "$TRANSCRIPT_PATH" ]]; then
        SESSION_ID=$(echo "$TRANSCRIPT_PATH" | md5 | cut -c1-32)
    fi
else
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi

AI_PROFILE=$(build_ai_profile)

# Create payload to scan the entire user message
PAYLOAD=$(jq -n \
  --arg tr_id "$SESSION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg source "user-prompt-submit" \
  --arg prompt "$USER_MESSAGE" \
  '{
    tr_id: $tr_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, source: $source},
    contents: [{prompt: $prompt}]
  }')

# Call Prisma AIRS API to scan the entire user input
SCAN_RESULT=$(curl -s -L "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')

# Parse ALL detection flags that were triggered
PROMPT_DETECTIONS=""
DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    PROMPT_DETECTIONS="${PROMPT_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

PROMPT_DETECTIONS=$(echo "$PROMPT_DETECTIONS" | sed 's/,$//')

# Check if user input should be blocked
if [[ "$ACTION" == "block" ]]; then
    echo "🚫 BLOCKED: Malicious content detected in user input ($CATEGORY)" >&2
    if [[ -n "$PROMPT_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED USER INPUT: $CATEGORY - detected: [$PROMPT_DETECTIONS] (scan_id: $SCAN_ID)" >> "$LOG_FILE"
    else
        echo "[$(date)] 🚫 BLOCKED USER INPUT: $CATEGORY (scan_id: $SCAN_ID)" >> "$LOG_FILE"
    fi
    exit 2  # Block the prompt
fi

# Allow the prompt to proceed
exit 0