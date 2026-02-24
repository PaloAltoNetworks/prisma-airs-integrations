#!/bin/bash

# Prisma AIRS User Input Security Scanner Hook for Claude Code
# Scans URLs in user messages BEFORE they reach Claude
# This provides first-line defense against malicious URLs

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/security.log}"
AIRS_BASE_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}"
AIRS_API_URL="${AIRS_BASE_URL%/}/v1/scan/sync/request"
AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME}"

# Create log file if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Check if required environment variables are configured
if [[ -z "$AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY environment variable not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

if [[ -z "$PROFILE_NAME" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME environment variable not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the user prompt from the input
USER_MESSAGE=$(echo "$INPUT_JSON" | jq -r '.prompt // empty' 2>/dev/null)

# If no prompt found, exit (nothing to scan)
if [[ -z "$USER_MESSAGE" ]]; then
    exit 0  # Allow if no prompt found
fi

# Create payload to scan the entire user message
PAYLOAD=$(cat << EOF
{
  "tr_id": "claude-user-input-$(date +%s)-$$",
  "ai_profile": {
    "profile_name": "$PROFILE_NAME"
  },
  "metadata": {
    "app_user": "claude-code-user",
    "app_name": "Claude Code",
    "ai_model": "sonnet",
    "source": "user-prompt-submit"
  },
  "contents": [
    {
      "prompt": $(echo "$USER_MESSAGE" | jq -R .)
    }
  ]
}
EOF
)

# Call Prisma AIRS API to scan the entire user input
SCAN_RESULT=$(curl -s -L "$AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $AIRS_API_KEY" \
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