#!/bin/bash

# Prisma AIRS URL Security Scanner Hook for Claude Code
# Receives JSON input via stdin from Claude Code hooks

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
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY environment variable not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

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
URL=$(echo "$INPUT_JSON" | jq -r '.url // empty')

# If no URL found, exit (nothing to scan)
if [[ -z "$URL" ]]; then
    exit 0  # Allow if no URL found
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

echo "[$(date)] 🌐 $TOOL_NAME: $URL" >> "$LOG_FILE"

AI_PROFILE=$(build_ai_profile)

# Create JSON payload for URL scanning
PAYLOAD=$(jq -n \
  --arg tr_id "$SESSION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg tool_name "$TOOL_NAME" \
  --arg source "pre-tool-use" \
  --arg url "$URL" \
  '{
    tr_id: $tr_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, tool_name: $tool_name, source: $source},
    contents: [{prompt: $url}]
  }')

# Call Prisma AIRS API
SCAN_RESULT=$(curl -s -L "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')

# Extract ALL detection details dynamically
URL_DETECTIONS=""
DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    URL_DETECTIONS="${URL_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

URL_DETECTIONS=$(echo "$URL_DETECTIONS" | sed 's/,$//')

# Handle the scan result
if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$URL_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED: $URL ($CATEGORY) - detected: [$URL_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] 🚫 BLOCKED: $URL ($CATEGORY) [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
    echo "🚫 BLOCKED: URL contains malicious content ($CATEGORY)" >&2
    exit 2  # Block the tool execution
elif [[ "$ACTION" != "allow" && "$ACTION" != "unknown" ]]; then
    if [[ -n "$URL_DETECTIONS" ]]; then
        echo "[$(date)] ⚠️  WARNING: $URL - $ACTION/$CATEGORY - detected: [$URL_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] ⚠️  WARNING: $URL - $ACTION/$CATEGORY [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
else
    if [[ -n "$URL_DETECTIONS" ]]; then
        echo "[$(date)] ✅ ALLOWED: $URL - detected: [$URL_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] ✅ ALLOWED: $URL [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
fi

exit 0