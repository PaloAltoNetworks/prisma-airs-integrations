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
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking tool use (fail-closed)" >&2
    exit 2
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: profile not configured — blocking tool use (fail-closed)" >&2
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

# Parse the hook input.
#
# Claude Code's PreToolUse hook event carries tool arguments under `.tool_input.*`,
# not at the top level. Reading `.url` (no `.tool_input` prefix) silently returns
# empty, causing the script to exit 0 (allow) without ever calling the AIRS scan
# endpoint - which leaves the tool call effectively unvetted. Field names per tool:
#
#   WebFetch       -> .tool_input.url     (a URL to fetch)
#   WebSearch      -> .tool_input.query   (a search query string, not a URL)
#   Bash           -> .tool_input.command (a shell command; URLs are embedded as
#                                          arguments to curl/wget/etc.)
#   mcp__<server>  -> arbitrary, handled by scan-mcp-request.sh
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')

case "$TOOL_NAME" in
    Bash)
        # Bash commands can contain a URL as an argument to curl, wget, http, etc.
        # Extract the first URL found in the command line. If none, exit allow
        # (other Bash-specific checks belong in a separate hook).
        COMMAND=$(echo "$INPUT_JSON" | jq -r '.tool_input.command // empty')
        URL=$(printf '%s' "$COMMAND" | grep -oE 'https?://[^[:space:]"'"'"';|`<>]+' | head -1)
        ;;
    WebSearch)
        # WebSearch passes a query string, not a URL. Scan the whole query for
        # prompt-injection / malicious-URL signals using AIRS's prompt detectors.
        URL=$(echo "$INPUT_JSON" | jq -r '.tool_input.query // empty')
        ;;
    *)
        # WebFetch and any other URL-carrying tool: read `.tool_input.url`.
        URL=$(echo "$INPUT_JSON" | jq -r '.tool_input.url // .tool_input.URL // empty')
        ;;
esac

# If no URL or scannable content found, exit (nothing to scan)
if [[ -z "$URL" ]]; then
    exit 0  # Allow if nothing to scan
fi

# Use Claude Code session_id as the AIRS transaction_id for session-level tracing.
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi
TRANSACTION_ID="$SESSION_ID"

echo "[$(date)] 🌐 $TOOL_NAME: $URL" >> "$LOG_FILE"

AI_PROFILE=$(build_ai_profile)

# Create JSON payload for URL scanning
PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg tool_name "$TOOL_NAME" \
  --arg source "pre-tool-use" \
  --arg url "$URL" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
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
