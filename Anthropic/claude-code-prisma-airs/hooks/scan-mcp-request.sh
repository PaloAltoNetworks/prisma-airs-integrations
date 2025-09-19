#!/bin/bash

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/security.log}"
AIRS_API_URL="${AIRS_API_URL:-https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request}"
AIRS_API_KEY="${AIRS_API_KEY}"
PROFILE_NAME="${AIRS_PROFILE_NAME}"

# Create log file if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Check if required environment variables are configured
if [[ -z "$AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: AIRS_API_KEY environment variable not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

if [[ -z "$PROFILE_NAME" ]]; then
    echo "[$(date)] ERROR: AIRS_PROFILE_NAME environment variable not set" >> "$LOG_FILE"
    exit 0  # Allow but log error
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract tool information
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
TOOL_INPUT=$(echo "$INPUT_JSON" | jq -r '.tool_input // {}' 2>/dev/null)

# Skip if no tool input to scan
if [[ -z "$TOOL_INPUT" || "$TOOL_INPUT" == "{}" || "$TOOL_INPUT" == "null" ]]; then
    exit 0
fi

# Extract text content from various possible fields in tool input
REQUEST_CONTENT=""
CONTENT_FIELDS=("query" "message" "prompt" "text" "content" "request" "input" "data")

for field in "${CONTENT_FIELDS[@]}"; do
    FIELD_VALUE=$(echo "$TOOL_INPUT" | jq -r ".$field // empty" 2>/dev/null)
    if [[ -n "$FIELD_VALUE" && "$FIELD_VALUE" != "null" ]]; then
        REQUEST_CONTENT="$FIELD_VALUE"
        break
    fi
done

# If no specific field found, try to extract all string values
if [[ -z "$REQUEST_CONTENT" ]]; then
    REQUEST_CONTENT=$(echo "$TOOL_INPUT" | jq -r '.. | strings' 2>/dev/null | head -10 | tr '\n' ' ')
fi

# Skip if no meaningful content to scan
if [[ -z "$REQUEST_CONTENT" || ${#REQUEST_CONTENT} -lt 5 ]]; then
    exit 0
fi

echo "[$(date)] 🔍 Scanning $TOOL_NAME request: ${REQUEST_CONTENT:0:100}..." >> "$LOG_FILE"

# Create payload for scanning MCP request
PAYLOAD=$(cat << EOF
{
  "tr_id": "mcp-request-$(date +%s)-$$",
  "ai_profile": {
    "profile_name": "$PROFILE_NAME"
  },
  "metadata": {
    "app_user": "claude-code-user",
    "app_name": "Claude Code",
    "ai_model": "sonnet",
    "source": "mcp-request",
    "tool_name": "$TOOL_NAME"
  },
  "contents": [
    {
      "prompt": $(echo "$REQUEST_CONTENT" | jq -R .)
    }
  ]
}
EOF
)

# Call Prisma AIRS API
SCAN_RESULT=$(curl -s -L "$AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "x-pan-token: $AIRS_API_KEY" \
  -d "$PAYLOAD")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')

# Extract ALL detection details dynamically
MCP_DETECTIONS=""
DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    MCP_DETECTIONS="${MCP_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

MCP_DETECTIONS=$(echo "$MCP_DETECTIONS" | sed 's/,$//')

# Handle the scan result
if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$MCP_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME request: $CATEGORY - detected: [$MCP_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME request: $CATEGORY [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
    echo "🚫 BLOCKED: MCP request contains malicious content ($CATEGORY)" >&2
    exit 2  # Block the tool execution
elif [[ "$ACTION" != "allow" && "$ACTION" != "unknown" ]]; then
    if [[ -n "$MCP_DETECTIONS" ]]; then
        echo "[$(date)] ⚠️  $TOOL_NAME request warning: $ACTION/$CATEGORY - detected: [$MCP_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] ⚠️  $TOOL_NAME request warning: $ACTION/$CATEGORY [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
else
    if [[ -n "$MCP_DETECTIONS" ]]; then
        echo "[$(date)] ✅ $TOOL_NAME request allowed - detected: [$MCP_DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
    else
        echo "[$(date)] ✅ $TOOL_NAME request allowed [scan:$SCAN_ID]" >> "$LOG_FILE"
    fi
fi

exit 0

