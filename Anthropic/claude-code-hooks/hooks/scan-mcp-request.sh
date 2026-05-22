#!/bin/bash

LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/prisma-airs.log}"

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
if [[ -n "$CLAUDE_CODE_APP_SUFFIX" ]]; then
    APP_NAME="Claude Code-${CLAUDE_CODE_APP_SUFFIX}"
else
    APP_NAME="Claude Code"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract tool information
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
TOOL_INPUT=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}' 2>/dev/null)

# Extract MCP server and tool from pattern: mcp__<server>__<tool>
MCP_SERVER=$(echo "$TOOL_NAME" | awk -F'__' '{print $2}')
TOOL_INVOKED=$(echo "$TOOL_NAME" | awk -F'__' '{print $3}')

# Use Claude Code session_id as the AIRS transaction_id for session-level tracing.
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi
TRANSACTION_ID="$SESSION_ID"

echo "[$(date)] PreToolUse MCP Hook: Scanning $TOOL_NAME request" >> "$LOG_FILE"

# Check if API key is configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking MCP request (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking MCP request (fail-closed)" >&2
    exit 2
fi

# Extract the actual request content to scan
MCP_REQUEST=""

# Handle different MCP tool input formats
if [[ "$TOOL_INPUT" != "null" && "$TOOL_INPUT" != "{}" ]]; then
    # Try to extract common fields that might contain user content
    QUERY=$(echo "$TOOL_INPUT" | jq -r '.query // .prompt // .message // .content // empty' 2>/dev/null)
    PATH_PARAM=$(echo "$TOOL_INPUT" | jq -r '.path // .file // .resource // empty' 2>/dev/null)
    
    if [[ -n "$QUERY" && "$QUERY" != "null" ]]; then
        MCP_REQUEST="$QUERY"
    elif [[ -n "$PATH_PARAM" && "$PATH_PARAM" != "null" ]]; then
        MCP_REQUEST="Accessing resource: $PATH_PARAM"
    else
        # Fallback: scan the entire tool_input as text
        MCP_REQUEST=$(echo "$TOOL_INPUT" | jq -r '. | tostring' 2>/dev/null || echo "$TOOL_INPUT")
    fi
fi

# If no meaningful content found, log and allow
if [[ -z "$MCP_REQUEST" || "$MCP_REQUEST" == "null" ]]; then
    echo "[$(date)] MCP Request: No scannable content found for $TOOL_NAME - allowing" >> "$LOG_FILE"
    exit 0
fi

echo "[$(date)] MCP Request: Scanning '$MCP_REQUEST' for $TOOL_NAME (${#MCP_REQUEST} chars)" >> "$LOG_FILE"

AI_PROFILE_JSON=$(build_ai_profile)
if [[ -z "$AI_PROFILE_JSON" ]]; then
    AI_PROFILE_JSON="{}"
fi

# Create AIRS payload using tool_event for MCP tool scans
MCP_PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE_JSON" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg server_name "$MCP_SERVER" \
  --arg tool_invoked "$TOOL_INVOKED" \
  --arg input "$TOOL_INPUT" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name},
    contents: [{
      tool_event: {
        metadata: {
          ecosystem: "mcp",
          method: "tools/call",
          server_name: $server_name,
          tool_invoked: $tool_invoked
        },
        input: $input
      }
    }]
  }')

# Call Prisma AIRS API
SCAN_RESULT=$(curl -s -L "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$MCP_PAYLOAD")

# Parse AIRS response
if [[ -n "$SCAN_RESULT" ]]; then
    ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // empty' 2>/dev/null)
    CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // empty' 2>/dev/null)
    SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
    TOOL_VERDICT=$(echo "$SCAN_RESULT" | jq -r '.tool_detected.verdict // empty' 2>/dev/null)
    
    # Extract ALL detection categories dynamically
    DETECTIONS=""
    DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '
      [
        (.tool_detected.summary.detections // {} | to_entries[]? | select(.value == true) | .key),
        (.tool_detected.input_detected.detection_entries // [] | .[] | (.detections // {}) | to_entries[]? | select(.value == true) | .key),
        (.prompt_detected // {} | to_entries[]? | select(.value == true) | .key)
      ] | unique | .[]
    ' 2>/dev/null)

    while IFS= read -r category; do
        [[ -z "$category" ]] && continue
        DETECTIONS="${DETECTIONS}$category,"
    done <<< "$DETECTED_CATEGORIES"

    DETECTIONS=$(echo "$DETECTIONS" | sed 's/,$//')

    echo "[$(date)] MCP Request Result: action=$ACTION, category=$CATEGORY, tool_verdict=${TOOL_VERDICT:-unknown}" >> "$LOG_FILE"
    
    # Decision logic
    if [[ "$ACTION" == "block" ]]; then
        if [[ -n "$DETECTIONS" ]]; then
            echo "[$(date)] 🚫 BLOCKED MCP REQUEST: $TOOL_NAME - $CATEGORY - detected: [$DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
        else
            echo "[$(date)] 🚫 BLOCKED MCP REQUEST: $TOOL_NAME - $CATEGORY content detected [scan:$SCAN_ID]" >> "$LOG_FILE"
        fi
        echo "🚫 Blocked: MCP request blocked due to $CATEGORY content detection" >&2
        exit 2
    elif [[ "$ACTION" == "allow" ]]; then
        if [[ -n "$DETECTIONS" ]]; then
            echo "[$(date)] ✅ ALLOWED MCP REQUEST: $TOOL_NAME ($CATEGORY) - detected: [$DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
        else
            echo "[$(date)] ✅ ALLOWED MCP REQUEST: $TOOL_NAME ($CATEGORY) [scan:$SCAN_ID]" >> "$LOG_FILE"
        fi
        exit 0
    else
        # Inconclusive scan - log warning but allow
        if [[ -n "$DETECTIONS" ]]; then
            echo "[$(date)] ⚠️  WARNING MCP REQUEST: $TOOL_NAME - Scan inconclusive (action=$ACTION, category=$CATEGORY) - detected: [$DETECTIONS] [scan:$SCAN_ID]" >> "$LOG_FILE"
        else
            echo "[$(date)] ⚠️  WARNING MCP REQUEST: $TOOL_NAME - Scan inconclusive (action=$ACTION, category=$CATEGORY) [scan:$SCAN_ID]" >> "$LOG_FILE"
        fi
        exit 0
    fi
else
    echo "[$(date)] ERROR: Empty response from AIRS for MCP request $TOOL_NAME — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: empty API response — blocking MCP request (fail-closed)" >&2
    exit 2
fi
