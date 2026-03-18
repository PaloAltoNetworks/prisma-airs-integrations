#!/bin/bash

LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/security.log}"

# Prisma AIRS API Configuration
PRISMA_AIRS_API_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"

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

# Extract transcript_path for session ID (if available)
TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcript_path // empty' 2>/dev/null)

# Generate session UUID
if [[ -n "$TRANSCRIPT_PATH" ]]; then
    # Extract session ID from transcript path (e.g., /path/to/.claude/sessions/abc-123/transcript.jsonl)
    SESSION_ID=$(echo "$TRANSCRIPT_PATH" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
    # If extraction failed, use path hash as fallback
    if [[ -z "$SESSION_ID" || "$SESSION_ID" == "$TRANSCRIPT_PATH" ]]; then
        SESSION_ID=$(echo "$TRANSCRIPT_PATH" | md5 | cut -c1-32)
    fi
else
    # Fallback: use working directory hash for session correlation
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi

echo "[$(date)] PreToolUse MCP Hook: Scanning $TOOL_NAME request" >> "$LOG_FILE"

# Check if API key is configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] WARNING: PRISMA_AIRS_API_KEY environment variable not set for MCP request scanning" >> "$LOG_FILE"
    exit 0
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

# Create AIRS payload using tool_event for MCP tool scans
MCP_PAYLOAD=$(jq -n \
  --arg tr_id "$SESSION_ID" \
  --arg profile "$PRISMA_AIRS_PROFILE_NAME" \
  --arg app_user "claude-code-user" \
  --arg app_name "$APP_NAME" \
  --arg server_name "$MCP_SERVER" \
  --arg tool_invoked "$TOOL_INVOKED" \
  --arg input "$TOOL_INPUT" \
  '{
    tr_id: $tr_id,
    ai_profile: {profile_name: $profile},
    metadata: {app_user: $app_user, app_name: $app_name},
    contents: [{
      prompt: $input,
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
    
    # Extract ALL detection categories dynamically
    DETECTIONS=""
    DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

    while IFS= read -r category; do
        [[ -z "$category" ]] && continue
        DETECTIONS="${DETECTIONS}$category,"
    done <<< "$DETECTED_CATEGORIES"

    DETECTIONS=$(echo "$DETECTIONS" | sed 's/,$//')

    echo "[$(date)] MCP Request Result: action=$ACTION, category=$CATEGORY" >> "$LOG_FILE"
    
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
    echo "[$(date)] ERROR: Empty response from AIRS for MCP request $TOOL_NAME" >> "$LOG_FILE"
    exit 0
fi

