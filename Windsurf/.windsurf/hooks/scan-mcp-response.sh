#!/bin/bash

# Prisma AIRS MCP Response Scanner for Windsurf Cascade
# Hook: post_mcp_tool_use — audit/alert only (post-hooks cannot block)
# Scans MCP tool responses as tool_event via AIRS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/prisma-airs.sh"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract MCP tool info
MCP_SERVER=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_server_name // "unknown"' 2>/dev/null)
MCP_TOOL=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_tool_name // "unknown"' 2>/dev/null)
MCP_ARGS=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_tool_arguments // {}' 2>/dev/null)
MCP_RESULT=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_result // empty' 2>/dev/null)
TOOL_LABEL="${MCP_SERVER}__${MCP_TOOL}"

log "PostToolUse MCP Hook: Scanning $TOOL_LABEL response"

# Try alternative field names if mcp_result is empty
if [[ -z "$MCP_RESULT" || ${#MCP_RESULT} -lt 5 ]]; then
    for field in "result" "response" "output" "mcp_response" "tool_result" "content"; do
        ALT_RESULT=$(echo "$INPUT_JSON" | jq -r ".tool_info.$field // empty" 2>/dev/null)
        if [[ -n "$ALT_RESULT" && ${#ALT_RESULT} -ge 5 ]]; then
            MCP_RESULT="$ALT_RESULT"
            break
        fi
    done
fi

# Skip if no result content
if [[ -z "$MCP_RESULT" || ${#MCP_RESULT} -lt 5 ]]; then
    log "$TOOL_LABEL: No response content to scan (${#MCP_RESULT} chars)"
    exit 0
fi

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "ERROR: PRISMA_AIRS_API_KEY not set for response scanning"
    exit 0
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

# Serialize tool input/output
TOOL_INPUT=$(echo "$MCP_ARGS" | jq -r 'if type == "string" then . else tostring end' 2>/dev/null || echo "$MCP_ARGS")
TRUNCATED_OUTPUT="$(echo "$MCP_RESULT" | head -c 2000)"

# Single scan as tool_event
log "MCP Response: Scanning $TOOL_LABEL tool_event (input: ${#TOOL_INPUT} chars, output: ${#TRUNCATED_OUTPUT} chars)"
SCAN_RESULT=$(airs_scan_tool_event "$MCP_SERVER" "$MCP_TOOL" "$TOOL_INPUT" "$TRUNCATED_OUTPUT" "$SESSION_ID")

if [[ -z "$SCAN_RESULT" ]]; then
    log "ERROR: Empty response from AIRS for $TOOL_LABEL"
    exit 0
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    log "ALERT $TOOL_LABEL response: $CATEGORY - detected: [$DETECTIONS] [scan:$SCAN_ID]"
    echo "⚠ PRISMA AIRS ALERT: Malicious content detected in MCP response from $TOOL_LABEL ($CATEGORY) [${DETECTIONS}]"
elif [[ -n "$DETECTIONS" ]]; then
    log "ALERT $TOOL_LABEL response: detected: [$DETECTIONS] [scan:$SCAN_ID]"
    echo "⚠ PRISMA AIRS ALERT: Flagged content in MCP response from $TOOL_LABEL [${DETECTIONS}]"
else
    log "ALLOWED $TOOL_LABEL response [scan:$SCAN_ID]"
fi

exit 0
