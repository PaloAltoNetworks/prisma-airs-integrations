#!/bin/bash

# Prisma AIRS MCP Response Scanner for Windsurf Cascade
# Hook: post_mcp_tool_use — audit/alert only (post-hooks cannot block)
# Scans MCP tool responses as tool_event via AIRS
# Response content scanning is handled by post_cascade_response hook

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

# Skip if no result content
if [[ -z "$MCP_RESULT" || ${#MCP_RESULT} -lt 5 ]]; then
    log "$TOOL_LABEL: No response content to scan (${#MCP_RESULT} chars)"
    exit 0
fi

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "ERROR: PRISMA_AIRS_API_KEY not set — cannot scan MCP response (fail-closed)"
    echo "PRISMA AIRS ALERT: API key not configured — MCP response not scanned (fail-closed)"
    exit 1
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

# Scan as tool_event (structured input + output with MCP metadata)
TRUNCATED_INPUT="$(echo "$MCP_ARGS" | head -c 20000)"
TRUNCATED_OUTPUT="$(echo "$MCP_RESULT" | head -c 20000 | tr '\n' ' ')"

if [[ ${#TRUNCATED_OUTPUT} -ge 10 ]]; then
    log "PostToolUse: Scanning $TOOL_LABEL as tool_event"
    SCAN_RESULT=$(airs_scan_tool_event "$MCP_SERVER" "$MCP_TOOL" "$TRUNCATED_INPUT" "$TRUNCATED_OUTPUT" "$SESSION_ID")

    if [[ -n "$SCAN_RESULT" ]]; then
        ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
        SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
        CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
        DETECTIONS=$(parse_detections "$SCAN_RESULT")

        if [[ "$ACTION" == "block" ]]; then
            log "ALERT $TOOL_LABEL tool_event: $CATEGORY - detected: [$DETECTIONS] [scan:$SCAN_ID]"
            echo "PRISMA AIRS ALERT: Malicious content in $TOOL_LABEL tool_event ($CATEGORY) [$DETECTIONS]"
        elif [[ -n "$DETECTIONS" ]]; then
            log "ALERT $TOOL_LABEL tool_event: detected: [$DETECTIONS] [scan:$SCAN_ID]"
        else
            log "ALLOWED $TOOL_LABEL tool_event [scan:$SCAN_ID]"
        fi
    fi
fi

exit 0
