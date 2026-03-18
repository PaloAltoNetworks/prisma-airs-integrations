#!/bin/bash

# Prisma AIRS MCP Tool Request Scanner for Windsurf Cascade
# Hook: pre_mcp_tool_use
# Scans MCP tool arguments before execution using AIRS tool_event content type
# Blocks requests containing malicious content (exit 2)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/prisma-airs.sh"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract MCP tool info (Windsurf format)
MCP_SERVER=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_server_name // "unknown"' 2>/dev/null)
MCP_TOOL=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_tool_name // "unknown"' 2>/dev/null)
MCP_ARGS=$(echo "$INPUT_JSON" | jq -r '.tool_info.mcp_tool_arguments // {}' 2>/dev/null)
TOOL_LABEL="${MCP_SERVER}__${MCP_TOOL}"

log "PreToolUse MCP Hook: Scanning $TOOL_LABEL request"

# Fail-open if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "WARNING: PRISMA_AIRS_API_KEY not set for MCP request scanning"
    exit 0
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

# Serialize tool input for scanning
TOOL_INPUT=$(echo "$MCP_ARGS" | jq -r 'if type == "string" then . else tostring end' 2>/dev/null || echo "$MCP_ARGS")

# Nothing meaningful to scan
if [[ -z "$TOOL_INPUT" || "$TOOL_INPUT" == "null" || "$TOOL_INPUT" == "{}" ]]; then
    log "MCP Request: No scannable content for $TOOL_LABEL - allowing"
    exit 0
fi

log "MCP Request: Scanning $TOOL_LABEL (${#TOOL_INPUT} chars)"

# Scan using tool_event content type — input only, no output yet
SCAN_RESULT=$(airs_scan_tool_event "$MCP_SERVER" "$MCP_TOOL" "$TOOL_INPUT" "" "$SESSION_ID")

if [[ -z "$SCAN_RESULT" ]]; then
    log "ERROR: Empty response from AIRS for $TOOL_LABEL"
    exit 0
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED MCP REQUEST: $TOOL_LABEL - $CATEGORY - detected: [$DETECTIONS] [scan:$SCAN_ID]"
    else
        log "BLOCKED MCP REQUEST: $TOOL_LABEL - $CATEGORY [scan:$SCAN_ID]"
    fi
    echo "Blocked by Prisma AIRS: MCP request to $TOOL_LABEL blocked due to $CATEGORY content (detected: $DETECTIONS)" >&2
    exit 2
elif [[ "$ACTION" == "allow" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "ALLOWED MCP REQUEST: $TOOL_LABEL - detected: [$DETECTIONS] [scan:$SCAN_ID]"
    else
        log "ALLOWED MCP REQUEST: $TOOL_LABEL [scan:$SCAN_ID]"
    fi
else
    log "WARNING MCP REQUEST: $TOOL_LABEL - inconclusive ($ACTION/$CATEGORY) [scan:$SCAN_ID]"
fi

exit 0
