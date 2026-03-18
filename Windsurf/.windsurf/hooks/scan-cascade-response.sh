#!/bin/bash

# Prisma AIRS Cascade Response Scanner for Windsurf
# Hook: post_cascade_response — audit/alert only (post-hooks cannot block)
# Scans the Cascade response as response content via AIRS

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/prisma-airs.sh"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the full Cascade response
RESPONSE=$(echo "$INPUT_JSON" | jq -r '.tool_info.response // empty' 2>/dev/null)

if [[ -z "$RESPONSE" || ${#RESPONSE} -lt 10 ]]; then
    exit 0
fi

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "WARNING: PRISMA_AIRS_API_KEY not set for Cascade response scanning"
    exit 0
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

log "Scanning Cascade response (${#RESPONSE} chars)"

# Single scan as response content
TRUNCATED="$(echo "$RESPONSE" | head -c 2000 | tr '\n' ' ')"
SCAN_RESULT=$(airs_scan "$TRUNCATED" "response" "cascade-response" "cascade" "$SESSION_ID")

if [[ -z "$SCAN_RESULT" ]]; then
    log "ERROR: Empty response from AIRS for Cascade response"
    exit 0
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    log "ALERT Cascade response content: $CATEGORY - detected: [$DETECTIONS] [scan:$SCAN_ID]"
elif [[ -n "$DETECTIONS" ]]; then
    log "ALERT Cascade response: detected: [$DETECTIONS] [scan:$SCAN_ID]"
fi

exit 0
