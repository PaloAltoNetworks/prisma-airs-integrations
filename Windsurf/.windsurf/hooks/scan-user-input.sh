#!/bin/bash

# Prisma AIRS User Input Scanner for Windsurf Cascade
# Hook: pre_user_prompt
# Scans user prompts BEFORE they reach Cascade
# Blocks prompts containing malicious content (exit 2)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/prisma-airs.sh"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract user prompt (Windsurf format)
USER_MESSAGE=$(echo "$INPUT_JSON" | jq -r '.tool_info.user_prompt // empty' 2>/dev/null)

# Nothing to scan
if [[ -z "$USER_MESSAGE" ]]; then
    exit 0
fi

# Fail-closed: block if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "ERROR: PRISMA_AIRS_API_KEY not set — blocking prompt (fail-closed)"
    echo "Prisma AIRS: API key not configured — blocking prompt (fail-closed)" >&2
    exit 2
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

# Scan the user prompt
SCAN_RESULT=$(airs_scan "$USER_MESSAGE" "prompt" "user-prompt" "pre_user_prompt" "$SESSION_ID")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED USER INPUT: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
    else
        log "BLOCKED USER INPUT: $CATEGORY (scan_id: $SCAN_ID)"
    fi
    # stderr is shown to the Cascade agent
    echo "Blocked by Prisma AIRS: User input contained $CATEGORY content (detected: $DETECTIONS)" >&2
    exit 2
fi

# Log allowed/warning
if [[ -n "$DETECTIONS" ]]; then
    log "ALLOWED USER INPUT: detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
fi

exit 0
