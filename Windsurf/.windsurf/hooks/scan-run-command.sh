#!/bin/bash

# Prisma AIRS Command Scanner for Windsurf Cascade
# Hook: pre_run_command
# Scans terminal commands before execution
# Blocks commands containing malicious content (exit 2)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/prisma-airs.sh"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the command (Windsurf format)
COMMAND_LINE=$(echo "$INPUT_JSON" | jq -r '.tool_info.command_line // empty' 2>/dev/null)

# Nothing to scan
if [[ -z "$COMMAND_LINE" ]]; then
    exit 0
fi

# Fail-closed: block if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "ERROR: PRISMA_AIRS_API_KEY not set — blocking command (fail-closed)"
    echo "Prisma AIRS: API key not configured — blocking command (fail-closed)" >&2
    exit 2
fi

SESSION_ID=$(get_session_id "$INPUT_JSON")

log "COMMAND: $COMMAND_LINE"

# Scan the command
SCAN_RESULT=$(airs_scan "$COMMAND_LINE" "prompt" "run-command" "pre_run_command" "$SESSION_ID")

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED COMMAND: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
        log "BLOCKED COMMAND TEXT: $COMMAND_LINE"
    else
        log "BLOCKED COMMAND: $CATEGORY (scan_id: $SCAN_ID)"
        log "BLOCKED COMMAND TEXT: $COMMAND_LINE"
    fi
    echo "Blocked by Prisma AIRS: Command blocked due to $CATEGORY content (detected: $DETECTIONS)" >&2
    echo "Command: $COMMAND_LINE" >&2
    exit 2
fi

# Log warnings
if [[ -n "$DETECTIONS" ]]; then
    log "COMMAND WARNING: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
fi

exit 0
