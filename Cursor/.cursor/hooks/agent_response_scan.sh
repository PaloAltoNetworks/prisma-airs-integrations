#!/bin/bash

# Prisma AIRS Agent Response Security Scanner Hook for Cursor
# Scans assistant responses AFTER generation to catch sensitive or malicious output
# Output contract: exit 0 = allow (no JSON), exit 2 = block

# Resolve and source shared helper
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prisma-airs.sh
source "$HOOKS_DIR/prisma-airs.sh"

# === FD HARDENING ===
# Save original stdout to FD 3 (kept for compatibility, not used for JSON here)
exec 3>&1
exec 1>>"$LOG_FILE"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Try common response-bearing field names (.text first, then others)
RESPONSE_TEXT=$(printf '%s' "$INPUT_JSON" | jq -r '
  .text
  // .response
  // .message
  // .content
  // .output
  // empty
' 2>/dev/null)

# Nothing to scan — allow silently
if [[ -z "$RESPONSE_TEXT" ]]; then
    exit 0
fi

# Truncate to 2000 chars
TRUNCATED=$(printf '%s' "$RESPONSE_TEXT" | head -c 20000)

log "AGENT-RESPONSE: Scanning assistant response (${#TRUNCATED} chars)"

# Fail-open: warn and allow if credentials missing
if [[ -z "$PRISMA_AIRS_API_KEY" ]] || ! has_profile; then
    log "WARNING: PRISMA_AIRS_API_KEY or profile not set — allowing response without scan"
    exit 0
fi

# Use Cursor's conversation_id to group all scans in one session
TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.conversation_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-cursor-response-$(date +%s)-$$}"

# Call AIRS
SCAN_RESULT=$(airs_scan "$TRUNCATED" "response" "$TR_ID")

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED AGENT RESPONSE: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
        BLOCK_MSG="Blocked by Prisma AIRS: Agent response contained $CATEGORY content (detected: $DETECTIONS)"
    else
        log "BLOCKED AGENT RESPONSE: $CATEGORY (scan_id: $SCAN_ID)"
        BLOCK_MSG="Blocked by Prisma AIRS: Agent response contained $CATEGORY content"
    fi

    echo "" >&2
    echo "$BLOCK_MSG" >&2
    echo "" >&2

    exit 2
fi

# Log allow — no stdout JSON for response hooks
if [[ -n "$DETECTIONS" ]]; then
    log "ALLOWED AGENT RESPONSE: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
else
    log "ALLOWED AGENT RESPONSE: $CATEGORY (scan_id: $SCAN_ID)"
fi

exit 0
