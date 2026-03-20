#!/bin/bash

# Prisma AIRS Prompt Security Scanner Hook for Cursor
# Scans user prompts BEFORE submission to detect prompt injection attacks

# Resolve and source shared helper
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prisma-airs.sh
source "$HOOKS_DIR/prisma-airs.sh"

# === FD HARDENING FOR CLEAN JSON OUTPUT ===
exec 3>&1
exec 1>>"$LOG_FILE"

print_allow() {
    printf '%s\n' '{"continue":true}' >&3
}

print_deny() {
    local message="$1"
    jq -cn --arg message "$message" '{"continue":false,"user_message":$message}' >&3
}

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract prompt field
PROMPT=$(printf '%s' "$INPUT_JSON" | jq -r '.prompt // empty' 2>/dev/null)

# Nothing to scan
if [[ -z "$PROMPT" ]]; then
    print_allow
    exit 0
fi

# Truncate to 2000 chars
TRUNCATED=$(printf '%s' "$PROMPT" | head -c 20000)

log "PRE-PROMPT: Scanning user prompt (${#TRUNCATED} chars)"

# Fail-open: warn and allow if credentials missing
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "WARNING: PRISMA_AIRS_API_KEY not set — allowing prompt without scan"
    print_allow
    exit 0
fi

# Use Cursor's conversation_id to group all scans in one session
TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.conversation_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-cursor-prompt-$(date +%s)-$$}"

# Call AIRS
SCAN_RESULT=$(airs_scan "$TRUNCATED" "prompt" "$TR_ID")

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)
DETECTIONS=$(parse_detections "$SCAN_RESULT")

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "BLOCKED USER PROMPT: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
        BLOCK_MSG="Blocked by Prisma AIRS: Prompt contained $CATEGORY content (detected: $DETECTIONS)"
    else
        log "BLOCKED USER PROMPT: $CATEGORY (scan_id: $SCAN_ID)"
        BLOCK_MSG="Blocked by Prisma AIRS: Prompt contained $CATEGORY content"
    fi

    echo "" >&2
    echo "$BLOCK_MSG" >&2
    echo "This prompt may contain prompt injection, jailbreaking, or malicious instructions." >&2
    echo "" >&2

    print_deny "$BLOCK_MSG"
    exit 2
fi

# Log allow and proceed
if [[ -n "$DETECTIONS" ]]; then
    log "ALLOWED USER PROMPT: $CATEGORY - detected: [$DETECTIONS] (scan_id: $SCAN_ID)"
else
    log "ALLOWED USER PROMPT: $CATEGORY (scan_id: $SCAN_ID)"
fi

print_allow
exit 0
