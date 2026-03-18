#!/bin/bash
# Cursor postToolUse hook — Prisma AIRS scanner
#
# Scans MCP and Shell tool outputs. Skips Cursor built-ins (Grep, Read, Write, etc.)
# which operate on local files and don't introduce external content.
#
#   MCP tools  → scan as tool_event (structured input + output)
#   Shell      → scan as response   (command output is external content)
#   Built-ins  → skip (Grep, Read, Write, Delete, Task — local operations)
#
# Cursor contract:
#   stdin  → JSON { tool_name, tool_input, tool_output, tool_use_id, cwd, ... }
#   stdout → JSON {} (allow) or { "updated_mcp_tool_output": "..." } (block)
#   NEVER emit: permission, additional_context
#   NEVER exit 2

set -o pipefail

# === SOURCE SHARED HELPERS ===
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${HOOKS_DIR}/prisma-airs.sh"

# === READ STDIN FIRST (before any redirects) ===
INPUT_JSON=$(cat)

# === FD3 HARDENING: redirect stdout to log, keep FD3 for hook output ===
exec 3>&1
exec 1>>"$LOG_FILE"
exec 2>>"$LOG_FILE"

allow() {
    printf '%s\n' '{}' >&3
}

block() {
    local message="$1"
    jq -cn --arg msg "$message" '{"updated_mcp_tool_output": $msg}' >&3
}

# === PARSE STDIN ===
if ! echo "$INPUT_JSON" | jq -e . > /dev/null 2>&1; then
    log "SCAN-RESPONSE: Failed to parse stdin JSON, passing through"
    allow
    exit 0
fi

TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')

# === SKIP CURSOR BUILT-INS: local operations, no external content ===
case "$TOOL_NAME" in
    Grep|Read|Write|Delete|Task|Glob|Edit|NotebookEdit)
        log "SCAN-RESPONSE: Skipping built-in tool=$TOOL_NAME"
        allow
        exit 0
        ;;
esac

TOOL_INPUT_RAW=$(echo "$INPUT_JSON" | jq -c '.tool_input // ""')
TOOL_OUTPUT_RAW=$(echo "$INPUT_JSON" | jq -c '.tool_output // ""')

# Normalize tool_input to string
if echo "$TOOL_INPUT_RAW" | jq -e 'type == "string"' > /dev/null 2>&1; then
    TOOL_INPUT=$(echo "$TOOL_INPUT_RAW" | jq -r '.')
else
    TOOL_INPUT=$(echo "$TOOL_INPUT_RAW" | jq -c '.')
fi

# Normalize tool_output to string
if echo "$TOOL_OUTPUT_RAW" | jq -e 'type == "string"' > /dev/null 2>&1; then
    TOOL_OUTPUT=$(echo "$TOOL_OUTPUT_RAW" | jq -r '.')
else
    TOOL_OUTPUT=$(echo "$TOOL_OUTPUT_RAW" | jq -c '.')
fi

log "SCAN-RESPONSE: tool=$TOOL_NAME output_size=${#TOOL_OUTPUT}"

# === GUARDRAIL: empty output ===
if [[ -z "${TOOL_OUTPUT// /}" ]]; then
    log "SCAN-RESPONSE: tool_output is empty, skipping scan"
    allow
    exit 0
fi

# === GUARDRAIL: output size limit (50KB) ===
if [[ ${#TOOL_OUTPUT} -gt 51200 ]]; then
    log "SCAN-RESPONSE: tool_output too large (${#TOOL_OUTPUT} bytes), skipping scan"
    allow
    exit 0
fi

# === GUARDRAIL: API key and profile ===
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "SCAN-RESPONSE: WARNING: PRISMA_AIRS_API_KEY not set, skipping scan"
    allow
    exit 0
fi

if [[ -z "$RESPONSE_PROFILE" ]]; then
    log "SCAN-RESPONSE: WARNING: RESPONSE_PROFILE not set, skipping scan"
    allow
    exit 0
fi

# === PARSE TOOL NAME ===
parse_tool_name "$TOOL_NAME"
# Sets MCP_SERVER and MCP_TOOL

# === EXTRACT AND LOG URLS (audit trail) ===
URLS=$(printf '%s' "$TOOL_OUTPUT" | jq -Rs 'scan("https?://[^\\s<>\"'\'']+") | select(length > 0)' 2>/dev/null \
    | jq -rs 'unique[]' 2>/dev/null || true)
if [[ -n "$URLS" ]]; then
    URL_COUNT=$(printf '%s\n' "$URLS" | wc -l | tr -d ' ')
    URL_PREVIEW=$(printf '%s\n' "$URLS" | head -3 | tr '\n' ' ')
    log "SCAN-RESPONSE: Found ${URL_COUNT} URL(s): ${URL_PREVIEW}"
fi

# === TRUNCATE CONTENT TO 2000 CHARS BEFORE SCANNING ===
TRUNCATED_OUTPUT=$(printf '%s' "$TOOL_OUTPUT" | head -c 2000)
TRUNCATED_INPUT=$(printf '%s' "$TOOL_INPUT" | head -c 2000)

# === SESSION ID: use Cursor's conversation_id to group all scans in one session ===
TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.conversation_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-cursor-posttool-$(date +%s)-$$}"

# === SCAN WITH AIRS ===
# MCP tools → tool_event (structured input + output with server/tool metadata)
# Shell      → response  (plain text output from command execution)
if [[ "$TOOL_NAME" == MCP:* ]]; then
    log "SCAN-RESPONSE: Scanning MCP tool=$TOOL_NAME server=$MCP_SERVER as tool_event"
    SCAN_RESULT=$(airs_scan_tool_event \
        "$MCP_SERVER" \
        "$MCP_TOOL" \
        "$TRUNCATED_INPUT" \
        "$TRUNCATED_OUTPUT" \
        "$TR_ID" \
        "$RESPONSE_PROFILE")
else
    log "SCAN-RESPONSE: Scanning tool=$TOOL_NAME as response"
    SCAN_RESULT=$(airs_scan \
        "$TRUNCATED_OUTPUT" \
        "response" \
        "$RESPONSE_PROFILE" \
        "$TR_ID")
fi

CURL_EXIT=$?

# === FAIL-OPEN on curl error ===
if [[ $CURL_EXIT -ne 0 ]]; then
    log "SCAN-RESPONSE: WARNING: curl failed (exit: $CURL_EXIT), allowing by default"
    allow
    exit 0
fi

# === PARSE SCAN RESULT ===
ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)

# Fail-open on bad API response
if [[ -z "$ACTION" || "$ACTION" == "unknown" || "$ACTION" == "null" ]]; then
    log "SCAN-RESPONSE: WARNING: AIRS returned invalid/no action, allowing by default (raw: ${SCAN_RESULT:0:200})"
    allow
    exit 0
fi

DETECTIONS=$(parse_detections "$SCAN_RESULT")

# === HANDLE VERDICT ===
if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "SCAN-RESPONSE: BLOCKED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
        BLOCK_MSG="BLOCKED by Prisma AIRS: ${CATEGORY} (detected: ${DETECTIONS}) [scan:${SCAN_ID}]"
    else
        log "SCAN-RESPONSE: BLOCKED tool=$TOOL_NAME category=$CATEGORY scan_id=$SCAN_ID"
        BLOCK_MSG="BLOCKED by Prisma AIRS: ${CATEGORY} [scan:${SCAN_ID}]"
    fi
    block "$BLOCK_MSG"
    exit 0
elif [[ "$ACTION" == "allow" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "SCAN-RESPONSE: ALLOWED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
    else
        log "SCAN-RESPONSE: ALLOWED tool=$TOOL_NAME scan_id=$SCAN_ID"
    fi
else
    log "SCAN-RESPONSE: WARNING tool=$TOOL_NAME action=$ACTION category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
fi

allow
exit 0
