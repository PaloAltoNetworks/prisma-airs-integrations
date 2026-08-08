#!/bin/bash
# Cursor beforeMCPExecution hook
# Scans MCP tool input via Prisma AIRS before execution (tool_event content type).
# Can block the tool call when AIRS flags the input (e.g. prompt injection, malicious params).
#
# Cursor contract:
#   stdin  → JSON { tool_name, tool_input, ... }
#   stdout → JSON { permission: "allow" } or { permission: "deny", user_message, agent_message }
#   exit 0 = allow, exit 2 = deny

# Source shared AIRS helpers (sets PRISMA_AIRS_API_URL, PRISMA_AIRS_API_KEY, PRISMA_AIRS_PROFILE_NAME,
# LOG_FILE, log(), parse_tool_name(), airs_scan_tool_event(), parse_detections())
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prisma-airs.sh
source "$SCRIPT_DIR/prisma-airs.sh"

# === FD HARDENING: redirect stdout to log, keep FD3 for clean JSON output ===
exec 3>&1
exec 1>>"$LOG_FILE"

# --- Output helpers ---

print_allow() {
    printf '%s\n' '{"permission":"allow"}' >&3
}

print_deny() {
    local user_msg="$1"
    local agent_msg="$2"
    jq -cn \
        --arg user_message "$user_msg" \
        --arg agent_message "$agent_msg" \
        '{permission: "deny", user_message: $user_message, agent_message: $agent_message}' >&3
}

# --- Read input ---

INPUT_JSON=$(cat)

# --- Extract tool_name ---

TOOL_NAME=$(printf '%s' "$INPUT_JSON" | jq -r '.tool_name // empty' 2>/dev/null)

if [[ -z "$TOOL_NAME" ]]; then
    log "PRE-MCP: No tool_name in input; allowing through"
    print_allow
    exit 0
fi

# --- Extract tool_input (NOT .parameters — that field is incorrect) ---
# tool_input may be a string or an object; normalize to string for the API

TOOL_INPUT_RAW=$(printf '%s' "$INPUT_JSON" | jq -c '.tool_input // empty' 2>/dev/null)

if [[ -z "$TOOL_INPUT_RAW" || "$TOOL_INPUT_RAW" == "null" ]]; then
    log "PRE-MCP: tool_name=$TOOL_NAME — empty tool_input; allowing through"
    print_allow
    exit 0
fi

# If tool_input is already a JSON string scalar, unwrap it; otherwise re-serialize the object.
TOOL_INPUT_TYPE=$(printf '%s' "$TOOL_INPUT_RAW" | jq -r 'type' 2>/dev/null)

if [[ "$TOOL_INPUT_TYPE" == "string" ]]; then
    TOOL_INPUT_STR=$(printf '%s' "$TOOL_INPUT_RAW" | jq -r '.' 2>/dev/null)
else
    # object, array, number, boolean — serialize to compact JSON string
    TOOL_INPUT_STR=$(printf '%s' "$TOOL_INPUT_RAW" | jq -c '.' 2>/dev/null)
fi

if [[ -z "$TOOL_INPUT_STR" ]]; then
    log "PRE-MCP: tool_name=$TOOL_NAME — could not normalize tool_input; allowing through"
    print_allow
    exit 0
fi

# --- Validate required configuration ---

if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    log "PRE-MCP: ERROR — PRISMA_AIRS_API_KEY is not set; blocking tool=$TOOL_NAME (fail-closed)"
    print_deny "Prisma AIRS: API key not configured — blocking MCP request (fail-closed)" \
               "AIRS security scan could not run: API key not configured. Do not retry."
    exit 2
fi

if ! has_profile; then
    log "PRE-MCP: ERROR — no profile configured; blocking tool=$TOOL_NAME (fail-closed)"
    print_deny "Prisma AIRS: profile not configured — blocking MCP request (fail-closed)" \
               "AIRS security scan could not run: profile not configured. Do not retry."
    exit 2
fi

# --- Parse tool name into server + tool components ---

parse_tool_name "$TOOL_NAME"
# MCP_SERVER and MCP_TOOL are now set

# --- Use Cursor's conversation_id to group all scans in one session ---

TR_ID=$(printf '%s' "$INPUT_JSON" | jq -r '.conversation_id // empty' 2>/dev/null)
TR_ID="${TR_ID:-cursor-mcp-$(date +%s)-$$}"

# --- Scan with AIRS tool_event ---

log "PRE-MCP: Scanning tool=$TOOL_NAME server=$MCP_SERVER tr_id=$TR_ID"

SCAN_RESULT=$(airs_scan_tool_event "$MCP_SERVER" "$MCP_TOOL" "$TOOL_INPUT_STR" "" "$TR_ID")
CURL_EXIT=$?

if [[ $CURL_EXIT -ne 0 ]]; then
    log "PRE-MCP: curl error (exit $CURL_EXIT) scanning tool=$TOOL_NAME; failing open"
    print_allow
    exit 0
fi

# --- Parse verdict ---

ACTION=$(printf '%s' "$SCAN_RESULT" | jq -r '.action // "unknown"' 2>/dev/null)
CATEGORY=$(printf '%s' "$SCAN_RESULT" | jq -r '.category // "unknown"' 2>/dev/null)
SCAN_ID=$(printf '%s' "$SCAN_RESULT" | jq -r '.scan_id // "unknown"' 2>/dev/null)

if [[ -z "$ACTION" || "$ACTION" == "null" ]]; then
    log "PRE-MCP: Empty or unparseable AIRS response for tool=$TOOL_NAME; failing open"
    print_allow
    exit 0
fi

DETECTIONS=$(parse_detections "$SCAN_RESULT")

# --- Enforce ---

if [[ "$ACTION" == "block" ]]; then
    if [[ -n "$DETECTIONS" ]]; then
        log "PRE-MCP: BLOCKED tool=$TOOL_NAME category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
    else
        log "PRE-MCP: BLOCKED tool=$TOOL_NAME category=$CATEGORY scan_id=$SCAN_ID"
    fi

    USER_MSG="Prisma AIRS blocked this MCP tool call.

Tool: $TOOL_NAME
Scan ID: $SCAN_ID
Category: $CATEGORY${DETECTIONS:+
Detections: $DETECTIONS}

The tool input was flagged for potential security issues."

    AGENT_MSG="AIRS security scan blocked the ${TOOL_NAME} tool call (scan_id: ${SCAN_ID}, category: ${CATEGORY}). Do not retry this tool call. Inform the user that the tool input was flagged by security scanning."

    print_deny "$USER_MSG" "$AGENT_MSG"
    exit 2
fi

# --- Allow ---

if [[ -n "$DETECTIONS" ]]; then
    log "PRE-MCP: ALLOWED tool=$TOOL_NAME action=$ACTION category=$CATEGORY detections=[$DETECTIONS] scan_id=$SCAN_ID"
else
    log "PRE-MCP: ALLOWED tool=$TOOL_NAME action=$ACTION scan_id=$SCAN_ID"
fi

print_allow
exit 0
