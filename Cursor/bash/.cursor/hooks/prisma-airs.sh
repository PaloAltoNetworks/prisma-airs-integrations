#!/bin/bash
# Shared Prisma AIRS configuration for Cursor IDE hooks

# Resolve paths relative to this script
HOOKS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$HOOKS_DIR/../.." && pwd)"

# Load .env from project root if it exists
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Prisma AIRS API Configuration
PRISMA_AIRS_API_URL="${PRISMA_AIRS_API_URL:-https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request}"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY:-}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
PRISMA_AIRS_PROFILE_ID="${PRISMA_AIRS_PROFILE_ID:-}"
TIMEOUT_SECONDS=3

# Build ai_profile JSON: prefer profile_id over profile_name
build_ai_profile() {
    if [[ -n "$PRISMA_AIRS_PROFILE_ID" ]]; then
        echo "{\"profile_id\": \"$PRISMA_AIRS_PROFILE_ID\"}"
    elif [[ -n "$PRISMA_AIRS_PROFILE_NAME" ]]; then
        echo "{\"profile_name\": \"$PRISMA_AIRS_PROFILE_NAME\"}"
    else
        echo ""
    fi
}

has_profile() {
    [[ -n "$PRISMA_AIRS_PROFILE_ID" || -n "$PRISMA_AIRS_PROFILE_NAME" ]]
}
APP_NAME="cursor-hooks"

# Logging
LOG_FILE="${HOOKS_DIR}/prisma-airs.log"
mkdir -p "$HOOKS_DIR"
touch "$LOG_FILE"

log() {
    echo "[$(date)] $*" >> "$LOG_FILE"
}

# Parse Cursor tool_name into server and tool components
# MCP:<server>:<tool...> → MCP_SERVER=<server>, MCP_TOOL=<tool...>
# non-MCP → MCP_SERVER=cursor, MCP_TOOL=<raw>
parse_tool_name() {
    local raw="$1"
    if [[ "$raw" == MCP:* ]]; then
        local without_prefix="${raw#MCP:}"
        MCP_SERVER="${without_prefix%%:*}"
        MCP_TOOL="${without_prefix}"
    else
        MCP_SERVER="cursor"
        MCP_TOOL="$raw"
    fi
}

# Call AIRS API with a prompt or response payload
# Usage: airs_scan "content" "prompt|response" "session-id"
airs_scan() {
    local content="$1"
    local content_type="${2:-prompt}"
    local session_id="${3:-cursor-$(date +%s)-$$}"

    local content_json
    content_json=$(printf '%s' "$content" | jq -Rs .)

    local ai_profile_json
    ai_profile_json=$(build_ai_profile)

    local payload
    payload=$(jq -n \
        --arg tr_id "$session_id" \
        --argjson ai_profile "$ai_profile_json" \
        --arg app_name "$APP_NAME" \
        --argjson content "$content_json" \
        --arg content_type "$content_type" \
        'if $content_type == "response" then
  {
    tr_id: $tr_id,
    ai_profile: $ai_profile,
    metadata: { app_user: "cursor-user", app_name: $app_name },
    contents: [{ response: $content }]
  }
else
  {
    tr_id: $tr_id,
    ai_profile: $ai_profile,
    metadata: { app_user: "cursor-user", app_name: $app_name },
    contents: [{ prompt: $content }]
  }
end')

    timeout "${TIMEOUT_SECONDS}s" curl -s -L \
        --max-time "$TIMEOUT_SECONDS" \
        --connect-timeout 1 \
        "$PRISMA_AIRS_API_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
        -d "$payload"
}

# Call AIRS API with a tool_event payload (tool interactions)
# Usage: airs_scan_tool_event "server" "tool" "input" "output" "session-id"
airs_scan_tool_event() {
    local server_name="${1:-unknown}"
    local tool_invoked="${2:-unknown}"
    local tool_input="$3"
    local tool_output="$4"
    local session_id="${5:-cursor-$(date +%s)-$$}"

    local input_json output_json
    input_json=$(printf '%s' "$tool_input" | jq -Rs .)
    output_json=$(printf '%s' "$tool_output" | jq -Rs .)

    local ai_profile_json
    ai_profile_json=$(build_ai_profile)

    local payload
    payload=$(jq -n \
        --arg tr_id "$session_id" \
        --argjson ai_profile "$ai_profile_json" \
        --arg app_name "$APP_NAME" \
        --arg server "$server_name" \
        --arg tool "$tool_invoked" \
        --argjson input "$input_json" \
        --argjson output "$output_json" \
        '{
  tr_id: $tr_id,
  ai_profile: $ai_profile,
  metadata: { app_user: "cursor-user", app_name: $app_name },
  contents: [{
    tool_event: {
      metadata: {
        ecosystem: "mcp",
        method: "tools/call",
        server_name: $server,
        tool_invoked: $tool
      },
      input: $input,
      output: $output
    }
  }]
}')

    timeout "${TIMEOUT_SECONDS}s" curl -s -L \
        --max-time "$TIMEOUT_SECONDS" \
        --connect-timeout 1 \
        "$PRISMA_AIRS_API_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
        -d "$payload"
}

# Parse all triggered detection categories from an AIRS scan result
# Returns comma-separated list
parse_detections() {
    local scan_result="$1"
    echo "$scan_result" | jq -r '
      [
        (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
        (.response_detected // {} | to_entries[] | select(.value == true) | .key)
      ] | unique | join(",")
    ' 2>/dev/null
}
