#!/bin/bash
# Shared Prisma AIRS configuration for Cline hooks

# Resolve paths relative to this script
LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_DIR="$(cd "$LIB_DIR/.." && pwd)"
PROJECT_DIR="$(cd "$HOOKS_DIR/../.." && pwd)"

# Load .env from project root if it exists
if [[ -f "$PROJECT_DIR/.env" ]]; then
    set -a
    source "$PROJECT_DIR/.env"
    set +a
fi

# Prisma AIRS API Configuration
PRISMA_AIRS_API_URL="https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY:-}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
APP_NAME="Cline"

# Logging
LOG_FILE="${LIB_DIR}/prisma-airs.log"
touch "$LOG_FILE"

log() {
    echo "[$(date)] $*" >> "$LOG_FILE"
}

# Generate session ID from taskId or fallback
get_session_id() {
    local input_json="$1"
    local task_id
    task_id=$(echo "$input_json" | jq -r '.taskId // empty' 2>/dev/null)
    if [[ -n "$task_id" ]]; then
        echo "$task_id"
    else
        echo "$PWD" | md5 | cut -c1-32
    fi
}

# Output JSON response to stdout (Cline reads this)
# Usage: respond false                    → allow
#        respond true "error message"     → block
#        respond false "context text"     → allow + inject context
respond() {
    local cancel="${1:-false}"
    local message="${2:-}"

    if [[ "$cancel" == "true" ]]; then
        printf '{"cancel":true,"errorMessage":"%s"}' "$(echo "$message" | sed 's/"/\\"/g')"
    elif [[ -n "$message" ]]; then
        printf '{"cancel":false,"contextModification":"%s"}' "$(echo "$message" | sed 's/"/\\"/g')"
    else
        printf '{"cancel":false}'
    fi
}

# Call AIRS API with a prompt or response payload
# Usage: airs_scan "content" "prompt|response" "source-label" "tool-name" "session-id"
airs_scan() {
    local content="$1"
    local content_type="${2:-prompt}"
    local source_label="$3"
    local tool_name="${4:-unknown}"
    local session_id="${5:-$(echo "$PWD" | md5 | cut -c1-32)}"

    local content_json
    content_json=$(echo "$content" | jq -Rs .)

    local payload
    if [[ "$content_type" == "response" ]]; then
        payload="{
  \"tr_id\": \"$session_id\",
  \"ai_profile\": {\"profile_name\": \"$PRISMA_AIRS_PROFILE_NAME\"},
  \"metadata\": {\"app_user\": \"cline-user\", \"app_name\": \"$APP_NAME\", \"source\": \"$source_label\", \"tool_name\": \"$tool_name\"},
  \"contents\": [{\"response\": $content_json}]
}"
    else
        payload="{
  \"tr_id\": \"$session_id\",
  \"ai_profile\": {\"profile_name\": \"$PRISMA_AIRS_PROFILE_NAME\"},
  \"metadata\": {\"app_user\": \"cline-user\", \"app_name\": \"$APP_NAME\", \"source\": \"$source_label\", \"tool_name\": \"$tool_name\"},
  \"contents\": [{\"prompt\": $content_json}]
}"
    fi

    curl -s -L --max-time 10 --retry 1 "$PRISMA_AIRS_API_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json" \
        -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
        -d "$payload"
}

# Parse all triggered detection categories from an AIRS scan result
parse_detections() {
    local scan_result="$1"
    echo "$scan_result" | jq -r '
      [
        (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
        (.response_detected // {} | to_entries[] | select(.value == true) | .key)
      ] | unique | join(",")
    ' 2>/dev/null
}
