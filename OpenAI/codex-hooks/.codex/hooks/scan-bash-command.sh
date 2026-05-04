#!/bin/bash

# Prisma AIRS Bash Command Security Scanner Hook for Codex CLI
# Scans bash commands BEFORE they are executed
# Hook Event: PreToolUse (matcher: Bash)

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.codex/hooks/prisma-airs.log}"
PRISMA_AIRS_API_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"
PRISMA_AIRS_PROFILE_ID="${PRISMA_AIRS_PROFILE_ID:-}"

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

# Create log file if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Check if required environment variables are configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking bash command (fail-closed)" >&2
    exit 2
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: profile not configured — blocking bash command (fail-closed)" >&2
    exit 2
fi

# Set app name with optional custom suffix
if [[ -n "$CODEX_APP_SUFFIX" ]]; then
    APP_NAME="Codex CLI-${CODEX_APP_SUFFIX}"
else
    APP_NAME="Codex CLI"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Extract the bash command from the input
# Codex PreToolUse provides: session_id, turn_id, tool_name, tool_use_id, tool_input.command
BASH_COMMAND=$(echo "$INPUT_JSON" | jq -r '.tool_input.command // empty' 2>/dev/null)

# If no command found, exit (nothing to scan)
if [[ -z "$BASH_COMMAND" ]]; then
    exit 0  # Allow if no command found
fi

# Codex provides session_id natively; fall back to transcript_path or cwd hash
SESSION_ID=$(echo "$INPUT_JSON" | jq -r '.session_id // empty' 2>/dev/null)
if [[ -z "$SESSION_ID" ]]; then
    TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcript_path // empty' 2>/dev/null)
    if [[ -n "$TRANSCRIPT_PATH" ]]; then
        SESSION_ID=$(echo "$TRANSCRIPT_PATH" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
        if [[ -z "$SESSION_ID" || "$SESSION_ID" == "$TRANSCRIPT_PATH" ]]; then
            SESSION_ID=$(echo "$TRANSCRIPT_PATH" | md5 | cut -c1-32)
        fi
    else
        SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
    fi
fi

TURN_ID=$(echo "$INPUT_JSON" | jq -r '.turn_id // empty' 2>/dev/null)
TOOL_USE_ID=$(echo "$INPUT_JSON" | jq -r '.tool_use_id // empty' 2>/dev/null)
if [[ -n "$TURN_ID" && -n "$TOOL_USE_ID" ]]; then
    TRANSACTION_ID="${TURN_ID}:${TOOL_USE_ID}"
elif [[ -n "$TOOL_USE_ID" ]]; then
    TRANSACTION_ID="$TOOL_USE_ID"
elif [[ -n "$TURN_ID" ]]; then
    TRANSACTION_ID="$TURN_ID"
else
    TRANSACTION_ID="$SESSION_ID"
fi

# Extract model from Codex input for AIRS metadata
MODEL=$(echo "$INPUT_JSON" | jq -r '.model // "unknown"' 2>/dev/null)

echo "[$(date)] BASH COMMAND: $BASH_COMMAND" >> "$LOG_FILE"

AI_PROFILE=$(build_ai_profile)

# Create payload — send as prompt for text analysis + code_prompt for malicious code detection
PAYLOAD=$(jq -n \
  --arg session_id "$SESSION_ID" \
  --arg transaction_id "$TRANSACTION_ID" \
  --argjson ai_profile "$AI_PROFILE" \
  --arg app_user "codex-cli-user" \
  --arg app_name "$APP_NAME" \
  --arg ai_model "$MODEL" \
  --arg prompt "$BASH_COMMAND" \
  --arg code_prompt "$BASH_COMMAND" \
  '{
    session_id: $session_id,
    transaction_id: $transaction_id,
    ai_profile: $ai_profile,
    metadata: {app_user: $app_user, app_name: $app_name, ai_model: $ai_model},
    contents: [{prompt: $prompt, code_prompt: $code_prompt}]
  }')

# Call Prisma AIRS API
SCAN_RESULT=$(curl -s -L --max-time 10 --retry 1 "$PRISMA_AIRS_API_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -H "x-pan-token: $PRISMA_AIRS_API_KEY" \
  -d "$PAYLOAD")

# Fail-closed on empty response (network error, timeout, etc.)
if [[ -z "$SCAN_RESULT" ]]; then
    echo "[$(date)] ERROR: Empty response from AIRS API — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: empty API response — blocking bash command (fail-closed)" >&2
    exit 2
fi

ACTION=$(echo "$SCAN_RESULT" | jq -r '.action // "unknown"')
CATEGORY=$(echo "$SCAN_RESULT" | jq -r '.category // "unknown"')
SCAN_ID=$(echo "$SCAN_RESULT" | jq -r '.scan_id // "unknown"')
REPORT_ID=$(echo "$SCAN_RESULT" | jq -r '.report_id // empty')

# Parse ALL detection flags that were triggered
BASH_DETECTIONS=""
DETECTED_CATEGORIES=$(echo "$SCAN_RESULT" | jq -r '.prompt_detected | to_entries | map(select(.value == true)) | map(.key) | .[]' 2>/dev/null)

while IFS= read -r category; do
    [[ -z "$category" ]] && continue
    BASH_DETECTIONS="${BASH_DETECTIONS}$category,"
done <<< "$DETECTED_CATEGORIES"

BASH_DETECTIONS=$(echo "$BASH_DETECTIONS" | sed 's/,$//')

# Check if bash command should be blocked
if [[ "$ACTION" == "block" ]]; then
    LOG_ENTRY="[$(date)] BLOCKED BASH COMMAND: $CATEGORY"
    [[ -n "$BASH_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$BASH_DETECTIONS]"
    LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY (report_id: $REPORT_ID)"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
    echo "[$(date)] BLOCKED COMMAND: $BASH_COMMAND" >> "$LOG_FILE"
    echo "BLOCKED: Malicious bash command detected ($CATEGORY)" >&2
    exit 2  # Block the command
fi

if [[ "$ACTION" != "allow" ]]; then
    LOG_ENTRY="[$(date)] ERROR: Unexpected AIRS action for bash command: $ACTION/$CATEGORY — blocking (fail-closed)"
    LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
    [[ -n "$REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY (report_id: $REPORT_ID)"
    echo "$LOG_ENTRY" >> "$LOG_FILE"
    echo "Prisma AIRS: unexpected API response — blocking bash command (fail-closed)" >&2
    exit 2
fi

# Log allowed commands
LOG_ENTRY="[$(date)] ALLOWED BASH COMMAND"
[[ -n "$BASH_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY: $CATEGORY - detected: [$BASH_DETECTIONS]"
LOG_ENTRY="$LOG_ENTRY (scan_id: $SCAN_ID)"
echo "$LOG_ENTRY" >> "$LOG_FILE"
exit 0
