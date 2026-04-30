#!/bin/bash

# Prisma AIRS Bash Response Security Scanner Hook for Codex CLI
# Scans bash command output AFTER execution
# Hook Event: PostToolUse (matcher: Bash)

LOG_FILE="${SECURITY_LOG_PATH:-.codex/hooks/prisma-airs.log}"

# Ensure log file exists before anything writes to it
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Prisma AIRS API Configuration
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

# Set app name with optional custom suffix
if [[ -n "$CODEX_APP_SUFFIX" ]]; then
    APP_NAME="Codex CLI-${CODEX_APP_SUFFIX}"
else
    APP_NAME="Codex CLI"
fi

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Parse the hook input
# Codex PostToolUse provides: session_id, turn_id, tool_name, tool_use_id,
#   tool_input.command, tool_response, cwd, model
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
BASH_COMMAND=$(echo "$INPUT_JSON" | jq -r '.tool_input.command // ""')

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

# Log that we're processing this tool
echo "[$(date)] $TOOL_NAME: PostToolUse hook triggered" >> "$LOG_FILE"

# Enhanced response content extraction - try multiple approaches
RESPONSE_CONTENT=""

# First attempt: Enhanced extraction
RESPONSE_CONTENT="$(echo "$INPUT_JSON" \
  | jq -r '
      .tool_response
      | if type=="object" then
          (.result // .content // .text // .body // .message // .data // .output // .response // .value)
          // (.. | strings | join("\n"))
        elif type=="string" then
          .
        else
          ""
        end
    ' \
  | sed -e 's/\r//g')"

# Fallback: If extraction failed, try simpler approach
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    RESPONSE_CONTENT="$(echo "$INPUT_JSON" | jq -r '.tool_response | .. | strings' 2>/dev/null | tr '\n' ' ' | head -c 20000)"
fi

# Final fallback: Convert entire tool_response to string if it's not null
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    TOOL_RESP_RAW="$(echo "$INPUT_JSON" | jq -r '.tool_response // empty')"
    if [[ -n "$TOOL_RESP_RAW" && "$TOOL_RESP_RAW" != "null" ]]; then
        RESPONSE_CONTENT="$TOOL_RESP_RAW"
    fi
fi

# Log content extraction result
echo "[$(date)] $TOOL_NAME: Extracted content length: ${#RESPONSE_CONTENT}" >> "$LOG_FILE"

# Skip if no content to scan
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    echo "[$(date)] $TOOL_NAME: Skipping - insufficient content (${#RESPONSE_CONTENT} chars)" >> "$LOG_FILE"
    exit 0
fi

# Fail-closed: block if API key not configured
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] ERROR: PRISMA_AIRS_API_KEY not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: API key not configured — blocking response (fail-closed)" >&2
    exit 2
fi

if ! has_profile; then
    echo "[$(date)] ERROR: PRISMA_AIRS_PROFILE_NAME or PRISMA_AIRS_PROFILE_ID not set — blocking (fail-closed)" >> "$LOG_FILE"
    echo "Prisma AIRS: profile not configured — blocking response (fail-closed)" >&2
    exit 2
fi

# Truncate content for API efficiency (AIRS response max ~20K for contextual grounding)
TRUNCATED_CONTENT="$(echo "$RESPONSE_CONTENT" | head -c 20000 | tr '\n' ' ')"
if [[ ${#TRUNCATED_CONTENT} -ge 10 ]]; then
    AI_PROFILE_JSON=$(build_ai_profile)

    # Send both command (as context) and response in contents[] for better AIRS analysis
    CONTENT_PAYLOAD=$(jq -n \
      --arg session_id "$SESSION_ID" \
      --arg transaction_id "$TRANSACTION_ID" \
      --argjson ai_profile "$AI_PROFILE_JSON" \
      --arg app_user "codex-cli-user" \
      --arg app_name "$APP_NAME" \
      --arg ai_model "$MODEL" \
      --arg tool_name "$TOOL_NAME" \
      --arg command "$BASH_COMMAND" \
      --arg response "$TRUNCATED_CONTENT" \
      --arg code_response "$TRUNCATED_CONTENT" \
      '{
        session_id: $session_id,
        transaction_id: $transaction_id,
        ai_profile: $ai_profile,
        metadata: {app_user: $app_user, app_name: $app_name, ai_model: $ai_model, tool_name: $tool_name},
        contents: [
          {prompt: $command},
          {response: $response, code_response: $code_response}
        ]
      }')

    # Curl with timeouts and retries
    CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
    CONTENT_RESULT=$(curl "${CURL_OPTS[@]}" "$PRISMA_AIRS_API_URL" \
      -H "Content-Type: application/json" -H "x-pan-token: $PRISMA_AIRS_API_KEY" -d "$CONTENT_PAYLOAD")

    # Fail-closed on empty response
    if [[ -z "$CONTENT_RESULT" ]]; then
        echo "[$(date)] ERROR: Empty response from AIRS API for $TOOL_NAME — blocking (fail-closed)" >> "$LOG_FILE"
        echo "Prisma AIRS: empty API response — blocking bash response (fail-closed)" >&2
        exit 2
    fi

    CONTENT_ACTION=$(echo "$CONTENT_RESULT" | jq -r '.action // "unknown"')
    CONTENT_CATEGORY=$(echo "$CONTENT_RESULT" | jq -r '.category // "unknown"')
    CONTENT_SCAN_ID=$(echo "$CONTENT_RESULT" | jq -r '.scan_id // "unknown"')
    CONTENT_REPORT_ID=$(echo "$CONTENT_RESULT" | jq -r '.report_id // empty')

    # Dynamically extract all true detection fields from both prompt_detected and response_detected
    RESP_DETECTIONS=$(echo "$CONTENT_RESULT" | jq -r '
      [
        (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
        (.response_detected // {} | to_entries[] | select(.value == true) | .key)
      ] | unique | join(",")
    ')

    # Extract DLP pattern details if available
    DLP_PATTERNS=$(echo "$CONTENT_RESULT" | jq -r '
      [.prompt_masked_data.pattern_detections[]?.pattern, .response_masked_data.pattern_detections[]?.pattern]
      | map(select(. != null)) | unique | join(",")
    ' 2>/dev/null)

    if [[ "$CONTENT_ACTION" != "allow" ]]; then
      LOG_ENTRY="[$(date)] BLOCKED $TOOL_NAME response: $CONTENT_CATEGORY"
      [[ "$CONTENT_ACTION" != "block" ]] && LOG_ENTRY="[$(date)] ERROR: Unexpected AIRS action for $TOOL_NAME response: $CONTENT_ACTION/$CONTENT_CATEGORY — blocking (fail-closed)"
      [[ -n "$RESP_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY - detected: [$RESP_DETECTIONS]"
      [[ -n "$DLP_PATTERNS" ]] && LOG_ENTRY="$LOG_ENTRY - dlp_patterns: [$DLP_PATTERNS]"
      LOG_ENTRY="$LOG_ENTRY [scan:$CONTENT_SCAN_ID]"
      [[ -n "$CONTENT_REPORT_ID" ]] && LOG_ENTRY="$LOG_ENTRY [report:$CONTENT_REPORT_ID]"
      echo "$LOG_ENTRY" >> "$LOG_FILE"

      if [[ "$CONTENT_ACTION" == "block" ]]; then
        BLOCK_MSG="Blocked by Prisma AIRS: $TOOL_NAME response contained $CONTENT_CATEGORY content"
        [[ -n "$RESP_DETECTIONS" ]] && BLOCK_MSG="$BLOCK_MSG (detected: $RESP_DETECTIONS)"
      else
        BLOCK_MSG="Prisma AIRS: unexpected API response for $TOOL_NAME response — blocking (fail-closed)"
      fi

      echo "" >&2
      echo "$BLOCK_MSG" >&2
      echo "" >&2
      # Codex PostToolUse: decision:block replaces tool result with feedback
      printf '%s' "$(jq -n --arg msg "$BLOCK_MSG" '{
  "decision": "block",
  "reason": $msg,
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse",
    "additionalContext": $msg
  }
}')"
      exit 0
    else
      LOG_ENTRY="[$(date)] ALLOWED $TOOL_NAME response"
      [[ -n "$RESP_DETECTIONS" ]] && LOG_ENTRY="$LOG_ENTRY: $CONTENT_CATEGORY - detected: [$RESP_DETECTIONS]"
      LOG_ENTRY="$LOG_ENTRY (scan_id: $CONTENT_SCAN_ID)"
      echo "$LOG_ENTRY" >> "$LOG_FILE"
    fi
fi

exit 0
