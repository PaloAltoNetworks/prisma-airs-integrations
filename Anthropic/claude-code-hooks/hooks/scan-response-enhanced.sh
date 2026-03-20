#!/bin/bash

LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/prisma-airs.log}"

# Prisma AIRS API Configuration
PRISMA_AIRS_API_URL="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}/v1/scan/sync/request"
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME:-}"

# Set app name with optional custom suffix
if [[ -n "$CLAUDE_CODE_APP_SUFFIX" ]]; then
    APP_NAME="Claude Code-${CLAUDE_CODE_APP_SUFFIX}"
else
    APP_NAME="Claude Code"
fi

# === FD HARDENING FOR CLEAN JSON OUTPUT ===
# Save original stdout to FD 3 for JSON responses
exec 3>&1
# Redirect stdout to log file to prevent pollution
exec 1>>"$LOG_FILE"
# Keep stderr available for user messages (shows in terminal Claude Code)

# Create log file if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Parse the hook input
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
TOOL_RESPONSE=$(echo "$INPUT_JSON" | jq -r '.tool_response // ""')

# Detect MCP tools and extract server/tool from pattern: mcp__<server>__<tool>
IS_MCP=false
if [[ "$TOOL_NAME" == mcp__* ]]; then
    IS_MCP=true
    MCP_SERVER=$(echo "$TOOL_NAME" | awk -F'__' '{print $2}')
    TOOL_INVOKED=$(echo "$TOOL_NAME" | awk -F'__' '{print $3}')
    TOOL_INPUT_STR=$(echo "$INPUT_JSON" | jq -c '.tool_input // {}' 2>/dev/null)
fi

# Extract transcript_path for session ID (if available)
TRANSCRIPT_PATH=$(echo "$INPUT_JSON" | jq -r '.transcript_path // empty' 2>/dev/null)

# Generate session UUID
if [[ -n "$TRANSCRIPT_PATH" ]]; then
    # Extract session ID from transcript path (e.g., /path/to/.claude/sessions/abc-123/transcript.jsonl)
    SESSION_ID=$(echo "$TRANSCRIPT_PATH" | sed -E 's/.*\/sessions\/([^\/]+)\/.*/\1/')
    # If extraction failed, use path hash as fallback
    if [[ -z "$SESSION_ID" || "$SESSION_ID" == "$TRANSCRIPT_PATH" ]]; then
        SESSION_ID=$(echo "$TRANSCRIPT_PATH" | md5 | cut -c1-32)
    fi
else
    # Fallback: use working directory hash for session correlation
    SESSION_ID=$(echo "$PWD" | md5 | cut -c1-32)
fi

# Log that we're processing this tool
echo "[$(date)] 🔍 $TOOL_NAME: PostToolUse hook triggered"

# Enhanced response content extraction - try multiple approaches
RESPONSE_CONTENT=""

# First attempt: Enhanced extraction
RESPONSE_CONTENT="$(echo "$INPUT_JSON" \
  | jq -r '
      .tool_response
      | if type=="object" then
          # try common fields first, else collect strings
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
    # Try extracting all strings from tool_response
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
echo "[$(date)] 🔍 $TOOL_NAME: Extracted content length: ${#RESPONSE_CONTENT}"

# Skip if no content to scan
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    echo "[$(date)] 🔍 $TOOL_NAME: Skipping - insufficient content (${#RESPONSE_CONTENT} chars)"
    exit 0
fi

# Fail-closed guard for API key
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
    echo "[$(date)] WARNING: PRISMA_AIRS_API_KEY not set, skipping scan" >> "$LOG_FILE"
    exit 0
fi

# Scan response content if reasonable size (truncate and optimize)
TRUNCATED_CONTENT="$(echo "$RESPONSE_CONTENT" | head -c 20000 | tr '\n' ' ')"
if [[ ${#TRUNCATED_CONTENT} -ge 10 ]]; then
    if [[ "$IS_MCP" == true ]]; then
        # Use tool_event for MCP tools (includes input + output)
        CONTENT_PAYLOAD=$(jq -n \
          --arg tr_id "$SESSION_ID" \
          --arg profile "$PRISMA_AIRS_PROFILE_NAME" \
          --arg app_user "claude-code-user" \
          --arg app_name "$APP_NAME" \
          --arg server_name "$MCP_SERVER" \
          --arg tool_invoked "$TOOL_INVOKED" \
          --arg input "$TOOL_INPUT_STR" \
          --arg output "$TRUNCATED_CONTENT" \
          '{
            tr_id: $tr_id,
            ai_profile: {profile_name: $profile},
            metadata: {app_user: $app_user, app_name: $app_name},
            contents: [{
              response: $output,
              tool_event: {
                metadata: {
                  ecosystem: "mcp",
                  method: "tools/call",
                  server_name: $server_name,
                  tool_invoked: $tool_invoked
                },
                input: $input,
                output: $output
              }
            }]
          }')
    else
        CONTENT_PAYLOAD=$(cat << EOF
{
  "tr_id": "$SESSION_ID",
  "ai_profile": {"profile_name": "$PRISMA_AIRS_PROFILE_NAME"},
  "metadata": {"app_user": "claude-code-user", "app_name": "$APP_NAME", "tool_name": "$TOOL_NAME", "source": "response-content"},
  "contents": [{"response": $(echo "$TRUNCATED_CONTENT" | jq -R .)}]
}
EOF
)
    fi
    
    # Curl with timeouts and retries
    CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
    CONTENT_RESULT=$(curl "${CURL_OPTS[@]}" "$PRISMA_AIRS_API_URL" \
      -H "Content-Type: application/json" -H "x-pan-token: $PRISMA_AIRS_API_KEY" -d "$CONTENT_PAYLOAD")
    CONTENT_ACTION=$(echo "$CONTENT_RESULT" | jq -r '.action // "unknown"')
    CONTENT_CATEGORY=$(echo "$CONTENT_RESULT" | jq -r '.category // "unknown"')
    CONTENT_SCAN_ID=$(echo "$CONTENT_RESULT" | jq -r '.scan_id // "unknown"')
    
    # Dynamically extract all true detection fields from both prompt_detected and response_detected
    RESP_DETECTIONS=$(echo "$CONTENT_RESULT" | jq -r '
      [
        (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
        (.response_detected // {} | to_entries[] | select(.value == true) | .key)
      ] | unique | join(",")
    ')

    if [[ "$CONTENT_ACTION" == "block" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME response content: $CONTENT_CATEGORY - detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]"
        BLOCK_MSG="🚫 Blocked by Prisma AIRS: $TOOL_NAME response contained $CONTENT_CATEGORY content (detected: $RESP_DETECTIONS)"
      else
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME response content: $CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]"
        BLOCK_MSG="🚫 Blocked by Prisma AIRS: $TOOL_NAME response contained $CONTENT_CATEGORY content"
      fi
      # Show user message on stderr (visible in terminal Claude Code)
      echo "" >&2
      echo "$BLOCK_MSG" >&2
      echo "" >&2
      # Output blocking JSON to FD 3 (original stdout)
      printf '%s' '{
  "continue": false,
  "stopReason": "Prisma AIRS blocked tool response",
  "systemMessage": "Operation blocked by Prisma AIRS policy",
  "hookSpecificOutput": { "hookEventName": "PostToolUse" }
}' >&3
      exit 0
    elif [[ "$CONTENT_ACTION" != "allow" && "$CONTENT_ACTION" != "unknown" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] ⚠️  $TOOL_NAME response content warning: $CONTENT_ACTION/$CONTENT_CATEGORY - detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]"
      else
        echo "[$(date)] ⚠️  $TOOL_NAME response content warning: $CONTENT_ACTION/$CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]"
      fi
    fi
fi

exit 0