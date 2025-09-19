#!/bin/bash

# Configuration with environment variable support
LOG_FILE="${SECURITY_LOG_PATH:-.claude/hooks/security.log}"
AIRS_API_URL="${AIRS_API_URL:-https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request}"
AIRS_API_KEY="${AIRS_API_KEY}"
PROFILE_NAME="${AIRS_PROFILE_NAME}"

# Create log file if it doesn't exist
mkdir -p "/Users/jpro/demos/cc_hooks/.claude/hooks"
touch "$LOG_FILE"

# Read JSON input from stdin
INPUT_JSON=$(cat)

# Parse the hook input
TOOL_NAME=$(echo "$INPUT_JSON" | jq -r '.tool_name // "unknown"')
TOOL_RESPONSE=$(echo "$INPUT_JSON" | jq -r '.tool_response // ""')

# Log that we're processing this tool
echo "[$(date)] 🔍 $TOOL_NAME: PostToolUse hook triggered" >> "$LOG_FILE"

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
    RESPONSE_CONTENT="$(echo "$INPUT_JSON" | jq -r '.tool_response | .. | strings' 2>/dev/null | tr '\n' ' ' | head -c 2000)"
fi

# Final fallback: Convert entire tool_response to string if it's not null
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    TOOL_RESP_RAW="$(echo "$INPUT_JSON" | jq -r '.tool_response // empty')"
    if [[ -n "$TOOL_RESP_RAW" && "$TOOL_RESP_RAW" != "null" ]]; then
        RESPONSE_CONTENT="$TOOL_RESP_RAW"
    fi
fi

# Log content extraction result
echo "[$(date)] 🔍 $TOOL_NAME: Extracted content length: ${#RESPONSE_CONTENT}" >> "$LOG_FILE"

# Skip if no content to scan
if [[ -z "$RESPONSE_CONTENT" || ${#RESPONSE_CONTENT} -lt 5 ]]; then
    echo "[$(date)] 🔍 $TOOL_NAME: Skipping - insufficient content (${#RESPONSE_CONTENT} chars)" >> "$LOG_FILE"
    exit 0
fi

# Fail-closed guard for API key
: "${AIRS_API_KEY:?AIRS_API_KEY not set}"

# Extract URLs from response content with better regex
URLS=$(echo "$RESPONSE_CONTENT" | grep -oE 'https?://[^\s<>"'"'"'()]+' | sort -u)

# Scan URLs if found
if [[ -n "$URLS" ]]; then
    echo "[$(date)] 🔗 $TOOL_NAME: Found URLs in response" >> "$LOG_FILE"
    while IFS= read -r URL; do
        [[ -z "$URL" ]] && continue
        
        URL_PAYLOAD=$(cat << EOF
{
  "tr_id": "response-url-$(date +%s)",
  "ai_profile": {"profile_name": "$PROFILE_NAME"},
  "metadata": {"app_user": "claude-code-user", "tool_name": "$TOOL_NAME", "source": "response-url"},
  "contents": [{"response": "$URL"}]
}
EOF
)
        
        # Curl with timeouts and retries
        CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
        URL_RESULT=$(curl "${CURL_OPTS[@]}" "$AIRS_API_URL" \
          -H "Content-Type: application/json" -H "x-pan-token: $AIRS_API_KEY" -d "$URL_PAYLOAD")
        URL_ACTION=$(echo "$URL_RESULT" | jq -r '.action // "unknown"')
        URL_CATEGORY=$(echo "$URL_RESULT" | jq -r '.category // "unknown"')
        URL_SCAN_ID=$(echo "$URL_RESULT" | jq -r '.scan_id // "unknown"')
        
        # After URL_ACTION/URL_CATEGORY/URL_SCAN_ID:
        URL_DETECTIONS=""
        # Dynamically extract all true detection fields from both prompt_detected and response_detected
        URL_DETECTIONS=$(echo "$URL_RESULT" | jq -r '
          [
            (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
            (.response_detected // {} | to_entries[] | select(.value == true) | .key)
          ] | unique | join(",")
        ')

        if [[ "$URL_ACTION" == "block" ]]; then
          if [[ -n "$URL_DETECTIONS" ]]; then
            echo "[$(date)] 🚫 BLOCKED URL in $TOOL_NAME response: $URL ($URL_CATEGORY) - detected: [$URL_DETECTIONS] [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          else
            echo "[$(date)] 🚫 BLOCKED URL in $TOOL_NAME response: $URL ($URL_CATEGORY) [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          fi
          printf '%s' '{
  "continue": false,
  "stopReason": "Prisma AIRS blocked tool response",
  "hookSpecificOutput": { "hookEventName": "PostToolUse" }
}'
          exit 0
        elif [[ "$URL_ACTION" != "allow" ]]; then
          if [[ -n "$URL_DETECTIONS" ]]; then
            echo "[$(date)] ⚠️  URL WARNING in $TOOL_NAME response: $URL - $URL_ACTION/$URL_CATEGORY - detected: [$URL_DETECTIONS] [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          else
            echo "[$(date)] ⚠️  URL WARNING in $TOOL_NAME response: $URL - $URL_ACTION/$URL_CATEGORY [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          fi
        else
          if [[ -n "$URL_DETECTIONS" ]]; then
            echo "[$(date)] ✅ URL in $TOOL_NAME response: $URL - detected: [$URL_DETECTIONS] [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          else
            echo "[$(date)] ✅ URL in $TOOL_NAME response: $URL [scan:$URL_SCAN_ID]" >> "$LOG_FILE"
          fi
        fi
    done <<< "$URLS"
fi

# Scan response content if reasonable size (truncate and optimize)
TRUNCATED_CONTENT="$(echo "$RESPONSE_CONTENT" | head -c 2000 | tr '\n' ' ')"
if [[ ${#TRUNCATED_CONTENT} -ge 10 ]]; then
    CONTENT_PAYLOAD=$(cat << EOF
{
  "tr_id": "response-content-$(date +%s)",
  "ai_profile": {"profile_name": "$PROFILE_NAME"},
  "metadata": {"app_user": "claude-code-user", "tool_name": "$TOOL_NAME", "source": "response-content"},
  "contents": [{"response": $(echo "$TRUNCATED_CONTENT" | jq -R .)}]
}
EOF
)
    
    # Curl with timeouts and retries
    CURL_OPTS=(--silent --show-error --location --max-time 10 --retry 1)
    CONTENT_RESULT=$(curl "${CURL_OPTS[@]}" "$AIRS_API_URL" \
      -H "Content-Type: application/json" -H "x-pan-token: $AIRS_API_KEY" -d "$CONTENT_PAYLOAD")
    CONTENT_ACTION=$(echo "$CONTENT_RESULT" | jq -r '.action // "unknown"')
    CONTENT_CATEGORY=$(echo "$CONTENT_RESULT" | jq -r '.category // "unknown"')
    CONTENT_SCAN_ID=$(echo "$CONTENT_RESULT" | jq -r '.scan_id // "unknown"')
    
    # After CONTENT_ACTION/CONTENT_CATEGORY/CONTENT_SCAN_ID:
    # Dynamically extract all true detection fields from both prompt_detected and response_detected
    RESP_DETECTIONS=$(echo "$CONTENT_RESULT" | jq -r '
      [
        (.prompt_detected // {} | to_entries[] | select(.value == true) | .key),
        (.response_detected // {} | to_entries[] | select(.value == true) | .key)
      ] | unique | join(",")
    ')

    if [[ "$CONTENT_ACTION" == "block" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME response content: $CONTENT_CATEGORY - detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      else
        echo "[$(date)] 🚫 BLOCKED $TOOL_NAME response content: $CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      fi
      printf '%s' '{
  "continue": false,
  "stopReason": "Prisma AIRS blocked tool response",
  "hookSpecificOutput": { "hookEventName": "PostToolUse" }
}'
      exit 0
    elif [[ "$CONTENT_ACTION" != "allow" && "$CONTENT_ACTION" != "unknown" ]]; then
      if [[ -n "$RESP_DETECTIONS" ]]; then
        echo "[$(date)] ⚠️  $TOOL_NAME response content warning: $CONTENT_ACTION/$CONTENT_CATEGORY - detected: [$RESP_DETECTIONS] [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      else
        echo "[$(date)] ⚠️  $TOOL_NAME response content warning: $CONTENT_ACTION/$CONTENT_CATEGORY [scan:$CONTENT_SCAN_ID]" >> "$LOG_FILE"
      fi
    fi
fi

exit 0
