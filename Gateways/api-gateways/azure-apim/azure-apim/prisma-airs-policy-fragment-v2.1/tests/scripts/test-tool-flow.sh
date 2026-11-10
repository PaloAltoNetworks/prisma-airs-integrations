#!/bin/bash

# Multi-turn tool calling test
# Tests the full flow: user query → tool call → tool result → final response

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(dirname "$SCRIPT_DIR")"

# Load environment
if [ -f "$TEST_DIR/.env" ]; then
    source "$TEST_DIR/.env"
else
    echo "❌ Error: .env file not found. Copy env.sample to .env and configure."
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Parse API type
API_TYPE="${1:-openai}"
TRACE_MODE="${2:-false}"

case "$API_TYPE" in
    openai)
        SERVER_URL="https://${AZURE_SERVICE}.azure-api.net/${OPENAI_API_NAME}/chat/completions"
        MODEL="${OPENAI_MODEL:-gpt-4}"
        API_NAME="$OPENAI_API_NAME"
        ;;
    foundry-claude)
        SERVER_URL="https://${AZURE_SERVICE}.azure-api.net/foundry-claude/v1/messages"
        MODEL="${FOUNDRY_CLAUDE_MODEL:-claude-haiku-4-5}"
        API_NAME="$FOUNDRY_CLAUDE_API_NAME"
        ;;
    foundry-gpt)
        SERVER_URL="https://${AZURE_SERVICE}.azure-api.net/${FOUNDRY_GPT_API_NAME}/openai/v1/responses"
        MODEL="${FOUNDRY_GPT_MODEL:-gpt-5.4-nano}"
        API_NAME="$FOUNDRY_GPT_API_NAME"
        ;;
    *)
        echo "Usage: $0 {openai|foundry-claude|foundry-gpt} [--trace]"
        exit 1
        ;;
esac

echo -e "${BLUE}=== Multi-Turn Tool Calling Test ===${NC}"
echo "API: $API_TYPE"
echo "Model: $MODEL"
echo

# Get debug token if needed
if [ "$TRACE_MODE" = "--trace" ]; then
    DEBUG_TOKEN=$("$SCRIPT_DIR/refresh-tokens.sh" get-debug-token "$API_NAME")
    echo -e "${GREEN}✅ Debug token acquired${NC}"
fi

# Build base headers
base_headers=(-H "Content-Type: application/json")
api_header="${AZURE_APIM_HEADER:-Ocp-Apim-Subscription-Key}"
if [ -n "${AZURE_APIM_KEY:-}" ]; then
    base_headers+=(-H "${api_header}: ${AZURE_APIM_KEY}")
fi

if [ "$API_TYPE" = "foundry-claude" ]; then
    base_headers+=(-H "anthropic-version: 2023-06-01")
fi

# Step 1: Initial request with tools
echo -e "\n${YELLOW}📍 Step 1: User asks about weather (with tools available)${NC}"

if [ "$API_TYPE" = "openai" ]; then
    payload1=$(jq -n --arg model "$MODEL" '{
        model: $model,
        max_tokens: 100,
        messages: [{"role": "user", "content": "What is the weather like in San Francisco?"}],
        tools: [{
            type: "function",
            function: {
                name: "get_weather",
                description: "Get current weather",
                parameters: {
                    type: "object",
                    properties: {
                        location: {type: "string", description: "City and state"}
                    },
                    required: ["location"]
                }
            }
        }]
    }')
elif [ "$API_TYPE" = "foundry-claude" ]; then
    payload1=$(jq -n --arg model "$MODEL" '{
        model: $model,
        max_tokens: 100,
        messages: [{"role": "user", "content": "What is the weather like in San Francisco?"}],
        tools: [{
            name: "get_weather",
            description: "Get current weather",
            input_schema: {
                type: "object",
                properties: {
                    location: {type: "string", description: "City and state"}
                },
                required: ["location"]
            }
        }]
    }')
else
    # foundry-gpt
    payload1=$(jq -n --arg model "$MODEL" '{
        model: $model,
        max_output_tokens: 100,
        input: [{"role": "user", "content": "What is the weather like in San Francisco?"}],
        tools: [{
            name: "get_weather",
            type: "function",
            description: "Get current weather",
            parameters: {
                type: "object",
                properties: {
                    location: {type: "string", description: "City and state"}
                },
                required: ["location"]
            }
        }]
    }')
fi

# Add trace headers if enabled
headers=("${base_headers[@]}")
if [ "$TRACE_MODE" = "--trace" ]; then
    TRACE_ID1=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')
    headers+=(-H "Apim-Debug-Authorization: ${DEBUG_TOKEN}")
    headers+=(-H "Apim-Correlation-Id: ${TRACE_ID1}")
    headers+=(-H "Apim-Trace: true")
    echo -e "${BLUE}🔍 Trace ID: $TRACE_ID1${NC}"

    HEADERS_FILE1=$(mktemp)
    http_response=$(curl -s -w "\n%{http_code}" -D "$HEADERS_FILE1" -X POST "$SERVER_URL" "${headers[@]}" -d "$payload1")
    response1=$(echo "$http_response" | sed '$d')
    http_code=$(echo "$http_response" | tail -n1)

    echo "$response1" | jq '.' 2>/dev/null || echo "$response1"

    # Retrieve trace
    ACTUAL_TRACE_ID1=$(grep -i "Apim-Trace-Id:" "$HEADERS_FILE1" | sed 's/.*: //' | tr -d '\r\n' || echo "")
    if [ -z "$ACTUAL_TRACE_ID1" ]; then
        ACTUAL_TRACE_ID1="$TRACE_ID1"
    else
        echo -e "${BLUE}📋 Actual Trace ID: $ACTUAL_TRACE_ID1${NC}"
    fi

    sleep 2
    TRACE_FILE1="$TEST_DIR/traces/trace-${ACTUAL_TRACE_ID1}.json"
    if "$SCRIPT_DIR/refresh-tokens.sh" get-trace "$ACTUAL_TRACE_ID1" "$TRACE_FILE1"; then
        echo -e "${GREEN}✅ Step 1 trace saved: $TRACE_FILE1${NC}"
    fi
    rm -f "$HEADERS_FILE1"
else
    response1=$(curl -s -X POST "$SERVER_URL" "${headers[@]}" -d "$payload1")
    echo "$response1" | jq '.' 2>/dev/null || echo "$response1"
fi

# Step 2: Send tool result back
echo -e "\n${YELLOW}📍 Step 2: App provides tool result (simulated weather data)${NC}"

if [ "$API_TYPE" = "openai" ]; then
    payload2=$(jq -n --arg model "$MODEL" '{
        model: $model,
        max_tokens: 100,
        messages: [
            {"role": "user", "content": "What is the weather like in San Francisco?"},
            {"role": "assistant", "content": null, "tool_calls": [{"id": "call_test", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco, CA\"}"}}]},
            {"role": "tool", "tool_call_id": "call_test", "content": "{\"temperature\": \"72F\", \"conditions\": \"sunny\"}"}
        ]
    }')
elif [ "$API_TYPE" = "foundry-claude" ]; then
    payload2=$(jq -n --arg model "$MODEL" '{
        model: $model,
        max_tokens: 100,
        messages: [
            {"role": "user", "content": "What is the weather like in San Francisco?"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "toolu_test", "name": "get_weather", "input": {"location": "San Francisco, CA"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_test", "content": "Temperature: 72F, Conditions: sunny"}]}
        ]
    }')
else
    # foundry-gpt - Responses API uses previous_response_id for continuation
    # Extract response_id and call_id from Step 1 response
    RESPONSE_ID=$(echo "$response1" | jq -r '.id')
    CALL_ID=$(echo "$response1" | jq -r '.output[0].call_id // empty')

    if [ -z "$RESPONSE_ID" ] || [ -z "$CALL_ID" ]; then
        echo -e "${RED}❌ Error: Could not extract response_id or call_id from Step 1${NC}"
        exit 1
    fi

    echo -e "${BLUE}📋 Using response_id: $RESPONSE_ID${NC}"
    echo -e "${BLUE}📋 Using call_id: $CALL_ID${NC}"

    payload2=$(jq -n --arg model "$MODEL" --arg response_id "$RESPONSE_ID" --arg call_id "$CALL_ID" '{
        model: $model,
        max_output_tokens: 100,
        previous_response_id: $response_id,
        input: [
            {
                "type": "function_call_output",
                "call_id": $call_id,
                "output": "{\"temperature\": \"72F\", \"conditions\": \"sunny\"}"
            }
        ]
    }')
fi

# Add trace headers for step 2
headers=("${base_headers[@]}")
if [ "$TRACE_MODE" = "--trace" ]; then
    TRACE_ID2=$(uuidgen | tr '[:upper:]' '[:lower:]' | tr -d '-')
    headers+=(-H "Apim-Debug-Authorization: ${DEBUG_TOKEN}")
    headers+=(-H "Apim-Correlation-Id: ${TRACE_ID2}")
    headers+=(-H "Apim-Trace: true")
    echo -e "${BLUE}🔍 Trace ID: $TRACE_ID2${NC}"

    HEADERS_FILE2=$(mktemp)
    http_response=$(curl -s -w "\n%{http_code}" -D "$HEADERS_FILE2" -X POST "$SERVER_URL" "${headers[@]}" -d "$payload2")
    response2=$(echo "$http_response" | sed '$d')
    http_code=$(echo "$http_response" | tail -n1)

    echo "$response2" | jq '.' 2>/dev/null || echo "$response2"

    # Retrieve trace
    ACTUAL_TRACE_ID2=$(grep -i "Apim-Trace-Id:" "$HEADERS_FILE2" | sed 's/.*: //' | tr -d '\r\n' || echo "")
    if [ -z "$ACTUAL_TRACE_ID2" ]; then
        ACTUAL_TRACE_ID2="$TRACE_ID2"
    else
        echo -e "${BLUE}📋 Actual Trace ID: $ACTUAL_TRACE_ID2${NC}"
    fi

    sleep 2
    TRACE_FILE2="$TEST_DIR/traces/trace-${ACTUAL_TRACE_ID2}.json"
    if "$SCRIPT_DIR/refresh-tokens.sh" get-trace "$ACTUAL_TRACE_ID2" "$TRACE_FILE2"; then
        echo -e "${GREEN}✅ Step 2 trace saved: $TRACE_FILE2${NC}"
    fi
    rm -f "$HEADERS_FILE2"
else
    response2=$(curl -s -X POST "$SERVER_URL" "${headers[@]}" -d "$payload2")
    echo "$response2" | jq '.' 2>/dev/null || echo "$response2"
fi

echo -e "\n${GREEN}✅ Multi-turn tool test completed${NC}"
echo -e "${BLUE}Expected behavior:${NC}"
echo "  - Step 1: AIRS scans prompt, skips tool_use response (no text)"
echo "  - Step 2: AIRS scans tool_result content and final response text"
