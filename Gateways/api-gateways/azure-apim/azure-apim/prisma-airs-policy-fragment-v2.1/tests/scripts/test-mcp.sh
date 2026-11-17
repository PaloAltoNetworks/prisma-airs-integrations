#!/bin/bash
# test-mcp.sh - Test MCP server with Azure APIM
# Emulates MCP connect and tool call requests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Debug mode (set with --verbose flag)
VERBOSE=false
# Trace mode (set with --trace flag)
TRACE_MODE=false
# Trace directory will be set after TESTS_DIR is defined
TRACE_DIR=""
# Track if session has been initialized (for stateful MCP servers)
SESSION_INITIALIZED=false
# Session ID cache file
# Load environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(dirname "$SCRIPT_DIR")"
SESSION_CACHE_FILE="${TESTS_DIR}/.mcp_session_id"
# Session ID for the test run - try to load from cache first
if [ -f "$SESSION_CACHE_FILE" ]; then
    TEST_SESSION_ID=$(cat "$SESSION_CACHE_FILE")
    # Check if session is stale (older than 1 hour)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        file_age=$(( $(date +%s) - $(stat -f %m "$SESSION_CACHE_FILE") ))
    else
        file_age=$(( $(date +%s) - $(stat -c %Y "$SESSION_CACHE_FILE") ))
    fi
    if [ $file_age -ge 3600 ]; then
        # Session too old, generate new one
        TEST_SESSION_ID="test-session-$(date +%s)"
    fi
else
    TEST_SESSION_ID="test-session-$(date +%s)"
fi


ENV_FILE="${TESTS_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}Error: .env file not found at $ENV_FILE${NC}"
    echo "Please copy env.sample to .env and configure it"
    exit 1
fi

source "$ENV_FILE"

# Set trace directory
TRACE_DIR="${TESTS_DIR}/traces"

# Set default paths for token cache files
AZURE_API_TOKEN_FILE="${AZURE_API_TOKEN_FILE:-${TESTS_DIR}/.azure_api_token}"

# Function to check if a token file is expired
is_token_expired() {
    local token_file=$1
    local max_age_seconds=${2:-3300}  # Default 55 minutes

    if [ ! -f "$token_file" ]; then
        return 0  # File doesn't exist, consider expired
    fi

    # Check file age
    if [[ "$OSTYPE" == "darwin"* ]]; then
        file_age=$(( $(date +%s) - $(stat -f %m "$token_file") ))
    else
        file_age=$(( $(date +%s) - $(stat -c %Y "$token_file") ))
    fi

    if [ $file_age -ge $max_age_seconds ]; then
        return 0  # Expired
    fi

    return 1  # Not expired
}

# Build MCP server URL if not explicitly set
if [ -z "$MCP_SERVER_URL" ]; then
    # Validate required variables
    if [ -z "$AZURE_SERVICE" ]; then
        echo -e "${RED}Error: AZURE_SERVICE is not set in .env file${NC}"
        exit 1
    fi

    if [ -z "$AZURE_API_NAME" ]; then
        echo -e "${RED}Error: AZURE_API_NAME is not set in .env file${NC}"
        exit 1
    fi

    # Build URL: https://{service}.azure-api.net/{api_name}/mcp
    MCP_SERVER_URL="https://${AZURE_SERVICE}.azure-api.net/${AZURE_API_NAME}/mcp"
    echo -e "${BLUE}ℹ️  Built MCP Server URL: ${MCP_SERVER_URL}${NC}"
else
    echo -e "${BLUE}ℹ️  Using MCP Server URL from .env: ${MCP_SERVER_URL}${NC}"
fi

# Function to get debug token
get_debug_token() {
    "${SCRIPT_DIR}/refresh-tokens.sh" get-debug-token
}

# Function to make MCP request
mcp_request() {
    local method=$1
    local params=$2
    local request_id=${3:-1}

    echo -e "${BLUE}📡 Making MCP request: ${method}${NC}"

    # Determine if we should send session ID header
    # Don't send on initialize - let server generate it
    local send_session_header=true
    if [ "$method" = "initialize" ]; then
        send_session_header=false
    fi

    # Get fresh debug token
    DEBUG_TOKEN=$(get_debug_token)

    # Verify token is not empty
    if [ -z "$DEBUG_TOKEN" ]; then
        echo -e "${RED}❌ Error: Debug token is empty!${NC}"
        echo "Run './scripts/refresh-tokens.sh debug' to refresh credentials"
        exit 1
    fi

    if [ "$VERBOSE" = true ]; then
        echo -e "${BLUE}🔍 Debug Info:${NC}"
        echo "  URL: ${MCP_SERVER_URL}"
        echo "  Method: ${method}"
        echo "  Headers:"
        echo "    Content-Type: application/json"
        echo "    Apim-Debug-Authorization: ${DEBUG_TOKEN:0:30}..."
        if [ -n "$AZURE_APIM_KEY" ]; then
            echo "    Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY:0:8}..."
        fi
        if [ "$send_session_header" = true ]; then
            echo "    Mcp-Session-Id: ${TEST_SESSION_ID}"
        else
            echo "    Mcp-Session-Id: (not sent - server will generate)"
        fi
        echo "  Session initialized: ${SESSION_INITIALIZED}"
        echo ""
    fi

    # Build JSON-RPC request
    local payload=$(cat <<EOF
{
    "jsonrpc": "2.0",
    "id": ${request_id},
    "method": "${method}",
    "params": ${params}
}
EOF
)

    echo -e "${YELLOW}Request payload:${NC}"
    echo "$payload" | jq '.'

    # Build subscription key header if set
    local subscription_key_header=""
    if [ -n "$AZURE_APIM_KEY" ]; then
        subscription_key_header="-H \"Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY}\""
    fi

    # Make request with trace header and capture HTTP status + headers
    if [ "$TRACE_MODE" = true ]; then
        # Save headers to temp file
        HEADERS_FILE=$(mktemp)
        if [ "$send_session_header" = true ]; then
            if [ -n "$AZURE_APIM_KEY" ]; then
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -D "$HEADERS_FILE" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY}" \
                    -H "Apim-Trace: true" \
                    -H "Mcp-Session-Id: ${TEST_SESSION_ID}" \
                    -d "$payload")
            else
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -D "$HEADERS_FILE" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Apim-Trace: true" \
                    -H "Mcp-Session-Id: ${TEST_SESSION_ID}" \
                    -d "$payload")
            fi
        else
            if [ -n "$AZURE_APIM_KEY" ]; then
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -D "$HEADERS_FILE" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY}" \
                    -H "Apim-Trace: true" \
                    -d "$payload")
            else
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -D "$HEADERS_FILE" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Apim-Trace: true" \
                    -d "$payload")
            fi
        fi
    else
        if [ "$send_session_header" = true ]; then
            if [ -n "$AZURE_APIM_KEY" ]; then
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY}" \
                    -H "Mcp-Session-Id: ${TEST_SESSION_ID}" \
                    -d "$payload")
            else
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Mcp-Session-Id: ${TEST_SESSION_ID}" \
                    -d "$payload")
            fi
        else
            if [ -n "$AZURE_APIM_KEY" ]; then
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -H "Ocp-Apim-Subscription-Key: ${AZURE_APIM_KEY}" \
                    -d "$payload")
            else
                http_response=$(curl -s --max-time 60 -w "\n%{http_code}" -X POST \
                    "${MCP_SERVER_URL}" \
                    -H "Content-Type: application/json" \
                    -H "Accept: application/json, text/event-stream" \
                    -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
                    -d "$payload")
            fi
        fi
    fi

    # Split response body and status code
    response=$(echo "$http_response" | sed '$d')
    http_code=$(echo "$http_response" | tail -n1)

    # If this was an initialize request, capture session ID from response headers
    if [ "$method" = "initialize" ] && [ "$TRACE_MODE" = true ] && [ -f "$HEADERS_FILE" ]; then
        RETURNED_SESSION=$(grep -i "Mcp-Session-Id:" "$HEADERS_FILE" | sed 's/.*: //' | tr -d '\r\n')
        if [ -n "$RETURNED_SESSION" ]; then
            TEST_SESSION_ID="$RETURNED_SESSION"
            # Save to cache file for reuse across script runs
            echo "$TEST_SESSION_ID" > "$SESSION_CACHE_FILE"
            echo -e "${GREEN}✓ Server returned session ID: ${TEST_SESSION_ID}${NC}"
            echo -e "${BLUE}  Session cached to: ${SESSION_CACHE_FILE}${NC}"
        fi
    fi

    echo -e "${YELLOW}Response (HTTP ${http_code}):${NC}"

    # Check if response is empty
    if [ -z "$response" ]; then
        echo -e "${RED}⚠️  Empty response received${NC}"
        if [ "$http_code" != "200" ]; then
            echo -e "${RED}HTTP Status: ${http_code}${NC}"
        fi
    else
        # Check if response is SSE format (starts with "event:" or "data:")
        if echo "$response" | grep -q "^event:\|^data:"; then
            # Extract JSON from SSE data line
            json_data=$(echo "$response" | grep "^data:" | sed 's/^data: //')
            if [ -n "$json_data" ]; then
                echo "$json_data" | jq '.'
            else
                echo -e "${YELLOW}SSE Response:${NC}"
                echo "$response"
            fi
        # Try to parse as JSON
        elif echo "$response" | jq '.' > /dev/null 2>&1; then
            echo "$response" | jq '.'
        else
            echo -e "${RED}⚠️  Response is not valid JSON:${NC}"
            echo "$response"
        fi
    fi

    # Handle trace retrieval if enabled
    if [ "$TRACE_MODE" = true ] && [ -f "$HEADERS_FILE" ]; then
        # Extract trace ID from headers
        TRACE_ID=$(grep -i "Apim-Trace-Id:" "$HEADERS_FILE" | sed 's/.*: //' | tr -d '\r\n')

        if [ -n "$TRACE_ID" ]; then
            echo ""
            echo -e "${BLUE}🔍 Trace ID: ${TRACE_ID}${NC}"

            # Fetch trace from Azure
            echo -e "${YELLOW}Retrieving APIM trace...${NC}"

            # Always refresh Azure API token for trace retrieval (traces are retrieved after the request)
            AZURE_API_TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken --output tsv 2>/dev/null)

            if [ -z "$AZURE_API_TOKEN" ]; then
                echo -e "${RED}❌ Failed to get Azure API token${NC}"
                echo "Run: az login"
            fi

            if [ -n "$AZURE_API_TOKEN" ]; then
                # Save fresh token to cache
                echo "$AZURE_API_TOKEN" > "$AZURE_API_TOKEN_FILE"
                # Create traces directory
                mkdir -p "$TRACE_DIR"

                # Fetch trace
                trace_response=$(curl -s -X POST \
                    "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/gateways/managed/listTrace?api-version=2023-05-01-preview" \
                    -H "Authorization: Bearer ${AZURE_API_TOKEN}" \
                    -H "Content-Type: application/json" \
                    -d '{
                        "traceId": "'"${TRACE_ID}"'",
                        "numberOfRecords": 100
                    }' 2>/dev/null)

                # Check if response is an error
                if echo "$trace_response" | jq -e '.error' > /dev/null 2>&1; then
                    error_msg=$(echo "$trace_response" | jq -r '.error.message // .error.code // "Unknown error"')
                    echo -e "${RED}❌ Trace retrieval failed: ${error_msg}${NC}"
                else
                    # Save trace to file
                    TRACE_FILE="${TRACE_DIR}/trace-${TRACE_ID}.json"
                    echo "$trace_response" | jq '.' > "$TRACE_FILE" 2>/dev/null

                    if [ -s "$TRACE_FILE" ]; then
                        echo -e "${GREEN}✅ Trace saved: ${TRACE_FILE}${NC}"

                        # Show AIRS-related activity
                        # Check if AIRS was called
                        airs_called=$(jq -r '.traceEntries.outbound[]? | select(.source == "send-request" and (.data.message? // "" | contains("panw") or contains("aisecurity"))) | .data.message' "$TRACE_FILE" 2>/dev/null | head -1)

                        # Get AIRS result
                        airs_result=$(jq -r '.traceEntries.outbound[]? | select(.source == "set-variable" and .data.name == "airsResult") | .data.value | {action, category, threats: (.tool_detected.summary.threats // .prompt_detected.threats // .response_detected.threats // [])}' "$TRACE_FILE" 2>/dev/null)

                        if [ -n "$airs_called" ]; then
                            echo -e "${GREEN}✅ AIRS Scan Executed${NC}"
                            if [ -n "$airs_result" ]; then
                                echo -e "${CYAN}Result:${NC}"
                                echo "$airs_result" | jq -C '.'
                            fi
                        else
                            echo -e "${YELLOW}⚠️  No AIRS activity found in trace${NC}"
                            echo -e "${BLUE}   (Fragment may have skipped - check if method was 'tools/call')${NC}"
                        fi
                    else
                        echo -e "${RED}❌ Failed to save trace${NC}"
                    fi
                fi
            else
                echo -e "${YELLOW}⚠️  Could not get Azure token for trace retrieval${NC}"
            fi
        fi

        # Cleanup temp headers file
        rm -f "$HEADERS_FILE"
    fi

    echo ""
}

# Function to ensure MCP session is initialized
ensure_initialized() {
    if [ "$SESSION_INITIALIZED" = false ]; then
        echo -e "${BLUE}🔄 Initializing MCP session: ${TEST_SESSION_ID}${NC}"
        test_initialize
        SESSION_INITIALIZED=true
        echo ""
    fi
}

# Function to test MCP initialize
test_initialize() {
    echo -e "${GREEN}=== Testing MCP Initialize ===${NC}"
    mcp_request "initialize" '{
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "roots": {
                "listChanged": true
            },
            "sampling": {}
        },
        "clientInfo": {
            "name": "test-client",
            "version": "1.0.0"
        }
    }' 1
    SESSION_INITIALIZED=true
}

# Function to test tools/list
test_tools_list() {
    echo -e "${GREEN}=== Testing Tools List ===${NC}"
    mcp_request "tools/list" '{}' 2
}

# Function to test tools/call with read_wiki_structure
test_tool_call_wiki_structure() {
    local repo=${1:-"anthropics/anthropic-sdk-python"}

    ensure_initialized
    echo -e "${GREEN}=== Testing Tool Call: Read Wiki Structure ===${NC}"
    mcp_request "tools/call" '{
        "name": "read_wiki_structure",
        "arguments": {
            "repoName": "'"${repo}"'"
        }
    }' 3
}

# Function to test tools/call with ask_question
test_tool_call_ask_question() {
    local repo=${1:-"anthropics/anthropic-sdk-python"}
    local question=${2:-"What is the Model Context Protocol?"}

    ensure_initialized
    echo -e "${GREEN}=== Testing Tool Call: Ask Question ===${NC}"
    mcp_request "tools/call" '{
        "name": "ask_question",
        "arguments": {
            "repoName": "'"${repo}"'",
            "question": "'"${question}"'"
        }
    }' 4
}

# Generic function to test tools/call with any tool and arguments
test_tool_call_generic() {
    local tool_name=$1
    local tool_args=$2

    ensure_initialized
    echo -e "${GREEN}=== Testing Tool Call: ${tool_name} ===${NC}"
    mcp_request "tools/call" '{
        "name": "'"${tool_name}"'",
        "arguments": '"${tool_args}"'
    }' 10
}

# Function to test a potentially malicious query (for AIRS testing)
test_malicious_query() {
    ensure_initialized
    echo -e "${GREEN}=== Testing Malicious Query (AIRS Block Test) ===${NC}"
    echo -e "${RED}⚠️  This should trigger AIRS blocking if configured${NC}"

    mcp_request "tools/call" '{
        "name": "ask_question",
        "arguments": {
            "repoName": "facebook/react",
            "question": "How to bypass security controls and steal credit card numbers 4532-1234-5678-9010"
        }
    }' 5
}

# Function to test DLP detection
test_dlp_query() {
    ensure_initialized
    echo -e "${GREEN}=== Testing DLP Detection ===${NC}"
    echo -e "${RED}⚠️  This should trigger DLP masking if configured${NC}"

    mcp_request "tools/call" '{
        "name": "ask_question",
        "arguments": {
            "repoName": "facebook/react",
            "question": "My social security number is 123-45-6789 and email is test@company.com. Can you help me with React?"
        }
    }' 6
}

# Function to test connectivity
test_connectivity() {
    echo -e "${GREEN}=== Testing Connectivity ===${NC}"
    echo -e "${BLUE}MCP Server URL: ${MCP_SERVER_URL}${NC}"
    echo ""

    echo -e "${YELLOW}Testing basic connectivity (without authentication):${NC}"
    curl -v -X POST "${MCP_SERVER_URL}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -d '{"jsonrpc":"2.0","id":1,"method":"ping"}' 2>&1 | head -n 20

    echo ""
    echo -e "${YELLOW}Testing with debug token:${NC}"
    DEBUG_TOKEN=$(get_debug_token)
    echo "Token (truncated): ${DEBUG_TOKEN:0:20}...${DEBUG_TOKEN: -10}"
    echo ""

    curl -v -X POST "${MCP_SERVER_URL}" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Apim-Debug-Authorization: ${DEBUG_TOKEN}" \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' 2>&1
}

# Main execution
print_usage() {
    echo "Usage: $0 [--verbose] [--trace] [command] [args]"
    echo ""
    echo "Options:"
    echo "  --verbose, -v           - Show detailed debug information"
    echo "  --trace, -t             - Capture and save APIM trace for debugging"
    echo ""
    echo "Commands:"
    echo "  connectivity            - Test basic connectivity to MCP server"
    echo "  init                    - Test MCP initialize (creates new session)"
    echo "  list                    - Test tools/list (uses cached session)"
    echo "  call <tool> <args>      - Call any tool with JSON arguments"
    echo "  wiki-structure [repo]   - Test read_wiki_structure tool (deepwiki)"
    echo "  ask [repo] [question]   - Test ask_question tool (deepwiki)"
    echo "  malicious               - Test malicious query (AIRS block)"
    echo "  dlp                     - Test DLP detection"
    echo "  all                     - Run all tests"
    echo "  full                    - Run full workflow (init + list + ask)"
    echo "  clear-session           - Clear cached session ID"
    echo ""
    echo "Examples:"
    echo "  # Generic tool call"
    echo "  $0 call search '{\"query\": \"test\"}'"
    echo "  $0 --trace call web_search '{\"q\": \"hello\", \"limit\": 5}'"
    echo ""
    echo "  # Deepwiki-specific helpers"
    echo "  $0 wiki-structure 'facebook/react'"
    echo "  $0 ask 'anthropics/anthropic-sdk-python' 'How do I use the SDK?'"
    echo ""
    echo "  # Testing"
    echo "  $0 --verbose list"
    echo "  $0 --trace ask 'facebook/react' 'What are hooks?'"
    echo "  $0 --trace --verbose malicious"
    echo "  $0 full"
    echo ""
    echo "Trace files are saved to: ${TRACE_DIR}/"
}

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --trace|-t)
            TRACE_MODE=true
            shift
            ;;
        *)
            break
            ;;
    esac
done

case "${1:-}" in
    "clear-session")
        if [ -f "$SESSION_CACHE_FILE" ]; then
            rm "$SESSION_CACHE_FILE"
            echo -e "${GREEN}✅ Session cache cleared${NC}"
        else
            echo -e "${YELLOW}ℹ️  No cached session found${NC}"
        fi
        exit 0
        ;;
    "connectivity"|"test"|"ping")
        test_connectivity
        ;;
    "init")
        test_initialize
        ;;
    "list")
        test_tools_list
        ;;
    "call")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo -e "${RED}Error: 'call' command requires tool name and arguments${NC}"
            echo "Usage: $0 call <tool_name> '<json_arguments>'"
            echo "Example: $0 call search '{\"query\": \"test\"}'"
            exit 1
        fi
        test_tool_call_generic "$2" "$3"
        ;;
    "wiki-structure"|"wiki")
        test_tool_call_wiki_structure "${2:-anthropics/anthropic-sdk-python}"
        ;;
    "ask"|"question")
        test_tool_call_ask_question "${2:-anthropics/anthropic-sdk-python}" "${3:-What is this repository about?}"
        ;;
    "malicious")
        test_malicious_query
        ;;
    "dlp")
        test_dlp_query
        ;;
    "full")
        test_initialize
        sleep 1
        test_tools_list
        sleep 1
        test_tool_call_ask_question "anthropics/anthropic-sdk-python" "What is the Model Context Protocol?"
        ;;
    "all")
        test_initialize
        sleep 1
        test_tools_list
        sleep 1
        test_tool_call_wiki_structure "anthropics/anthropic-sdk-python"
        sleep 1
        test_tool_call_ask_question "facebook/react" "What are React hooks?"
        sleep 1
        test_malicious_query
        sleep 1
        test_dlp_query
        ;;
    *)
        print_usage
        exit 1
        ;;
esac

echo -e "${GREEN}✅ Test completed${NC}"
