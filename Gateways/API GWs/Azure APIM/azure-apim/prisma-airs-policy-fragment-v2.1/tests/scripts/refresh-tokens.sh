#!/bin/bash
# refresh-tokens.sh - Manages Azure APIM tokens for MCP testing
# This script refreshes Azure API tokens and debug credentials as needed

set -e

# Load environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: .env file not found at $ENV_FILE"
    echo "Please copy env.sample to .env and configure it"
    exit 1
fi

source "$ENV_FILE"

# Required variables check
REQUIRED_VARS=("AZURE_SUB_ID" "AZURE_RG" "AZURE_SERVICE")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo "Error: $var is not set in .env file"
        exit 1
    fi
done

# API name is required for debug/get-debug-token commands
if [ "${1:-}" = "debug" ] || [ "${1:-}" = "get-debug-token" ]; then
    if [ -z "${2:-}" ] && [ -z "${AZURE_API_NAME:-}" ]; then
        echo "Error: API name must be provided as parameter or AZURE_API_NAME must be set in .env"
        exit 1
    fi
fi

# Set default paths for token cache files
AZURE_API_TOKEN_FILE="${AZURE_API_TOKEN_FILE:-${SCRIPT_DIR}/../.azure_api_token}"
AZURE_DEBUG_TOKEN_FILE="${AZURE_DEBUG_TOKEN_FILE:-${SCRIPT_DIR}/../.azure_debug_token}"

# Function to check if a token file is expired
is_token_expired() {
    local token_file=$1
    local max_age_seconds=${2:-3300}  # Default 55 minutes (tokens typically last 1 hour)

    if [ ! -f "$token_file" ]; then
        return 0  # File doesn't exist, consider expired
    fi

    # Check file age
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        file_age=$(( $(date +%s) - $(stat -f %m "$token_file") ))
    else
        # Linux
        file_age=$(( $(date +%s) - $(stat -c %Y "$token_file") ))
    fi

    if [ $file_age -ge $max_age_seconds ]; then
        return 0  # Expired
    fi

    return 1  # Not expired
}

# Function to refresh Azure API token
refresh_azure_api_token() {
    echo "🔄 Refreshing Azure API token..." >&2

    # Get new token using Azure CLI
    AZURE_API_TOKEN=$(az account get-access-token \
        --resource https://management.azure.com \
        --query accessToken \
        --output tsv)

    if [ -z "$AZURE_API_TOKEN" ]; then
        echo "❌ Failed to get Azure API token. Make sure you're logged in with 'az login'" >&2
        exit 1
    fi

    # Save token to cache file
    echo "$AZURE_API_TOKEN" > "$AZURE_API_TOKEN_FILE"
    echo "✅ Azure API token refreshed and cached" >&2
}

# Function to refresh debug credentials
refresh_debug_credentials() {
    local api_name="${1:-${AZURE_API_NAME}}"

    if [ -z "$api_name" ]; then
        echo "❌ Error: API name not provided and AZURE_API_NAME not set" >&2
        exit 1
    fi

    echo "🔄 Refreshing Azure APIM debug credentials for API: $api_name..." >&2

    # Load Azure API token from cache or refresh if needed
    if is_token_expired "$AZURE_API_TOKEN_FILE"; then
        refresh_azure_api_token
    else
        AZURE_API_TOKEN=$(cat "$AZURE_API_TOKEN_FILE")
        echo "✅ Using cached Azure API token" >&2
    fi

    # Call listDebugCredentials API
    response=$(curl -s -X POST \
        "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/gateways/managed/listDebugCredentials?api-version=2023-05-01-preview" \
        -H "Authorization: Bearer ${AZURE_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "credentialsExpireAfter": "PT1H",
            "purposes": ["tracing"],
            "apiId": "/subscriptions/'"${AZURE_SUB_ID}"'/resourceGroups/'"${AZURE_RG}"'/providers/Microsoft.ApiManagement/service/'"${AZURE_SERVICE}"'/apis/'"${api_name}"'"
        }')

    # Extract token from response
    debug_token=$(echo "$response" | grep -o '"token":"[^"]*"' | sed 's/"token":"//;s/"$//')

    if [ -z "$debug_token" ]; then
        echo "❌ Failed to get debug credentials" >&2
        echo "Response: $response" >&2
        exit 1
    fi

    # Save token to cache file
    echo "$debug_token" > "$AZURE_DEBUG_TOKEN_FILE"
    echo "✅ Debug credentials refreshed and cached for $api_name" >&2
}

# Function to refresh trace token
refresh_trace_token() {
    echo "🔄 Refreshing trace token..." >&2

    # Load Azure API token from cache or refresh if needed
    if is_token_expired "$AZURE_API_TOKEN_FILE"; then
        refresh_azure_api_token
    else
        AZURE_API_TOKEN=$(cat "$AZURE_API_TOKEN_FILE")
        echo "✅ Using cached Azure API token" >&2
    fi

    # Generate trace ID if not provided
    if [ -z "$AZURE_TRACE_ID" ]; then
        AZURE_TRACE_ID="test-trace-$(date +%s)"
    fi

    # Call listTrace API
    response=$(curl -s -X POST \
        "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/gateways/managed/listTrace?api-version=2023-05-01-preview" \
        -H "Authorization: Bearer ${AZURE_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{ "traceId": "'"${AZURE_TRACE_ID}"'" }')

    # Extract token from response
    trace_token=$(echo "$response" | grep -o '"value":"[^"]*"' | sed 's/"token":"//;s/"$//')

    if [ -z "$trace_token" ]; then
        echo "⚠️  Failed to get trace token, will try debug credentials instead" >&2
        refresh_debug_credentials
        trace_token=$(cat "$AZURE_DEBUG_TOKEN_FILE")
    fi

    echo "$trace_token"
}

# Function to get current debug token (refresh if expired)
get_debug_token() {
    local api_name="${1:-${AZURE_API_NAME}}"

    # Check if debug token exists and is not expired (50 minutes)
    if is_token_expired "$AZURE_DEBUG_TOKEN_FILE" 3000; then
        refresh_debug_credentials "$api_name"
    else
        echo "✅ Using cached debug credentials" >&2
    fi

    cat "$AZURE_DEBUG_TOKEN_FILE"
}

# Function to retrieve a trace by ID
get_trace() {
    local trace_id="$1"
    local output_file="$2"

    if [ -z "$trace_id" ] || [ -z "$output_file" ]; then
        echo "❌ Error: get-trace requires trace_id and output_file" >&2
        echo "Usage: $0 get-trace <trace_id> <output_file>" >&2
        return 1
    fi

    # Load Azure API token from cache or refresh if needed
    if is_token_expired "$AZURE_API_TOKEN_FILE"; then
        refresh_azure_api_token
    else
        AZURE_API_TOKEN=$(cat "$AZURE_API_TOKEN_FILE")
    fi

    # Ensure traces directory exists
    mkdir -p "$(dirname "$output_file")"

    # Retrieve trace from Azure APIM using POST with traceId in body
    response=$(curl -s -w "\n%{http_code}" -X POST \
        "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/gateways/managed/listTrace?api-version=2023-05-01-preview" \
        -H "Authorization: Bearer ${AZURE_API_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{ "traceId": "'"${trace_id}"'" }')

    # Extract HTTP code and body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    if [ "$http_code" != "200" ]; then
        echo "❌ Failed to retrieve trace (HTTP $http_code)" >&2
        echo "$body" >&2
        return 1
    fi

    # Save trace to file
    echo "$body" > "$output_file"
    return 0
}

# Main execution based on command line argument
case "${1:-}" in
    "azure-api")
        refresh_azure_api_token
        ;;
    "debug")
        refresh_debug_credentials "$2"
        ;;
    "trace")
        refresh_trace_token
        ;;
    "get-debug-token")
        get_debug_token "$2"
        ;;
    "get-trace")
        get_trace "$2" "$3"
        ;;
    *)
        echo "Usage: $0 {azure-api|debug|trace|get-debug-token|get-trace}"
        echo ""
        echo "Commands:"
        echo "  azure-api              - Refresh Azure API token"
        echo "  debug [api-name]       - Refresh debug credentials for API"
        echo "  trace                  - Refresh trace token"
        echo "  get-debug-token [api-name] - Get current debug token (refresh if needed)"
        echo "  get-trace <id> <file>  - Retrieve trace by ID and save to file"
        exit 1
        ;;
esac
