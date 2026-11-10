#!/bin/bash
# update-fragment.sh - Upload/update APIM policy fragment
# Syncs the local panw-airs-mcp-scan fragment to Azure APIM

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Load environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(dirname "$SCRIPT_DIR")"
POLICY_DIR="$(dirname "$TESTS_DIR")"
ENV_FILE="${TESTS_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}Error: .env file not found at $ENV_FILE${NC}"
    echo "Please copy env.sample to .env and configure it"
    exit 1
fi

source "$ENV_FILE"

# Validate required variables
if [ -z "$AZURE_SUB_ID" ] || [ -z "$AZURE_RG" ] || [ -z "$AZURE_SERVICE" ]; then
    echo -e "${RED}Error: Required variables not set in .env file${NC}"
    echo "Required: AZURE_SUB_ID, AZURE_RG, AZURE_SERVICE"
    exit 1
fi

# Fragment configuration
FRAGMENT_ID="${1:-panw-airs-mcp-scan}"
FRAGMENT_FILE="${POLICY_DIR}/${FRAGMENT_ID}"

if [ ! -f "$FRAGMENT_FILE" ]; then
    echo -e "${RED}Error: Fragment file not found: $FRAGMENT_FILE${NC}"
    exit 1
fi

echo -e "${BLUE}📤 Uploading policy fragment to Azure APIM${NC}"
echo "  Subscription: ${AZURE_SUB_ID}"
echo "  Resource Group: ${AZURE_RG}"
echo "  APIM Service: ${AZURE_SERVICE}"
echo "  Fragment ID: ${FRAGMENT_ID}"
echo "  Source File: ${FRAGMENT_FILE}"
echo ""

# Check Azure CLI authentication
if ! az account show > /dev/null 2>&1; then
    echo -e "${RED}❌ Not logged into Azure CLI${NC}"
    echo "Run: az login"
    exit 1
fi

# Read fragment content and escape for JSON
FRAGMENT_CONTENT=$(cat "$FRAGMENT_FILE" | jq -Rs .)

# Build JSON payload
PAYLOAD=$(cat <<EOF
{
  "properties": {
    "description": "Prisma AIRS MCP scanning policy fragment - scans tool inputs and outputs",
    "format": "xml",
    "value": ${FRAGMENT_CONTENT}
  }
}
EOF
)

echo -e "${YELLOW}Creating/updating fragment...${NC}"

# Use Azure REST API to create/update the fragment
RESPONSE=$(az rest \
    --method PUT \
    --url "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/policyFragments/${FRAGMENT_ID}?api-version=2023-05-01-preview" \
    --body "$PAYLOAD" \
    2>&1)

EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo -e "${RED}❌ Failed to upload fragment${NC}"
    echo "$RESPONSE"
    exit 1
fi

# Check for immediate errors in response
ERROR_CODE=$(echo "$RESPONSE" | jq -r '.error.code // empty' 2>/dev/null)
if [ -n "$ERROR_CODE" ]; then
    echo -e "${RED}❌ API returned error: ${ERROR_CODE}${NC}"
    ERROR_MSG=$(echo "$RESPONSE" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
    echo -e "${RED}   ${ERROR_MSG}${NC}"

    # Show details if available
    ERROR_DETAILS=$(echo "$RESPONSE" | jq -r '.error.details[]?.message // empty' 2>/dev/null)
    if [ -n "$ERROR_DETAILS" ]; then
        echo -e "${RED}   Details:${NC}"
        echo "$ERROR_DETAILS" | while read -r line; do
            echo -e "${RED}     - $line${NC}"
        done
    fi
    exit 1
fi

# Check if it's an async operation (status 201 with ProvisioningState)
PROVISIONING_STATE=$(echo "$RESPONSE" | jq -r '.properties.ProvisioningState // "Succeeded"' 2>/dev/null)

if [ "$PROVISIONING_STATE" = "InProgress" ]; then
    echo -e "${YELLOW}⏳ Waiting for provisioning to complete...${NC}"

    # Poll for completion (max 30 seconds)
    for i in {1..30}; do
        sleep 1
        STATUS=$(az rest \
            --method GET \
            --url "https://management.azure.com/subscriptions/${AZURE_SUB_ID}/resourceGroups/${AZURE_RG}/providers/Microsoft.ApiManagement/service/${AZURE_SERVICE}/policyFragments/${FRAGMENT_ID}?api-version=2023-05-01-preview" \
            2>/dev/null)

        # Check for errors during polling
        POLL_ERROR=$(echo "$STATUS" | jq -r '.error.code // empty' 2>/dev/null)
        if [ -n "$POLL_ERROR" ]; then
            echo -e "${RED}❌ Fragment provisioning failed${NC}"
            ERROR_MSG=$(echo "$STATUS" | jq -r '.error.message // "Unknown error"' 2>/dev/null)
            echo -e "${RED}   ${ERROR_MSG}${NC}"

            # Extract validation errors if present
            VALIDATION_ERRORS=$(echo "$STATUS" | jq -r '.error.details[]? | select(.code == "ValidationError") | .message' 2>/dev/null)
            if [ -n "$VALIDATION_ERRORS" ]; then
                echo -e "${RED}   Validation Errors:${NC}"
                echo "$VALIDATION_ERRORS" | while read -r line; do
                    echo -e "${RED}     • $line${NC}"
                done
            fi
            exit 1
        fi

        STATE=$(echo "$STATUS" | jq -r '.properties.ProvisioningState // "Succeeded"' 2>/dev/null)

        # Check for Failed state
        if [ "$STATE" = "Failed" ]; then
            echo -e "${RED}❌ Fragment provisioning failed${NC}"
            echo "$STATUS" | jq '.properties' 2>/dev/null || echo "$STATUS"
            exit 1
        fi

        if [ "$STATE" != "InProgress" ]; then
            RESPONSE="$STATUS"
            break
        fi

        if [ $((i % 5)) -eq 0 ]; then
            echo -e "${YELLOW}  Still provisioning... (${i}s)${NC}"
        fi
    done

    # Check if we timed out
    if [ "$STATE" = "InProgress" ]; then
        echo -e "${YELLOW}⚠️  Provisioning still in progress after 30s${NC}"
        echo -e "${YELLOW}   The fragment may still be deploying in the background${NC}"
        echo -e "${YELLOW}   Check Azure Portal to verify final status${NC}"
    fi
fi

# Final status check
FINAL_STATE=$(echo "$RESPONSE" | jq -r '.properties.ProvisioningState // "Unknown"' 2>/dev/null)

if [ "$FINAL_STATE" = "Succeeded" ] || [ "$FINAL_STATE" = "Unknown" ]; then
    echo -e "${GREEN}✅ Policy fragment uploaded successfully${NC}"
    echo ""
    echo -e "${BLUE}Fragment Details:${NC}"
    echo "$RESPONSE" | jq '{
        id: .id,
        name: .name,
        description: .properties.description,
        format: .properties.format,
        provisioningState: .properties.ProvisioningState
    }' 2>/dev/null || echo "$RESPONSE"
elif [ "$FINAL_STATE" = "Failed" ]; then
    echo -e "${RED}❌ Fragment provisioning failed${NC}"
    echo ""
    echo -e "${RED}Full response:${NC}"
    echo "$RESPONSE" | jq '.' 2>/dev/null || echo "$RESPONSE"
    exit 1
else
    echo -e "${YELLOW}⚠️  Unexpected provisioning state: ${FINAL_STATE}${NC}"
    echo "$RESPONSE" | jq '.'
    exit 1
fi

echo ""
echo -e "${GREEN}✅ Done!${NC}"
echo ""
echo "Next steps:"
echo "  1. Verify in Azure Portal: API Management → APIs → Policy Fragments"
echo "  2. Test the fragment by referencing it in an API policy and sending test requests"
