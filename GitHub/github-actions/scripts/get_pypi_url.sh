#!/bin/bash
#
# Model Security Private PyPI Authentication Script
# Authenticates with SCM and retrieves PyPI repository URL
#

set -euo pipefail

# Check required environment variables
: "${MODEL_SECURITY_CLIENT_ID:?Error: MODEL_SECURITY_CLIENT_ID not set}"
: "${MODEL_SECURITY_CLIENT_SECRET:?Error: MODEL_SECURITY_CLIENT_SECRET not set}"
: "${TSG_ID:?Error: TSG_ID not set}"

# Set default endpoints
API_ENDPOINT="${MODEL_SECURITY_API_ENDPOINT:-https://api.sase.paloaltonetworks.com/aims}"
TOKEN_ENDPOINT="${MODEL_SECURITY_TOKEN_ENDPOINT:-https://auth.apps.paloaltonetworks.com/oauth2/access_token}"

# Get SCM access token
TOKEN_RESPONSE=$(curl -sf -X POST "$TOKEN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u "$MODEL_SECURITY_CLIENT_ID:$MODEL_SECURITY_CLIENT_SECRET" \
    -d "grant_type=client_credentials&scope=tsg_id:$TSG_ID") || {
    echo "Error: Failed to obtain SCM access token" >&2
    exit 1
}

SCM_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
if [[ -z "$SCM_TOKEN" || "$SCM_TOKEN" == "null" ]]; then
    echo "Error: Failed to extract access token from response" >&2
    exit 1
fi

# Get PyPI URL
PYPI_RESPONSE=$(curl -sf -X GET "$API_ENDPOINT/mgmt/v1/pypi/authenticate" \
    -H "Authorization: Bearer $SCM_TOKEN") || {
    echo "Error: Failed to retrieve PyPI URL" >&2
    exit 1
}

PYPI_URL=$(echo "$PYPI_RESPONSE" | jq -r '.url')
if [[ -z "$PYPI_URL" || "$PYPI_URL" == "null" ]]; then
    echo "Error: Failed to extract PyPI URL from response" >&2
    exit 1
fi

echo "$PYPI_URL"
