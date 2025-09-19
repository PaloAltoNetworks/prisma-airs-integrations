#! /bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# Error out if no arguments are provided
if [ $# -eq 0 ]; then
    echo "Error: No message content provided. Please pass your message as arguments to the script."
    exit 1
fi

# Load environment variables from .env file
if [ -f .env ]; then
    set -a # Automatically export all variables
    USER_CONTENT="$*"
    source .env
    set +a
else
    echo ".env file not found!"
    exit 1
fi

# Check if the required variables are set
if [ -z "$MY_AIRS_API_KEY" ] ||[ -z "$AZURE_OPENAI_API_KEY" ] || [ -z "$AZURE_RESOURCE" ] || [ -z "$AZURE_DEPLOYMENT" ] || [ -z "$AZURE_API_VERSION" ]; then
    echo "Error: Make sure MY_AIRS_API_KEY, AZURE_OPENAI_API_KEY, AZURE_RESOURCE, AZURE_DEPLOYMENT and AZURE_API_VERSION are set."
    exit 1
fi

CONFIG=$(cat <<EOM | jq -c .
{
    "input_guardrails": [
        {
            "deny": true,
            "panw-prisma-airs.intercept": {
                "profile_name": "prompt-profile",
                "credentials": {
                    "AIRS_API_KEY": "$MY_AIRS_API_KEY"
                }
            }
        }
    ],
    "output_guardrails": [
        {
            "deny": true,
            "panw-prisma-airs.intercept": {
                "profile_name": "response-profile",
                "credentials": {
                    "AIRS_API_KEY": "$MY_AIRS_API_KEY"
                }
            }
        }
    ]
}
EOM
)

echo Sending \"$USER_CONTENT\" to Portkey with Azure OpenAI...
curl -s http://127.0.0.1:8787/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "x-portkey-provider: azure-openai" \
    -H "Authorization: $AZURE_OPENAI_API_KEY" \
    -H "x-portkey-azure-resource-name: $AZURE_RESOURCE" \
    -H "x-portkey-azure-deployment-id: $AZURE_DEPLOYMENT" \
    -H "x-portkey-azure-api-version: $AZURE_API_VERSION" \
    -H "x-portkey-config: $CONFIG" \
    -d "{
        \"model\": \"gpt4.0-mini\",
        \"messages\": [{\"role\": \"user\", \"content\": \"$USER_CONTENT\" }]
    }" | jq .


