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
if [ -z "$MY_AIRS_API_KEY" ] || [ -z "$GOOGLE_CLOUD_PROJECT_ID" ] || [ -z "$GOOGLE_CLOUD_REGION" ] || [ -z "$VERTEX_SERVICE_ACCOUNT_FILE" ]; then
    echo "Error: Make sure MY_AIRS_API_KEY, GOOGLE_CLOUD_PROJECT_ID, GOOGLE_CLOUD_REGION, and VERTEX_SERVICE_ACCOUNT_FILE are set in your .env file."
    exit 1
fi

# Expand the tilde (~) if it is in the file path
SERVICE_ACCOUNT_FILE_PATH=$(eval echo "$VERTEX_SERVICE_ACCOUNT_FILE")

# Check if the service account file exists
if [ ! -f "$SERVICE_ACCOUNT_FILE_PATH" ]; then
    echo "Error: Service account file not found at $SERVICE_ACCOUNT_FILE_PATH"
    exit 1
fi

# Read the service account file and escape it for JSON using jq
SERVICE_ACCOUNT_JSON=$(jq -R -s . "$SERVICE_ACCOUNT_FILE_PATH")

# Store the config in a variable
CONFIG=$(cat <<EOM | jq -c .
{
    "provider": "vertex-ai",
    "vertex_project_id": "$GOOGLE_CLOUD_PROJECT_ID",
    "vertex_region": "$GOOGLE_CLOUD_REGION",
    "vertex_service_account_json": $(cat "$SERVICE_ACCOUNT_FILE_PATH"),
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

# Make a request to the gateway
echo Sending \"$USER_CONTENT\" to Portkey with Vertex AI...
curl -X POST http://localhost:8787/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "x-portkey-config: $CONFIG" \
    -d '{
            "model": "gemini-2.5-flash",
            "messages": [{"role": "user", "content": "$USER_CONTENT"}]
        }' | jq .