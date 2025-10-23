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
if [ -z "$MY_AIRS_API_KEY" ] || [ -z "$AWS_ACCESS_KEY_ID" ] || [ -z "$AWS_SECRET_ACCESS_KEY" ] || [ -z "$AWS_REGION" ]; then
    echo "Error: Make sure MY_AIRS_API_KEY, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION are set."
    exit 1
fi

# Store the config in a variable
CONFIG=$(cat <<EOM | jq -c .
{
    "provider": "bedrock",
    "aws_access_key_id": "$AWS_ACCESS_KEY_ID",
    "aws_secret_access_key": "$AWS_SECRET_ACCESS_KEY",
    "aws_region": "$AWS_REGION",
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
echo Sending \"$USER_CONTENT\" to Portkey with AWS Bedrock...
curl -X POST http://localhost:8787/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "x-portkey-config: $CONFIG" \
    -d "{
            \"model\": \"anthropic.claude-3-haiku-20240307-v1:0\",
            \"messages\": [{\"role\": \"user\", \"content\": \"$USER_CONTENT\" }]
        }" | jq .