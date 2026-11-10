# Stop and remove any old container first
set -e

# Load environment variables from .env file
if [ -f .env ]; then
    set -a # Automatically export all variables
    source .env
    set +a
else
    echo ".env file not found!"
    exit 1
fi

podman stop litellm-proxy-all && podman rm litellm-proxy-all

# Run the new container with AWS environment variables
podman run -d \
    -e AZURE_API_KEY=$AZURE_OPENAI_API_KEY \
    -e AZURE_API_BASE=https://$AZURE_RESOURCE.openai.azure.com/\
    -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
    -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
    -e AWS_REGION_NAME="$AWS_REGION" \
    -e AIRS_API_KEY="$MY_AIRS_API_KEY" \
    -e LITELLM_ADMIN_KEY="$LITELLM_ADMIN_KEY" \
    -v $(pwd)/config-all.yaml:/app/config.yaml \
    -p 4000:4000 \
    --name litellm-proxy-all \
    ghcr.io/berriai/litellm:main-stable \
    --config /app/config.yaml