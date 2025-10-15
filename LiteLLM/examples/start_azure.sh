#! /bin/bash
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

podman stop litellm-proxy-azure && podman rm litellm-proxy-azure

podman run -d \
    -v $(pwd)/config-azure.yaml:/app/config.yaml \
    -e AZURE_API_KEY=$AZURE_OPENAI_API_KEY \
    -e AZURE_API_BASE=https://$AZURE_RESOURCE.openai.azure.com/\
    -e LITELLM_ADMIN_KEY="sk-1234" \
    -p 4000:4000 \
    --name litellm-proxy-azure \
    ghcr.io/berriai/litellm:main-stable \
    --config /app/config.yaml --detailed_debug

# RUNNING on http://0.0.0.0:4000
echo "LiteLLM Azure proxy running on http://0.0.0.0:4000"