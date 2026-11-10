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

podman stop litellm-proxy-aws && podman rm litellm-proxy-aws

# Run the new container with AWS environment variables
podman run -d \
  -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  -e AWS_REGION_NAME="$AWS_REGION" \
  -e LITELLM_ADMIN_KEY="sk-1234" \
  -v $(pwd)/config-aws.yaml:/app/config.yaml \
  -p 4000:4000 \
  --name litellm-proxy-aws \
  ghcr.io/berriai/litellm:main-stable \
  --config /app/config.yaml