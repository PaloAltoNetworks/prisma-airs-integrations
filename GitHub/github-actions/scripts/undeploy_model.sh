#!/usr/bin/env bash
# Undeploy and clean up a Vertex AI model endpoint to stop incurring GPU costs.
# Usage: GCP_PROJECT_ID=your-project GCP_REGION=us-central1 ./scripts/undeploy_model.sh
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config/model-config.yaml}"

DISPLAY_NAME=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['model']['display_name'])")
ENDPOINT_DISPLAY_NAME="${DISPLAY_NAME}-secure"
REGION="${GCP_REGION:-us-central1}"
PROJECT="${GCP_PROJECT_ID:?ERROR: Set GCP_PROJECT_ID environment variable}"

echo "Looking for endpoint: ${ENDPOINT_DISPLAY_NAME}"
echo "  Project: ${PROJECT}"
echo "  Region:  ${REGION}"

ENDPOINT_IDS=$(gcloud ai endpoints list \
  --project="${PROJECT}" \
  --region="${REGION}" \
  --filter="displayName~${ENDPOINT_DISPLAY_NAME}" \
  --format="value(name)" | awk -F/ '{print $NF}')

if [ -z "${ENDPOINT_IDS}" ]; then
  echo "No matching endpoints found. Nothing to clean up."
  exit 0
fi

for ENDPOINT_ID in ${ENDPOINT_IDS}; do
  echo "Found endpoint: ${ENDPOINT_ID}"
  echo "Undeploying all models from the endpoint..."

  DEPLOYED_MODEL_IDS=$(gcloud ai endpoints describe "${ENDPOINT_ID}" \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --format="value(deployedModels.id)" 2>/dev/null || true)

  for dm_id in ${DEPLOYED_MODEL_IDS}; do
    echo "  Undeploying model: ${dm_id}"
    gcloud ai endpoints undeploy-model "${ENDPOINT_ID}" \
      --project="${PROJECT}" \
      --region="${REGION}" \
      --deployed-model-id="${dm_id}" \
      --quiet
  done

  echo "Deleting endpoint: ${ENDPOINT_ID}"
  gcloud ai endpoints delete "${ENDPOINT_ID}" \
    --project="${PROJECT}" \
    --region="${REGION}" \
    --quiet

  echo "Endpoint ${ENDPOINT_ID} deleted."
done

echo "All matching endpoints cleaned up. GPU costs stopped."
