#!/usr/bin/env bash
# Deploy a model from Vertex AI Model Garden to a Vertex AI endpoint.
# Reads configuration from config/model-config.yaml.
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-config/model-config.yaml}"

# Parse configuration values from YAML
MODEL_ID=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['model']['huggingface_id'])")
DISPLAY_NAME=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['model']['display_name'])")
MACHINE_TYPE=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['deployment']['machine_type'])")
ACCEL_TYPE=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['deployment']['accelerator_type'])")
ACCEL_COUNT=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['deployment']['accelerator_count'])")
REGION="${GCP_REGION:-us-central1}"
PROJECT="${GCP_PROJECT_ID:?ERROR: GCP_PROJECT_ID environment variable is required}"

ENDPOINT_DISPLAY_NAME="${DISPLAY_NAME}-secure"

echo "============================================================"
echo "  Deploying Model to Vertex AI"
echo "============================================================"
echo "  Model:         ${MODEL_ID}"
echo "  Display Name:  ${ENDPOINT_DISPLAY_NAME}"
echo "  Machine Type:  ${MACHINE_TYPE}"
echo "  Accelerator:   ${ACCEL_TYPE} x ${ACCEL_COUNT}"
echo "  Region:        ${REGION}"
echo "  Project:       ${PROJECT}"
echo "============================================================"

gcloud config set project "${PROJECT}"

# Clean up any existing endpoint with the same display name to avoid duplicates
EXISTING_ENDPOINT=$(gcloud ai endpoints list \
  --region="${REGION}" \
  --filter="displayName=${ENDPOINT_DISPLAY_NAME}" \
  --format="value(name)" | head -1 | awk -F/ '{print $NF}')

if [ -n "${EXISTING_ENDPOINT}" ]; then
  echo "Found existing endpoint: ${EXISTING_ENDPOINT}"
  echo "Cleaning up before redeploying..."
  DEPLOYED_MODEL_IDS=$(gcloud ai endpoints describe "${EXISTING_ENDPOINT}" \
    --region="${REGION}" \
    --format="value(deployedModels.id)" 2>/dev/null || true)
  for dm_id in ${DEPLOYED_MODEL_IDS}; do
    echo "  Undeploying model: ${dm_id}"
    gcloud ai endpoints undeploy-model "${EXISTING_ENDPOINT}" \
      --region="${REGION}" \
      --deployed-model-id="${dm_id}" \
      --quiet
  done
  echo "  Deleting endpoint: ${EXISTING_ENDPOINT}"
  gcloud ai endpoints delete "${EXISTING_ENDPOINT}" \
    --region="${REGION}" \
    --quiet
  echo "Cleanup complete."
  echo ""
fi

gcloud ai model-garden models deploy \
  --model="${MODEL_ID}" \
  --machine-type="${MACHINE_TYPE}" \
  --accelerator-type="${ACCEL_TYPE}" \
  --accelerator-count="${ACCEL_COUNT}" \
  --region="${REGION}" \
  --endpoint-display-name="${ENDPOINT_DISPLAY_NAME}" \
  --hugging-face-access-token="${HF_TOKEN:-}" \
  --accept-eula

echo ""
echo "Model deployed successfully."
echo "Endpoint display name: ${ENDPOINT_DISPLAY_NAME}"
echo ""
echo "To test the endpoint, run:"
echo "  python scripts/test_model.py --config ${CONFIG_FILE}"
