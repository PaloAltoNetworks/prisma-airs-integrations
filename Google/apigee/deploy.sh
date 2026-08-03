#!/bin/bash
set -eo pipefail

# Load environment variables (check local first, then parent)
if [ -f .env ]; then
  source .env
elif [ -f ../.env ]; then
  source ../.env
fi

# Required variables
ORG="${APIGEE_ORG:-YOUR_APIGEE_ORG}"
ENV="${APIGEE_ENV:-eval}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-YOUR_GCP_PROJECT_ID}"

# Prisma AIRS configuration
PRISMA_AIRS_API_KEY="${PRISMA_AIRS_API_KEY}"
PRISMA_AIRS_PROFILE_NAME="${PRISMA_AIRS_PROFILE_NAME}"
PRISMA_AIRS_HOST="${PRISMA_AIRS_HOST:-service.api.aisecurity.paloaltonetworks.com}"

# Deployment service account (email only — no key file). Apigee mgmt API
# deploys "as" this SA via the deployments endpoint's serviceAccount= param;
# your own gcloud identity just needs iam.serviceAccounts.actAs on it.
DEPLOY_SA="${DEPLOY_SA}"

# Validate required secrets/credentials
if [[ -z "$PRISMA_AIRS_API_KEY" ]]; then
  echo "ERROR: PRISMA_AIRS_API_KEY is not set"
  exit 1
fi

if [[ -z "$PRISMA_AIRS_PROFILE_NAME" ]]; then
  echo "ERROR: PRISMA_AIRS_PROFILE_NAME is not set"
  exit 1
fi

if [[ -z "$DEPLOY_SA" ]]; then
  echo "ERROR: DEPLOY_SA is not set (deployment service account email, e.g. sa-apigee-dev@$PROJECT_ID.iam.gserviceaccount.com)"
  exit 1
fi

# Vertex AI configuration
VERTEX_PROJECT="${PROJECT_ID}"
VERTEX_MODEL="${VERTEX_MODEL:-gemini-2.5-flash}"

echo "=========================================="
echo "Deploying vertex-simple to Apigee"
echo "=========================================="
echo "Organization: $ORG"
echo "Environment: $ENV"
echo "Project: $PROJECT_ID"
echo "Vertex Model: $VERTEX_MODEL"
echo "AIRS Profile: $PRISMA_AIRS_PROFILE_NAME"
echo ""

# Step 1: Create or update KVM (pure REST — no apigeecli dependency)
echo "== Setting up KVM =="
AUTH_TOKEN=$(gcloud auth print-access-token)
KVM_PATH="/organizations/$ORG/environments/$ENV/keyvaluemaps"

KVM_STATUS=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $AUTH_TOKEN" \
  "https://apigee.googleapis.com/v1${KVM_PATH}/private")
if [[ "$KVM_STATUS" == "200" ]]; then
  echo "OK: KVM 'private' already exists"
else
  CREATE_RESP=$(curl -sS -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" \
    -d '{"name":"private","encrypted":true}' \
    -w "\n%{http_code}" \
    "https://apigee.googleapis.com/v1${KVM_PATH}")
  CREATE_CODE="${CREATE_RESP##*$'\n'}"
  [[ "$CREATE_CODE" =~ ^(200|201)$ ]] || { echo "ERROR: KVM create failed (HTTP $CREATE_CODE): ${CREATE_RESP%$'\n'*}"; exit 1; }
  echo "OK: KVM 'private' created (encrypted)"
fi

# Helper function to upsert a KVM entry via the Management API directly.
update_kvm_entry() {
  local key=$1 value=$2
  local entry_path="https://apigee.googleapis.com/v1${KVM_PATH}/private/entries/$key"
  local payload
  payload=$(jq -n --arg n "$key" --arg v "$value" '{name:$n, value:$v}')

  local entry_status
  entry_status=$(curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $AUTH_TOKEN" "$entry_path")

  local resp code
  if [[ "$entry_status" == "200" ]]; then
    resp=$(curl -sS -X PUT -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" \
      -d "$payload" -w "\n%{http_code}" "$entry_path")
  else
    resp=$(curl -sS -X POST -H "Authorization: Bearer $AUTH_TOKEN" -H "Content-Type: application/json" \
      -d "$payload" -w "\n%{http_code}" "https://apigee.googleapis.com/v1${KVM_PATH}/private/entries")
  fi
  code="${resp##*$'\n'}"
  [[ "$code" =~ ^(200|201)$ ]] || { echo "ERROR: KVM entry $key upsert failed (HTTP $code): ${resp%$'\n'*}"; exit 1; }
}

echo "Setting KVM entries..."
update_kvm_entry "prisma.airs.token" "$PRISMA_AIRS_API_KEY"
update_kvm_entry "prisma.airs.profile" "$PRISMA_AIRS_PROFILE_NAME"
update_kvm_entry "prisma.airs.host" "$PRISMA_AIRS_HOST"
update_kvm_entry "vertex.project" "$VERTEX_PROJECT"
update_kvm_entry "vertex.model" "$VERTEX_MODEL"

echo "OK: KVM configured"
echo ""

# Step 2: Verify Vertex AI permissions
echo "== Verifying Vertex AI access =="
RUNTIME_SA=$(gcloud apigee environments describe "$ENV" --organization="$ORG" --format="value(properties.runtimeServiceAccount)")

if [[ -n "$RUNTIME_SA" ]]; then
  echo "Runtime SA: $RUNTIME_SA"
  echo "Checking if SA has roles/aiplatform.user on $PROJECT_ID..."
  
  # Check IAM policy - fail fast if gcloud command fails
  HAS_VERTEX_ROLE=$(gcloud projects get-iam-policy "$PROJECT_ID" \
    --flatten="bindings[].members" \
    --filter="bindings.members:serviceAccount:$RUNTIME_SA AND bindings.role:roles/aiplatform.user" \
    --format="value(bindings.role)")
  
  if [[ -n "$HAS_VERTEX_ROLE" ]]; then
    echo "OK: Runtime SA has Vertex AI access"
  else
    echo "WARN: Runtime SA needs roles/aiplatform.user on $PROJECT_ID"
    
    if [[ "${SKIP_IAM_GRANT:-}" == "1" ]]; then
      echo "  SKIP_IAM_GRANT=1, skipping automatic grant."
      echo "  Grant it manually with:"
      echo "  gcloud projects add-iam-policy-binding $PROJECT_ID \\"
      echo "    --member=serviceAccount:$RUNTIME_SA \\"
      echo "    --role=roles/aiplatform.user"
      echo ""
      echo "  Continuing deployment (may fail if SA lacks access)..."
    else
      echo "  Granting automatically (set SKIP_IAM_GRANT=1 to skip)..."
      gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:$RUNTIME_SA" \
        --role="roles/aiplatform.user" \
        --condition=None
      echo "OK: Granted roles/aiplatform.user to runtime SA"
    fi
  fi
else
  echo "WARN: Could not determine runtime SA - ensure it has Vertex AI access"
fi
echo ""

# Step 3: Package and deploy
echo "== Packaging proxy =="
cd "$(dirname "$0")"
rm -f vertex-simple.zip
zip -r vertex-simple.zip apiproxy -q
echo "OK: Created vertex-simple.zip"
echo ""

echo "== Deploying to Apigee =="
AUTH_TOKEN=$(gcloud auth print-access-token)

# Import the proxy
IMPORT_RESPONSE=$(curl -s -X POST \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: multipart/form-data" \
  "https://apigee.googleapis.com/v1/organizations/$ORG/apis?name=vertex-simple&action=import" \
  -F "file=@vertex-simple.zip")

# Check for error in response
if echo "$IMPORT_RESPONSE" | grep -q '"error"'; then
  echo "ERROR: Failed to import proxy"
  echo "$IMPORT_RESPONSE"
  exit 1
fi

REVISION=$(echo "$IMPORT_RESPONSE" | jq -r '.revision')

echo "OK: Imported as revision $REVISION"

# Deploy the proxy with service account (email only — see DEPLOY_SA above).
# override=true auto-undeploys any older revision of this proxy in the env.
echo "Deploying revision $REVISION with SA: $DEPLOY_SA..."
DEPLOY_RESP=$(curl -sS -X POST -H "Authorization: Bearer $AUTH_TOKEN" \
  -w "\n%{http_code}" \
  "https://apigee.googleapis.com/v1/organizations/$ORG/environments/$ENV/apis/vertex-simple/revisions/$REVISION/deployments?override=true&serviceAccount=$DEPLOY_SA")
DEPLOY_CODE="${DEPLOY_RESP##*$'\n'}"
[[ "$DEPLOY_CODE" =~ ^(200|201)$ ]] || { echo "ERROR: Deploy failed (HTTP $DEPLOY_CODE): ${DEPLOY_RESP%$'\n'*}"; exit 1; }
echo "OK: Deploy request accepted (may take a few seconds to become ACTIVE)"

echo ""
echo "=========================================="
echo "OK: Deployment complete!"
echo "=========================================="
echo ""
echo "Test with:"
echo ""
if [[ -n "${HOSTNAME:-}" ]]; then
  echo "curl -i \\"
  echo "  -H \"Content-Type: application/json\" \\"
  echo "  -X POST \\"
  echo "  https://${HOSTNAME}/vertex \\"
  echo "  -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Write a haiku\"}]}]}'"
else
  echo "curl -i -k \\"
  echo "  -H \"Host: api.$ORG.internal\" \\"
  echo "  -H \"Content-Type: application/json\" \\"
  echo "  -X POST \\"
  echo "  https://YOUR_PSC_IP/vertex \\"
  echo "  -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Write a haiku\"}]}]}'"
  echo ""
  echo "(Set HOSTNAME in .env to print a ready-to-use curl next time.)"
fi
echo ""

