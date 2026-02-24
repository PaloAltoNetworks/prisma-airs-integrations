#!/bin/bash
set -eo pipefail

# Load environment variables (check local first, then parent)
if [ -f .env ]; then
  source .env
elif [ -f ../.env ]; then
  source ../.env
fi

# Required variables
ORG="${APIGEE_ORG:-panw-gcp-team-testing}"
ENV="${APIGEE_ENV:-eval}"
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-panw-gcp-team-testing}"

# Prisma AIRS configuration
AIRS_TOKEN="${PANW_PRISMA_AIRS_API_KEY}"
AIRS_PROFILE="${AIRS_API_PROFILE_NAME:-default}"

# Validate required secrets/credentials
if [[ -z "$AIRS_TOKEN" ]]; then
  echo "❌ PANW_PRISMA_AIRS_API_KEY is not set"
  exit 1
fi

if [[ ! -f "$GOOGLE_APPLICATION_CREDENTIALS" ]]; then
  echo "❌ GOOGLE_APPLICATION_CREDENTIALS not found: $GOOGLE_APPLICATION_CREDENTIALS"
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
echo "AIRS Profile: $AIRS_PROFILE"
echo ""

# Step 1: Create or update KVM
echo "== Setting up KVM =="
apigeecli kvms create -o "$ORG" -e "$ENV" --name private 2>/dev/null || echo "✓ KVM 'private' already exists"

# Helper function to update KVM entry
update_kvm_entry() {
  local key=$1
  local value=$2
  
  # Delete if exists
  apigeecli kvms entries delete -o "$ORG" -e "$ENV" --map private --key "$key" &>/dev/null || true
  
  # Create new entry
  apigeecli kvms entries create -o "$ORG" -e "$ENV" --map private --key "$key" --value "$value"
}

echo "Setting KVM entries..."
update_kvm_entry "airs.token" "$AIRS_TOKEN"
update_kvm_entry "airs.profile" "$AIRS_PROFILE"
update_kvm_entry "vertex.project" "$VERTEX_PROJECT"
update_kvm_entry "vertex.model" "$VERTEX_MODEL"

echo "✓ KVM configured"
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
    echo "✓ Runtime SA has Vertex AI access"
  else
    echo "⚠ Runtime SA needs roles/aiplatform.user on $PROJECT_ID"
    
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
      echo "✓ Granted roles/aiplatform.user to runtime SA"
    fi
  fi
else
  echo "⚠ Could not determine runtime SA - ensure it has Vertex AI access"
fi
echo ""

# Step 3: Package and deploy
echo "== Packaging proxy =="
cd "$(dirname "$0")"
rm -f vertex-simple.zip
zip -r vertex-simple.zip apiproxy -q
echo "✓ Created vertex-simple.zip"
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
  echo "❌ Failed to import proxy"
  echo "$IMPORT_RESPONSE"
  exit 1
fi

REVISION=$(echo "$IMPORT_RESPONSE" | jq -r '.revision')

echo "✓ Imported as revision $REVISION"

# Deploy the proxy with service account
# Use the deployment SA (from GOOGLE_APPLICATION_CREDENTIALS)
DEPLOY_SA=$(jq -r '.client_email' "$GOOGLE_APPLICATION_CREDENTIALS")
echo "Deploying revision $REVISION with SA: $DEPLOY_SA..."
apigeecli apis deploy -o "$ORG" -e "$ENV" -n vertex-simple --rev "$REVISION" --sa "$DEPLOY_SA" --ovr --wait 2>&1 | tail -2

echo ""
echo "=========================================="
echo "✅ Deployment complete!"
echo "=========================================="
echo ""
echo "Test with:"
echo ""
echo "curl -i -k \\"
echo "  -H \"Host: api.$ORG.internal\" \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -X POST \\"
echo "  https://YOUR_PSC_IP/vertex \\"
echo "  -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Write a haiku\"}]}]}'"
echo ""

