#!/usr/bin/env bash
# provision.sh — full provisioning of the AIRS-on-Apigee reference pattern.
#
# Runs inside the Cloud Run Job container. All configuration arrives as
# environment variables (set on the Job by cloudbuild.yaml; secrets injected
# from Secret Manager). There are no CLI arguments.
#
# Phases:
#   1. Enable required GCP APIs
#   2. Create / verify the Vertex service account + IAM bindings
#   3. (guarded) Create / verify the AIRS security profile via the mgmt API
#   4. Upsert the encrypted Apigee KVM `airs-config`
#   5. Import + deploy the PANW-AIRS SharedFlow
#   6. Import + deploy the vertex-airs-sync proxy
#
# Every phase is idempotent — safe to re-run on every pipeline trigger.

set -euo pipefail

# ----- config from environment ----------------------------------------------

PROJECT="${PROJECT:-}"
REGION="${REGION:-us-central1}"
APIGEE_ORG="${APIGEE_ORG:-$PROJECT}"
APIGEE_ENV="${APIGEE_ENV:-}"
VERTEX_SA="${VERTEX_SA:-}"
AIRS_PROFILE="${AIRS_PROFILE:-}"
AIRS_TOKEN="${AIRS_TOKEN:-}"
ENVGROUP_HOSTNAME="${ENVGROUP_HOSTNAME:-}"

# Guarded optional: AIRS security-profile creation. Off unless explicitly set.
CREATE_AIRS_PROFILE="${CREATE_AIRS_PROFILE:-0}"
AIRS_MGMT_TOKEN="${AIRS_MGMT_TOKEN:-}"
AIRS_MGMT_API="${AIRS_MGMT_API:-}"

# ----- constants ------------------------------------------------------------

SHAREDFLOW_NAME="PANW-AIRS"
SYNC_PROXY_NAME="vertex-airs-sync"
SHAREDFLOW_SRC="/app/bundles/PANW-AIRS"
SYNC_PROXY_SRC="/app/bundles/vertex-airs-sync"
KVM_NAME="airs-config"
APIGEE_API="https://apigee.googleapis.com/v1"

REQUIRED_APIS=(
  apigee.googleapis.com
  aiplatform.googleapis.com
  iam.googleapis.com
  serviceusage.googleapis.com
)

# ----- output helpers -------------------------------------------------------

step() { printf "\n\033[1;34m▶ %s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }
die()  { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

# ----- validation -----------------------------------------------------------

[[ -n "$PROJECT"      ]] || die "PROJECT not set"
[[ -n "$APIGEE_ENV"   ]] || die "APIGEE_ENV not set"
[[ -n "$VERTEX_SA"    ]] || die "VERTEX_SA not set"
[[ -n "$AIRS_PROFILE" ]] || die "AIRS_PROFILE not set"
[[ -n "$AIRS_TOKEN"   ]] || die "AIRS_TOKEN not set (expected from Secret Manager)"

command -v gcloud >/dev/null || die "gcloud not on PATH"
command -v jq     >/dev/null || die "jq not on PATH"
command -v zip    >/dev/null || die "zip not on PATH"
command -v curl   >/dev/null || die "curl not on PATH"

[[ -d "$SHAREDFLOW_SRC" ]] || die "Missing bundle dir $SHAREDFLOW_SRC"
[[ -d "$SYNC_PROXY_SRC" ]] || die "Missing bundle dir $SYNC_PROXY_SRC"

# The Job runs as a service account; gcloud picks up credentials from the
# metadata server automatically. This token is reused for all Apigee calls.
gcloud config set project "$PROJECT" --quiet >/dev/null 2>&1
TOKEN="$(gcloud auth print-access-token)"
[[ -n "$TOKEN" ]] || die "gcloud auth print-access-token returned empty"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ----- Apigee mgmt API helpers ----------------------------------------------

api() {
  local method="$1" path="$2" body="${3:-}"
  local extra_args=("-sS" "-X" "$method" "-H" "Authorization: Bearer $TOKEN")
  if [[ -n "$body" ]]; then
    extra_args+=("-H" "Content-Type: application/json" "--data" "$body")
  fi
  extra_args+=("-w" "\n%{http_code}")
  curl "${extra_args[@]}" "$APIGEE_API$path"
}

api_status() {
  curl -sS -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $TOKEN" "$APIGEE_API$1"
}

# ----- phase 1: enable APIs -------------------------------------------------

enable_apis() {
  step "Phase 1 — enabling required GCP APIs"
  # Single batched call; gcloud no-ops APIs already enabled.
  gcloud services enable "${REQUIRED_APIS[@]}" --project "$PROJECT" --quiet
  for a in "${REQUIRED_APIS[@]}"; do ok "$a"; done
}

# ----- phase 2: Vertex service account --------------------------------------

ensure_vertex_sa() {
  step "Phase 2 — Vertex service account"

  local sa_id="${VERTEX_SA%%@*}"   # account id = part before '@'

  if gcloud iam service-accounts describe "$VERTEX_SA" \
       --project "$PROJECT" >/dev/null 2>&1; then
    ok "Service account $VERTEX_SA exists"
  else
    gcloud iam service-accounts create "$sa_id" \
      --project "$PROJECT" \
      --display-name "Apigee → Vertex AI caller (AIRS pipeline)" --quiet
    ok "Service account $VERTEX_SA created"
  fi

  # roles/aiplatform.user lets the Apigee proxy call Vertex as this SA.
  # add-iam-policy-binding is idempotent — re-adding an existing binding no-ops.
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$VERTEX_SA" \
    --role "roles/aiplatform.user" \
    --condition=None --quiet >/dev/null
  ok "roles/aiplatform.user bound to $VERTEX_SA"

  # At RUNTIME the Apigee data plane impersonates this SA to mint the Google
  # access token for the Vertex TargetEndpoint (<Authentication><GoogleAccessToken>).
  # Impersonation requires the Apigee service agent to be a Token Creator ON
  # this SA — without it the proxy returns HTTP 500 GoogleTokenGenerationFailure.
  # (Deploy-time actAs is separate and not sufficient for runtime token minting.)
  local proj_num apigee_agent
  proj_num="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
  apigee_agent="service-${proj_num}@gcp-sa-apigee.iam.gserviceaccount.com"
  gcloud iam service-accounts add-iam-policy-binding "$VERTEX_SA" \
    --member "serviceAccount:$apigee_agent" \
    --role "roles/iam.serviceAccountTokenCreator" \
    --project "$PROJECT" --quiet >/dev/null
  ok "roles/iam.serviceAccountTokenCreator: $apigee_agent → $VERTEX_SA"
}

# ----- phase 3: AIRS security profile (guarded optional) --------------------

maybe_create_airs_profile() {
  step "Phase 3 — AIRS security profile"

  if [[ "$CREATE_AIRS_PROFILE" != "1" ]]; then
    ok "CREATE_AIRS_PROFILE not set — assuming profile '$AIRS_PROFILE' already exists"
    return 0
  fi

  # Opt-in path. Requires the AIRS management API base URL + a management
  # token (separate from the runtime scan token). Verify the exact endpoint
  # and payload schema against https://pan.dev/prisma-airs/ before relying on
  # this in production.
  [[ -n "$AIRS_MGMT_API"   ]] || die "CREATE_AIRS_PROFILE=1 but AIRS_MGMT_API not set"
  [[ -n "$AIRS_MGMT_TOKEN" ]] || die "CREATE_AIRS_PROFILE=1 but AIRS_MGMT_TOKEN not set"

  local resp code body
  resp="$(curl -sS -X POST \
    -H "Authorization: Bearer $AIRS_MGMT_TOKEN" \
    -H "Content-Type: application/json" \
    -w "\n%{http_code}" \
    --data "$(jq -n --arg n "$AIRS_PROFILE" '{name:$n}')" \
    "$AIRS_MGMT_API/v1/ai-security-profiles")"
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"

  if [[ "$code" =~ ^(200|201)$ ]]; then
    ok "AIRS security profile '$AIRS_PROFILE' created"
  elif [[ "$code" == "409" ]]; then
    ok "AIRS security profile '$AIRS_PROFILE' already exists"
  else
    die "AIRS profile create failed (HTTP $code): $body"
  fi
}

# ----- phase 4: KVM ---------------------------------------------------------

setup_kvm() {
  step "Phase 4 — encrypted KVM $KVM_NAME in env=$APIGEE_ENV"

  local kvm_path="/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/keyvaluemaps/$KVM_NAME"
  local status
  status="$(api_status "$kvm_path")"

  if [[ "$status" == "200" ]]; then
    ok "KVM $KVM_NAME exists"
  else
    local body code
    body="$(api POST "/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/keyvaluemaps" \
              "$(jq -n --arg n "$KVM_NAME" '{name:$n, encrypted:true}')")"
    code="${body##*$'\n'}"
    [[ "$code" =~ ^(200|201)$ ]] || die "KVM create failed (HTTP $code): $body"
    ok "KVM $KVM_NAME created (encrypted)"
  fi

  for entry in "airs_token:$AIRS_TOKEN" "airs_profile:$AIRS_PROFILE"; do
    local key="${entry%%:*}" val="${entry#*:}"
    local entry_path="$kvm_path/entries/$key"
    local entry_status payload resp code
    entry_status="$(api_status "$entry_path")"
    payload="$(jq -n --arg n "$key" --arg v "$val" '{name:$n, value:$v}')"

    if [[ "$entry_status" == "200" ]]; then
      resp="$(api PUT "$entry_path" "$payload")"
      code="${resp##*$'\n'}"
      [[ "$code" =~ ^(200|201)$ ]] || die "KVM entry update $key failed (HTTP $code): $resp"
      ok "KVM entry $key updated"
    else
      resp="$(api POST "$kvm_path/entries" "$payload")"
      code="${resp##*$'\n'}"
      [[ "$code" =~ ^(200|201)$ ]] || die "KVM entry create $key failed (HTTP $code): $resp"
      ok "KVM entry $key created"
    fi
  done
}

# ----- bundle helpers -------------------------------------------------------

zip_sharedflow() { ( cd "$1" && zip -qr "$2" sharedflowbundle -x "*.DS_Store" ); }
zip_proxy()      { ( cd "$1" && zip -qr "$2" apiproxy        -x "*.DS_Store" ); }

import_bundle() {
  local kind="$1" name="$2" zip="$3"   # kind = sharedflows | apis
  local resp code body rev
  resp="$(curl -sS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: multipart/form-data" \
    -F "file=@$zip" \
    -w "\n%{http_code}" \
    "$APIGEE_API/organizations/$APIGEE_ORG/$kind?action=import&name=$name")"
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  [[ "$code" =~ ^(200|201)$ ]] || die "Bundle import failed (HTTP $code): $body"
  rev="$(echo "$body" | jq -r '.revision // empty')"
  [[ -n "$rev" ]] || die "No revision returned in import response: $body"
  echo "$rev"
}

deploy_revision() {
  local kind="$1" name="$2" rev="$3" sa="${4:-}"
  local path="/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/$kind/$name/revisions/$rev/deployments?override=true"
  # Apigee deployments API query param is `serviceAccount` (NOT
  # `serviceAccountEmail` — that name returns HTTP 400 "Cannot bind query
  # parameter"). It pins the SA the proxy uses for Google Cloud auth (Vertex).
  [[ -n "$sa" ]] && path="$path&serviceAccount=$sa"
  local resp code body
  resp="$(api POST "$path")"
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  [[ "$code" =~ ^(200|201)$ ]] || die "Deploy failed (HTTP $code): $body"
}

# ----- phase 5 + 6: bundle deploy -------------------------------------------

deploy_sharedflow() {
  step "Phase 5 — SharedFlow $SHAREDFLOW_NAME"
  local zip="$WORK/$SHAREDFLOW_NAME.zip"
  zip_sharedflow "$SHAREDFLOW_SRC" "$zip"
  ok "Built bundle ($(wc -c <"$zip") bytes)"
  local rev
  rev="$(import_bundle sharedflows "$SHAREDFLOW_NAME" "$zip")"
  ok "Imported as revision $rev"
  deploy_revision sharedflows "$SHAREDFLOW_NAME" "$rev"
  ok "Deployed revision $rev to env=$APIGEE_ENV"
}

deploy_sync_proxy() {
  step "Phase 6 — sync proxy $SYNC_PROXY_NAME"
  local zip="$WORK/$SYNC_PROXY_NAME.zip"
  zip_proxy "$SYNC_PROXY_SRC" "$zip"
  ok "Built bundle ($(wc -c <"$zip") bytes)"
  local rev
  rev="$(import_bundle apis "$SYNC_PROXY_NAME" "$zip")"
  ok "Imported as revision $rev"
  deploy_revision apis "$SYNC_PROXY_NAME" "$rev" "$VERTEX_SA"
  ok "Deployed revision $rev to env=$APIGEE_ENV with SA=$VERTEX_SA"
}

# ----- main -----------------------------------------------------------------

echo "AIRS-on-Apigee provisioning"
echo "  project        = $PROJECT"
echo "  region         = $REGION"
echo "  apigee org     = $APIGEE_ORG"
echo "  apigee env     = $APIGEE_ENV"
echo "  vertex SA      = $VERTEX_SA"
echo "  airs profile   = $AIRS_PROFILE"
echo "  create profile = $CREATE_AIRS_PROFILE"
[[ -n "$ENVGROUP_HOSTNAME" ]] && echo "  hostname       = $ENVGROUP_HOSTNAME"

enable_apis
ensure_vertex_sa
maybe_create_airs_profile
setup_kvm
deploy_sharedflow
deploy_sync_proxy

step "Provisioning complete."
echo ""
echo "Deployed in env $APIGEE_ENV:"
echo "  - SharedFlow $SHAREDFLOW_NAME"
echo "  - Proxy      $SYNC_PROXY_NAME  basepath=/vertex-airs-sync"
if [[ -n "$ENVGROUP_HOSTNAME" ]]; then
  echo ""
  echo "Smoke test:"
  echo "  curl -i 'https://$ENVGROUP_HOSTNAME/vertex-airs-sync/v1/projects/$PROJECT/locations/$REGION/publishers/google/models/gemini-2.5-flash:generateContent' \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Hello\"}]}]}'"
fi
