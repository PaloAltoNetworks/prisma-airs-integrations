#!/usr/bin/env bash
# provision.sh — full provisioning of the MONOLITHIC AIRS-on-Apigee proxy.
#
# Sister to ../flow. That one deploys the reusable PANW-AIRS
# SharedFlow + a thin proxy. THIS one deploys the self-contained `vertex-simple`
# proxy (the manual proxy published in PaloAltoNetworks/prisma-airs-integrations
# under Google/apigee/apiproxy) — AIRS scanning AND DLP masking baked directly
# into one bundle, no SharedFlow dependency.
#
# Runs inside the Cloud Run Job container. All configuration arrives as
# environment variables (set on the Job by cloudbuild.yaml; secrets injected
# from Secret Manager). There are no CLI arguments.
#
# Phases:
#   1. Enable required GCP APIs
#   2. Create / verify the Vertex service account + IAM bindings
#      (incl. the Apigee-service-agent tokenCreator binding for runtime auth)
#   3. (guarded) Create / verify the AIRS security profile via the mgmt API
#   4. Upsert the encrypted Apigee KVM `private` (5 entries the proxy reads)
#   5. Import + deploy the vertex-simple proxy
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

# Monolith-specific config (the SharedFlow pipeline doesn't need these):
#   AIRS_HOST    — AIRS endpoint HOST (no scheme), region-bound. Default: US.
#                  The proxy prefixes a literal https:// (Apigee rejects target
#                  URLs that start with a variable), so store host only here.
#   VERTEX_MODEL — the Vertex model the proxy targets (baked into the KVM;
#                  the monolith builds the target URL from project + model).
AIRS_HOST="${AIRS_HOST:-service.api.aisecurity.paloaltonetworks.com}"
VERTEX_MODEL="${VERTEX_MODEL:-gemini-2.5-flash}"

# Guarded optional: AIRS security-profile creation. Off unless explicitly set.
CREATE_AIRS_PROFILE="${CREATE_AIRS_PROFILE:-0}"
AIRS_MGMT_TOKEN="${AIRS_MGMT_TOKEN:-}"
AIRS_MGMT_API="${AIRS_MGMT_API:-}"

# ----- constants ------------------------------------------------------------

PROXY_NAME="vertex-simple"
PROXY_SRC="/app/bundles/vertex-simple"
KVM_NAME="private"          # must match mapIdentifier in KVM-GetConfig.xml
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

[[ -d "$PROXY_SRC" ]] || die "Missing bundle dir $PROXY_SRC"

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
  gcloud services enable "${REQUIRED_APIS[@]}" --project "$PROJECT" --quiet
  for a in "${REQUIRED_APIS[@]}"; do ok "$a"; done
}

# ----- phase 2: Vertex service account --------------------------------------

ensure_vertex_sa() {
  step "Phase 2 — Vertex service account"

  local sa_id="${VERTEX_SA%%@*}"

  if gcloud iam service-accounts describe "$VERTEX_SA" \
       --project "$PROJECT" >/dev/null 2>&1; then
    ok "Service account $VERTEX_SA exists"
  else
    gcloud iam service-accounts create "$sa_id" \
      --project "$PROJECT" \
      --display-name "Apigee → Vertex AI caller (AIRS monolith)" --quiet
    ok "Service account $VERTEX_SA created"
  fi

  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$VERTEX_SA" \
    --role "roles/aiplatform.user" \
    --condition=None --quiet >/dev/null
  ok "roles/aiplatform.user bound to $VERTEX_SA"

  # At RUNTIME the Apigee data plane impersonates this SA to mint the Google
  # access token for the Vertex target (<Authentication><GoogleAccessToken>).
  # Without the Token Creator binding the proxy returns HTTP 500
  # GoogleTokenGenerationFailure even though deployment succeeds.
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

  # The vertex-simple proxy's KVM-GetConfig reads exactly these five keys.
  upsert_kvm_entry "$kvm_path" "prisma.airs.token"   "$AIRS_TOKEN"
  upsert_kvm_entry "$kvm_path" "prisma.airs.profile" "$AIRS_PROFILE"
  upsert_kvm_entry "$kvm_path" "prisma.airs.host"    "$AIRS_HOST"
  upsert_kvm_entry "$kvm_path" "vertex.project"      "$PROJECT"
  upsert_kvm_entry "$kvm_path" "vertex.model"        "$VERTEX_MODEL"
}

upsert_kvm_entry() {
  local kvm_path="$1" key="$2" val="$3"
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
}

# ----- bundle helpers -------------------------------------------------------

zip_proxy() { ( cd "$1" && zip -qr "$2" apiproxy -x "*.DS_Store" ); }

import_bundle() {
  local name="$1" zip="$2"
  local resp code body rev
  resp="$(curl -sS -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: multipart/form-data" \
    -F "file=@$zip" \
    -w "\n%{http_code}" \
    "$APIGEE_API/organizations/$APIGEE_ORG/apis?action=import&name=$name")"
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  [[ "$code" =~ ^(200|201)$ ]] || die "Bundle import failed (HTTP $code): $body"
  rev="$(echo "$body" | jq -r '.revision // empty')"
  [[ -n "$rev" ]] || die "No revision returned in import response: $body"
  echo "$rev"
}

deploy_revision() {
  local name="$1" rev="$2" sa="$3"
  # Apigee deployments API query param is `serviceAccount` (NOT
  # `serviceAccountEmail`, which returns HTTP 400 "Cannot bind query parameter").
  local path="/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/apis/$name/revisions/$rev/deployments?override=true&serviceAccount=$sa"
  local resp code body
  resp="$(api POST "$path")"
  code="${resp##*$'\n'}"
  body="${resp%$'\n'*}"
  [[ "$code" =~ ^(200|201)$ ]] || die "Deploy failed (HTTP $code): $body"
}

# ----- phase 5: proxy deploy ------------------------------------------------

deploy_proxy() {
  step "Phase 5 — proxy $PROXY_NAME"
  local zip="$WORK/$PROXY_NAME.zip"
  zip_proxy "$PROXY_SRC" "$zip"
  ok "Built bundle ($(wc -c <"$zip") bytes)"
  local rev
  rev="$(import_bundle "$PROXY_NAME" "$zip")"
  ok "Imported as revision $rev"
  deploy_revision "$PROXY_NAME" "$rev" "$VERTEX_SA"
  ok "Deployed revision $rev to env=$APIGEE_ENV with SA=$VERTEX_SA"
}

# ----- main -----------------------------------------------------------------

echo "AIRS-on-Apigee provisioning (MONOLITHIC PROXY)"
echo "  project        = $PROJECT"
echo "  region         = $REGION"
echo "  apigee org     = $APIGEE_ORG"
echo "  apigee env     = $APIGEE_ENV"
echo "  vertex SA      = $VERTEX_SA"
echo "  vertex model   = $VERTEX_MODEL"
echo "  airs profile   = $AIRS_PROFILE"
echo "  airs host      = $AIRS_HOST"
echo "  create profile = $CREATE_AIRS_PROFILE"
[[ -n "$ENVGROUP_HOSTNAME" ]] && echo "  hostname       = $ENVGROUP_HOSTNAME"

enable_apis
ensure_vertex_sa
maybe_create_airs_profile
setup_kvm
deploy_proxy

step "Provisioning complete."
echo ""
echo "Deployed in env $APIGEE_ENV:"
echo "  - Proxy $PROXY_NAME  basepath=/vertex  (model baked from KVM: $VERTEX_MODEL)"
if [[ -n "$ENVGROUP_HOSTNAME" ]]; then
  echo ""
  echo "Smoke test (model comes from the KVM, so the client just POSTs a prompt):"
  echo "  curl -i 'https://$ENVGROUP_HOSTNAME/vertex' \\"
  echo "    -H 'Content-Type: application/json' \\"
  echo "    -d '{\"contents\":[{\"role\":\"user\",\"parts\":[{\"text\":\"Hello\"}]}]}'"
fi
