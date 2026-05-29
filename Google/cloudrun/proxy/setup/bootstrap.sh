#!/usr/bin/env bash
# bootstrap.sh — ONE-TIME manual setup for the MONOLITHIC PROXY pipeline.
#
# Sister to ../flow/setup/bootstrap.sh. Run once, by hand, with an
# account that has Owner (or equivalent) on the project. It provisions what the
# pipeline itself cannot bootstrap:
#
#   1. Enables the GCP APIs the pipeline needs
#   2. Creates the Artifact Registry Docker repo (proxy provisioner image)
#   3. Creates the Secret Manager secret `airs-api-token` (SHARED with the flow
#      pipeline — idempotent if you already created it there)
#   4. Creates/reuses the runtime service account + grants provisioning roles
#   5. Grants Cloud Build roles (incl. to the runtime SA, used as the build
#      identity under a user-managed-SA org policy)
#   6. Prints the command to create the Cloud Build trigger
#
# Safe to re-run: every step is idempotent.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [options]

Required:
  --project=PROJECT_ID        GCP project to set up.

Optional:
  --region=REGION             Default: us-central1
  --ar-repo=NAME              Artifact Registry repo. Default: airs-apigee-proxy
  --runtime-sa-name=NAME      Runtime SA account id. Default: airs-pipeline-sa
  --cloud-build-sa=EMAIL      Cloud Build SA to grant roles to. Default: the
                              legacy <PROJECT_NUMBER>@cloudbuild SA.
  --airs-token=TOKEN          Seeds the airs-api-token secret. If omitted, an
                              empty secret is created and you add the value.
  -h, --help                  This message.
EOF
  exit "${1:-0}"
}

PROJECT=""
REGION="us-central1"
AR_REPO="airs-apigee-proxy"
RUNTIME_SA_NAME="airs-pipeline-sa"
CLOUD_BUILD_SA=""
AIRS_TOKEN=""

for arg in "$@"; do
  case "$arg" in
    --project=*)          PROJECT="${arg#*=}" ;;
    --region=*)           REGION="${arg#*=}" ;;
    --ar-repo=*)          AR_REPO="${arg#*=}" ;;
    --runtime-sa-name=*)  RUNTIME_SA_NAME="${arg#*=}" ;;
    --cloud-build-sa=*)   CLOUD_BUILD_SA="${arg#*=}" ;;
    --airs-token=*)       AIRS_TOKEN="${arg#*=}" ;;
    -h|--help)            usage 0 ;;
    *) echo "Unknown argument: $arg" >&2; usage 1 ;;
  esac
done

[[ -n "$PROJECT" ]] || { echo "Missing --project" >&2; usage 1; }

step() { printf "\n\033[1;34m▶ %s\033[0m\n" "$*"; }
ok()   { printf "  \033[32m✓\033[0m %s\n" "$*"; }
warn() { printf "  \033[33m!\033[0m %s\n" "$*"; }
die()  { printf "  \033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }

command -v gcloud >/dev/null || die "gcloud not on PATH"

PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
[[ -n "$PROJECT_NUMBER" ]] || die "Could not resolve project number for $PROJECT"

RUNTIME_SA="${RUNTIME_SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
[[ -n "$CLOUD_BUILD_SA" ]] || CLOUD_BUILD_SA="${PROJECT_NUMBER}@cloudbuild.gserviceaccount.com"
SECRET_NAME="airs-api-token"

echo "Bootstrapping AIRS-on-Apigee MONOLITHIC PROXY pipeline"
echo "  project        = $PROJECT ($PROJECT_NUMBER)"
echo "  region         = $REGION"
echo "  AR repo        = $AR_REPO"
echo "  runtime SA     = $RUNTIME_SA"
echo "  cloud build SA = $CLOUD_BUILD_SA"

# ----- 1: enable APIs -------------------------------------------------------

step "1 — enabling APIs"
gcloud services enable \
  cloudbuild.googleapis.com run.googleapis.com artifactregistry.googleapis.com \
  secretmanager.googleapis.com apigee.googleapis.com aiplatform.googleapis.com \
  iam.googleapis.com cloudresourcemanager.googleapis.com serviceusage.googleapis.com \
  --project "$PROJECT" --quiet
ok "APIs enabled"

# ----- 2: Artifact Registry repo --------------------------------------------

step "2 — Artifact Registry Docker repo '$AR_REPO'"
if gcloud artifacts repositories describe "$AR_REPO" \
     --location "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
  ok "Repo $AR_REPO already exists"
else
  gcloud artifacts repositories create "$AR_REPO" \
    --repository-format=docker --location "$REGION" --project "$PROJECT" \
    --description "AIRS-on-Apigee monolithic proxy provisioner images" --quiet
  ok "Repo $AR_REPO created"
fi

# ----- 3: Secret Manager secret (shared with the flow pipeline) -------------

step "3 — Secret Manager secret '$SECRET_NAME'"
if gcloud secrets describe "$SECRET_NAME" --project "$PROJECT" >/dev/null 2>&1; then
  ok "Secret $SECRET_NAME already exists (shared with flow pipeline)"
else
  gcloud secrets create "$SECRET_NAME" \
    --replication-policy=automatic --project "$PROJECT" --quiet
  ok "Secret $SECRET_NAME created"
fi

if [[ -n "$AIRS_TOKEN" ]]; then
  printf '%s' "$AIRS_TOKEN" | gcloud secrets versions add "$SECRET_NAME" \
    --data-file=- --project "$PROJECT" --quiet
  ok "Secret value added as a new version"
else
  warn "No --airs-token given. Add the value before the first pipeline run:"
  warn "  printf '%s' 'YOUR_AIRS_TOKEN' | gcloud secrets versions add $SECRET_NAME --data-file=- --project $PROJECT"
fi

# ----- 4: runtime service account + roles -----------------------------------

step "4 — runtime service account '$RUNTIME_SA'"
if gcloud iam service-accounts describe "$RUNTIME_SA" \
     --project "$PROJECT" >/dev/null 2>&1; then
  ok "Runtime SA already exists (shared with flow pipeline)"
else
  gcloud iam service-accounts create "$RUNTIME_SA_NAME" \
    --project "$PROJECT" \
    --display-name "AIRS-on-Apigee pipeline provisioner" --quiet
  ok "Runtime SA created"
fi

RUNTIME_ROLES=(
  roles/serviceusage.serviceUsageAdmin   # enable APIs
  roles/iam.serviceAccountAdmin          # create the Vertex SA
  roles/resourcemanager.projectIamAdmin  # bind aiplatform.user + tokenCreator
  roles/iam.serviceAccountUser           # deploy the proxy "as" the Vertex SA
  roles/apigee.admin                     # KVM + import + deploy
  roles/secretmanager.secretAccessor     # read airs-api-token
)
for role in "${RUNTIME_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$RUNTIME_SA" --role "$role" \
    --condition=None --quiet >/dev/null
  ok "runtime SA → $role"
done

# ----- 5: Cloud Build service account roles ---------------------------------

step "5 — Cloud Build service account roles"
CLOUD_BUILD_ROLES=(
  roles/artifactregistry.writer
  roles/run.admin
  roles/iam.serviceAccountUser
  roles/logging.logWriter
)

# Org policy may REQUIRE a user-managed build SA — reuse the runtime SA as the
# build identity (see ../flow bootstrap for the full rationale).
for role in "${CLOUD_BUILD_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$RUNTIME_SA" --role "$role" \
    --condition=None --quiet >/dev/null
  ok "runtime SA (build identity) → $role"
done

# Fallback for projects without that org policy (default cloudbuild/compute SA).
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for sa in "$CLOUD_BUILD_SA" "$COMPUTE_SA"; do
  for role in "${CLOUD_BUILD_ROLES[@]}"; do
    if gcloud projects add-iam-policy-binding "$PROJECT" \
         --member "serviceAccount:$sa" --role "$role" \
         --condition=None --quiet >/dev/null 2>&1; then
      ok "$sa → $role"
    else
      warn "$sa → $role (skipped — service account may not exist)"
    fi
  done
done

# ----- 6: Cloud Build trigger -----------------------------------------------

step "6 — Cloud Build trigger"
warn "Connect the GitHub repo to Cloud Build first (console one-time OAuth):"
warn "  Cloud Build → Triggers → Connect Repository."
echo ""
warn "TRIGGER REGION: GitHub App connections are 1st-gen GLOBAL, so use"
warn "--region=global. --service-account is required under a user-managed-SA"
warn "org policy (omitting it returns a bare INVALID_ARGUMENT)."
echo ""
echo "  Once connected, create the trigger with:"
echo ""
echo "    gcloud builds triggers create github \\"
echo "      --project=$PROJECT \\"
echo "      --region=global \\"
echo "      --name=airs-apigee-proxy-pipeline \\"
echo "      --repo-name=YOUR_REPO_NAME \\"
echo "      --repo-owner=YOUR_GITHUB_USERNAME \\"
echo "      --branch-pattern='^main$' \\"
echo "      --build-config=Google/cloudrun/proxy/cloudbuild.yaml \\"
echo "      --service-account=projects/$PROJECT/serviceAccounts/$RUNTIME_SA \\"
echo "      --substitutions=_REGION=$REGION,_RUNTIME_SA=$RUNTIME_SA,_APIGEE_ORG=$PROJECT,_APIGEE_ENV=eval,_VERTEX_SA=YOUR_VERTEX_SA,_VERTEX_MODEL=gemini-2.5-flash,_AIRS_PROFILE=YOUR_AIRS_PROFILE,_ENVGROUP_HOSTNAME=YOUR_ENVGROUP_HOSTNAME"
echo ""
warn "--build-config points at Google/cloudrun/proxy/cloudbuild.yaml (the proxy lives"
warn "in a subfolder). The flow pipeline uses Google/cloudrun/flow/cloudbuild.yaml."
echo ""

step "Bootstrap complete."
echo ""
echo "Next:"
echo "  1. If you skipped --airs-token, add the secret value (see step 3)."
echo "  2. Connect the GitHub repo and create the trigger (step 6)."
echo "  3. Push to main — the pipeline runs."
