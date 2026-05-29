#!/usr/bin/env bash
# bootstrap.sh — ONE-TIME manual setup for the AIRS-on-Apigee pipeline.
#
# Run this once, by hand, with an account that has Owner (or equivalent) on
# the project. It provisions the things the pipeline itself cannot bootstrap:
#
#   1. Enables the GCP APIs the pipeline needs
#   2. Creates the Artifact Registry Docker repo (holds the provisioner image)
#   3. Creates the Secret Manager secret `airs-api-token`
#   4. Creates the runtime service account the Cloud Run Job runs as + grants
#      it the roles it needs to provision everything
#   5. Grants the Cloud Build service account its roles
#   6. Prints the command to create the Cloud Build trigger (the GitHub repo
#      must be connected to Cloud Build in the console first — see notes)
#
# Safe to re-run: every step is idempotent.

set -euo pipefail

# ----- args -----------------------------------------------------------------

usage() {
  cat <<'EOF'
Usage: bootstrap.sh [options]

Required:
  --project=PROJECT_ID        GCP project to set up.

Optional:
  --region=REGION             Default: us-central1
  --ar-repo=NAME              Artifact Registry repo name. Default: airs-apigee
  --runtime-sa-name=NAME      Runtime SA account id. Default: airs-pipeline-sa
  --cloud-build-sa=EMAIL      Cloud Build service account to grant roles to.
                              Default: the legacy <PROJECT_NUMBER>@cloudbuild
                              .gserviceaccount.com. If your builds run as the
                              Compute Engine default SA, pass it explicitly.
  --airs-token=TOKEN          If given, seeds the airs-api-token secret with
                              this value. If omitted, an empty secret is
                              created and you add the value yourself later.
  -h, --help                  This message.
EOF
  exit "${1:-0}"
}

PROJECT=""
REGION="us-central1"
AR_REPO="airs-apigee"
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

# ----- helpers --------------------------------------------------------------

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

echo "Bootstrapping AIRS-on-Apigee pipeline"
echo "  project        = $PROJECT ($PROJECT_NUMBER)"
echo "  region         = $REGION"
echo "  AR repo        = $AR_REPO"
echo "  runtime SA     = $RUNTIME_SA"
echo "  cloud build SA = $CLOUD_BUILD_SA"

# ----- 1: enable APIs -------------------------------------------------------

step "1 — enabling APIs"
gcloud services enable \
  cloudbuild.googleapis.com \
  run.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  apigee.googleapis.com \
  aiplatform.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  serviceusage.googleapis.com \
  --project "$PROJECT" --quiet
ok "APIs enabled"

# ----- 2: Artifact Registry repo --------------------------------------------

step "2 — Artifact Registry Docker repo '$AR_REPO'"
if gcloud artifacts repositories describe "$AR_REPO" \
     --location "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
  ok "Repo $AR_REPO already exists"
else
  gcloud artifacts repositories create "$AR_REPO" \
    --repository-format=docker \
    --location "$REGION" \
    --project "$PROJECT" \
    --description "AIRS-on-Apigee provisioner images" --quiet
  ok "Repo $AR_REPO created"
fi

# ----- 3: Secret Manager secret ---------------------------------------------

step "3 — Secret Manager secret '$SECRET_NAME'"
if gcloud secrets describe "$SECRET_NAME" --project "$PROJECT" >/dev/null 2>&1; then
  ok "Secret $SECRET_NAME already exists"
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
  ok "Runtime SA already exists"
else
  gcloud iam service-accounts create "$RUNTIME_SA_NAME" \
    --project "$PROJECT" \
    --display-name "AIRS-on-Apigee pipeline provisioner" --quiet
  ok "Runtime SA created"
fi

# Roles the Job needs to provision everything. Broad on purpose — this SA
# enables APIs, creates a service account, edits project IAM, drives Apigee,
# and reads the AIRS token. Tighten later if your security posture requires.
RUNTIME_ROLES=(
  roles/serviceusage.serviceUsageAdmin   # enable APIs
  roles/iam.serviceAccountAdmin          # create the Vertex SA
  roles/resourcemanager.projectIamAdmin  # bind roles/aiplatform.user
  roles/iam.serviceAccountUser           # deploy the proxy "as" the Vertex SA
  roles/apigee.admin                     # KVM + import + deploy
  roles/secretmanager.secretAccessor     # read airs-api-token
)
for role in "${RUNTIME_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$RUNTIME_SA" \
    --role "$role" --condition=None --quiet >/dev/null
  ok "runtime SA → $role"
done

# ----- 5: Cloud Build service account roles ---------------------------------

step "5 — Cloud Build service account roles"
CLOUD_BUILD_ROLES=(
  roles/artifactregistry.writer   # push the provisioner image
  roles/run.admin                 # deploy + execute the Cloud Run Job
  roles/iam.serviceAccountUser    # deploy the Job "as" the runtime SA
  roles/logging.logWriter         # required with logging: CLOUD_LOGGING_ONLY
)

# Many orgs enforce constraints/cloudbuild.allowedWorkerPools or
# iam.disableServiceAccountKeyCreation-style policies that FORBID the default
# Cloud Build / Compute SAs and REQUIRE the trigger to run as a user-managed
# SA (you'll see "your organization policy requires you to select a
# user-managed service account"). To work under that policy with no extra
# identities, we make the runtime SA do double duty: it runs the build AND the
# Job. So grant the build roles to the runtime SA too. (It already has
# iam.serviceAccountUser from step 4, letting it deploy the Job "as" itself.)
for role in "${CLOUD_BUILD_ROLES[@]}"; do
  gcloud projects add-iam-policy-binding "$PROJECT" \
    --member "serviceAccount:$RUNTIME_SA" \
    --role "$role" --condition=None --quiet >/dev/null
  ok "runtime SA (build identity) → $role"
done

# Fallback for projects WITHOUT that org policy, where builds run as the legacy
# cloudbuild SA or the Compute Engine default SA. Harmless to also grant here;
# the compute SA may not exist yet, which is fine (skipped if so).
COMPUTE_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for sa in "$CLOUD_BUILD_SA" "$COMPUTE_SA"; do
  for role in "${CLOUD_BUILD_ROLES[@]}"; do
    if gcloud projects add-iam-policy-binding "$PROJECT" \
         --member "serviceAccount:$sa" \
         --role "$role" --condition=None --quiet >/dev/null 2>&1; then
      ok "$sa → $role"
    else
      warn "$sa → $role (skipped — service account may not exist)"
    fi
  done
done

# ----- 6: Cloud Build trigger (manual — needs a connected repo) -------------

step "6 — Cloud Build trigger"
warn "The GitHub repo must be connected to Cloud Build BEFORE a trigger can"
warn "be created. Connecting a repo is a one-time OAuth flow done in the"
warn "console: Cloud Build → Triggers → Connect Repository."
echo ""
warn "TRIGGER REGION: if you connected the repo via the GitHub App ('Install"
warn "Google Cloud Build'), that is a 1st-gen GLOBAL connection, so the trigger"
warn "must be created with --region=global. Passing a regional value here makes"
warn "gcloud look for a 2nd-gen connection that does not exist ('repository not"
warn "found'). This is separate from _REGION below, which is where the RESOURCES"
warn "(Artifact Registry, Cloud Run Job) deploy — trigger location != resource"
warn "location."
echo ""
echo "  Once the repo is connected, create the trigger with:"
echo ""
echo "    gcloud builds triggers create github \\"
echo "      --project=$PROJECT \\"
echo "      --region=global \\"
echo "      --name=airs-apigee-pipeline \\"
echo "      --repo-name=YOUR_REPO_NAME \\"
echo "      --repo-owner=YOUR_GITHUB_USERNAME \\"
echo "      --branch-pattern='^main$' \\"
echo "      --build-config=Google/cloudrun/flow/cloudbuild.yaml \\"
echo "      --service-account=projects/$PROJECT/serviceAccounts/$RUNTIME_SA \\"
echo "      --substitutions=_REGION=$REGION,_RUNTIME_SA=$RUNTIME_SA,_APIGEE_ORG=$PROJECT,_APIGEE_ENV=eval,_VERTEX_SA=YOUR_VERTEX_SA,_AIRS_PROFILE=YOUR_AIRS_PROFILE,_ENVGROUP_HOSTNAME=YOUR_ENVGROUP_HOSTNAME"
echo ""
warn "--service-account is REQUIRED if your org enforces a user-managed-SA"
warn "policy. Omitting it returns a bare 'INVALID_ARGUMENT' from the API. We"
warn "reuse the runtime SA ($RUNTIME_SA) as the build identity — step 5 grants"
warn "it the build roles for exactly this reason."
echo ""
warn "_VERTEX_SA: pass any SA email (e.g. vertex-airs-sa@$PROJECT.iam"
warn ".gserviceaccount.com) — the pipeline CREATES it if missing."
warn "_AIRS_PROFILE: the security-profile name in your SCM/Strata tenant."
warn "_ENVGROUP_HOSTNAME: the Apigee env-group hostname (e.g. <IP>.nip.io) —"
warn "optional, only enables the smoke-test URL in the run summary."
echo ""

step "Bootstrap complete."
echo ""
echo "Next:"
echo "  1. If you skipped --airs-token, add the secret value (see step 3 above)."
echo "  2. Connect the GitHub repo and create the trigger (step 6 above)."
echo "  3. Push to main — the pipeline runs."
