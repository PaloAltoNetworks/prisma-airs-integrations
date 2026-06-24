# AIRS-on-Apigee Provisioning Pipeline

A GCP-native CI/CD pipeline that provisions the **Prisma AIRS + Vertex AI on Apigee X** reference pattern from a git push — enable APIs, create the Vertex service account, configure the encrypted KVM, and import + deploy the SharedFlow and proxy, all in one automated run.

This is the automation layer for the SharedFlow reference bundles published under [`Google/apigee/sharedflow`](../../apigee/sharedflow).

> **Self-contained by design.** This pipeline keeps its **own copy** of the
> `PANW-AIRS` SharedFlow + `vertex-airs-sync` proxy bundles under [`bundles/`](bundles/)
> rather than referencing `Google/apigee/sharedflow/`, so each Cloud Run pipeline
> is a complete clone-and-run unit (the Docker build context is this folder only).
> Trade-off: the bundles live in two places — keep this copy in sync with the
> canonical one in `Google/apigee/sharedflow/` when that changes.

## How it works

```
  git push to main
        │
        ▼
  ┌─────────────────────┐
  │  Cloud Build        │   reads cloudbuild.yaml
  │  (the pipeline)     │
  │                     │
  │  1. docker build    │   builds the provisioner image
  │  2. docker push     │   → Artifact Registry
  │  3. run jobs deploy │   create/update the Cloud Run Job
  │  4. run jobs execute│   run it, wait, fail the build if it fails
  └─────────┬───────────┘
            │
            ▼
  ┌─────────────────────────────────────┐
  │  Cloud Run Job (provision.sh)       │
  │                                     │
  │  1. enable GCP APIs                 │
  │  2. create/verify Vertex SA + IAM   │
  │  3. (guarded) create AIRS profile   │
  │  4. upsert encrypted Apigee KVM     │
  │  5. import + deploy SharedFlow      │
  │  6. import + deploy sync proxy      │
  └─────────────────────────────────────┘
```

A few terms, since the pieces are GCP-specific:

- **Cloud Build** is GCP's CI engine. It reads `cloudbuild.yaml` and runs the steps in order. A *trigger* connects it to your git repo so a push starts a build.
- **Artifact Registry** is GCP's container image store — the pipeline's equivalent of Docker Hub.
- **A Cloud Run Job** is a container that runs once, to completion, then exits (unlike a Cloud Run *Service*, which stays up serving HTTP). Our `provision.sh` is a run-once task, so a Job is the right fit.
- **Secret Manager** holds the AIRS token. The Job reads it at runtime; it never lives in the repo or in an image.

Why a Job rather than running `provision.sh` directly inside Cloud Build? The Job is a **reusable, independently-runnable unit** — once deployed you can re-run provisioning from the console, on a schedule, or from another system, without a git push. Cloud Build just builds it and kicks off the first run.

## Repository layout

```
airs-apigee-pipeline/
├── cloudbuild.yaml        # the 4-step pipeline
├── Dockerfile             # the provisioner image (cloud-sdk + jq + zip)
├── provision.sh           # runs inside the Job — does the actual provisioning
├── pipeline.env.example   # documented config (Cloud Build substitutions)
├── setup/
│   └── bootstrap.sh       # ONE-TIME manual setup — run this first
└── bundles/
    ├── PANW-AIRS/         # the AIRS-call SharedFlow
    └── vertex-airs-sync/  # the synchronous Vertex proxy
```

## Prerequisites

- An **existing Apigee X organization** with an environment and an env group. The pipeline configures *within* an org — it does not create one (org creation is a ~45-minute, one-time operation).
- A **Prisma AIRS** tenant with a security profile and an API token.
- `gcloud` installed locally (only for the one-time `bootstrap.sh`).
- Permission to run `bootstrap.sh` — Owner or equivalent on the GCP project.

## Setup — three steps

### 1. Run the one-time bootstrap

```bash
./setup/bootstrap.sh \
  --project=YOUR_PROJECT_ID \
  --region=us-central1 \
  --airs-token=PANW-xxxxxxxx
```

This enables APIs, creates the Artifact Registry repo, creates the `airs-api-token` Secret Manager secret (seeded with `--airs-token`), creates the runtime service account, and grants both the runtime SA and the Cloud Build SA their roles. It is idempotent — safe to re-run.

If you omit `--airs-token`, the secret is created empty and you add the value yourself:

```bash
printf '%s' 'PANW-xxxxxxxx' | gcloud secrets versions add airs-api-token --data-file=- --project YOUR_PROJECT_ID
```

### 2. Connect the repo and create the trigger

Connecting a GitHub repo to Cloud Build is a one-time OAuth flow in the console: **Cloud Build → Triggers → Connect Repository**. Once connected, create the trigger (`bootstrap.sh` prints this command filled in for you):

```bash
gcloud builds triggers create github \
  --project=YOUR_PROJECT_ID \
  --region=global \
  --name=airs-apigee-pipeline \
  --repo-name=YOUR_REPO_NAME \
  --repo-owner=YOUR_GITHUB_USERNAME \
  --branch-pattern='^main$' \
  --build-config=Google/cloudrun/flow/cloudbuild.yaml \
  --service-account=projects/YOUR_PROJECT_ID/serviceAccounts/airs-pipeline-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --substitutions=_REGION=us-central1,_RUNTIME_SA=airs-pipeline-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com,_APIGEE_ORG=YOUR_PROJECT_ID,_APIGEE_ENV=eval,_VERTEX_SA=apigee-vertex-sa@YOUR_PROJECT_ID.iam.gserviceaccount.com,_AIRS_PROFILE=YOUR_AIRS_PROFILE,_ENVGROUP_HOSTNAME=YOUR_ENVGROUP_HOSTNAME
```

> **`--service-account` is required under a user-managed-SA org policy.** If your org enforces it (common in enterprise orgs), omitting this flag fails with a bare `INVALID_ARGUMENT` from the API — no field named. We reuse the runtime SA as the build identity (`bootstrap.sh` step 5 grants it the build roles), so one SA covers both build and Job.

> **`--region=global` is deliberate.** If you connected the repo via the GitHub App ("Install Google Cloud Build"), that is a **1st-gen, global** connection — the trigger must be created in `global`. Passing a regional value (e.g. `us-central1`) makes `gcloud` look for a 2nd-gen connection that does not exist and fails with *"repository not found."* This is separate from `_REGION`, which controls where the **resources** (Artifact Registry, Cloud Run Job) deploy — trigger location and resource location are independent.

`_VERTEX_SA` can be any SA email — the pipeline **creates it** if it doesn't exist. `_ENVGROUP_HOSTNAME` is optional and only enables the smoke-test URL in the run summary. See `pipeline.env.example` for every substitution variable and what it does.

### 3. Push to `main`

That's it. Every push to `main` now runs the pipeline. Watch it under **Cloud Build → History**; watch the provisioning output under **Cloud Run → Jobs → airs-apigee-provisioner → Logs**.

## Configuration

All deployment-specific values are **Cloud Build substitution variables**, set on the trigger. None are hardcoded. See [`pipeline.env.example`](pipeline.env.example) for the full list with descriptions.

The only secret — the AIRS API token — lives in Secret Manager as `airs-api-token` and is injected into the Job at deploy time. It is never in the repo, the image, or the build logs.

## Optional — AIRS security-profile creation

By default the pipeline assumes your AIRS security profile already exists. To have it create the profile via the AIRS management API instead:

1. Add an `airs-mgmt-token` secret (Secret Manager) with a management-API token.
2. In `cloudbuild.yaml`, add to the `deploy-job` step's args:
   - `--set-secrets=...,AIRS_MGMT_TOKEN=airs-mgmt-token:latest`
   - `--set-env-vars=...,AIRS_MGMT_API=<management API base URL>`
3. Set the `_CREATE_AIRS_PROFILE=1` substitution.

`provision.sh`'s `maybe_create_airs_profile()` is the seam — verify the exact endpoint and payload against [pan.dev](https://pan.dev/prisma-airs/) before relying on it.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Build fails at `push` step | Cloud Build SA missing `artifactregistry.writer` | Re-run `bootstrap.sh`; confirm the right Cloud Build SA via `--cloud-build-sa` |
| Build fails at `deploy-job` step with a permissions error | Cloud Build SA can't act as the runtime SA | Re-run `bootstrap.sh` — it grants `iam.serviceAccountUser` |
| Job fails: `AIRS_TOKEN not set` | The `airs-api-token` secret has no value | Add a secret version (see Setup step 1) |
| Job fails: Apigee `403` | Runtime SA missing `apigee.admin`, or wrong Apigee org | Re-run `bootstrap.sh`; check the `_APIGEE_ORG` substitution |
| Job fails enabling APIs | Runtime SA missing `serviceUsageAdmin` | Re-run `bootstrap.sh` |

Cloud Build → History shows each build; click into a build to see per-step logs. The Job's own output (the provisioning phases) is in Cloud Run → Jobs → Logs, or linked from the `execute-job` build step.
