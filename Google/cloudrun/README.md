# Google Cloud Run — AIRS-on-Apigee provisioning pipelines

Git-push-driven, **Cloud Build → Cloud Run Job** automation that provisions the
Prisma AIRS + Vertex AI on Apigee X reference patterns end to end (enable APIs,
create the Vertex service account + IAM bindings, configure the encrypted KVM,
import + deploy the Apigee bundles). The sibling [`../apigee`](../apigee) folder
holds the **manual** bundles + deploy scripts; this folder automates deploying
them with no manual `gcloud`/`curl` steps.

Two self-contained pipelines — clone the repo and run whichever fits:

| Folder | Pattern | Best for |
|--------|---------|----------|
| [`flow/`](flow) | **SharedFlow** — reusable `PANW-AIRS` flow + thin `vertex-airs-sync` proxy | Many proxies/LLMs sharing one AIRS posture |
| [`proxy/`](proxy) | **Monolithic** — self-contained `vertex-simple` (scan + DLP masking baked in) | A single LLM proxy; simplest footprint |

Both: scan prompt + response via the AIRS sync API, return a graceful block on
malicious content (prompt never reaches Vertex), support DLP masking when the
AIRS profile enables it, and call Vertex as a dedicated service account (with
the Apigee `tokenCreator` binding wired automatically).

## Self-contained by design

Each pipeline carries its **own copy** of the Apigee bundles under its
`bundles/` folder, rather than referencing the canonical bundles in
[`../apigee`](../apigee):

- `flow/bundles/` ↔ `../apigee/sharedflow/` (`PANW-AIRS`, `vertex-airs-sync`)
- `proxy/bundles/vertex-simple/` ↔ `../apigee/apiproxy/`

This is deliberate: it keeps each pipeline a complete **clone-and-run** unit and
lets the Docker build context be the pipeline folder only (no reaching across
the repo). The trade-off is that each bundle exists in two places — when you
change a canonical bundle in `../apigee`, update the matching copy here.

## Quick start

```bash
cd flow      # or: cd proxy
cat README.md
./setup/bootstrap.sh --project=YOUR_PROJECT_ID --region=us-central1
```

Each pipeline gets its own Cloud Build trigger pointed at that folder's
`cloudbuild.yaml` (e.g. `--build-config=Google/cloudrun/flow/cloudbuild.yaml`).
The GitHub-App connection is 1st-gen, so triggers are created with
`--region=global` while resources deploy to `_REGION` (default `us-central1`).
See each folder's README for the full bootstrap → trigger → push flow.

## Prerequisites

An Apigee X org (evaluation is fine), a Prisma AIRS API token + security
profile, and an account with Owner (or equivalent) on the GCP project to run
the one-time `bootstrap.sh`. The Vertex service account and its IAM bindings are
created by the pipeline.
