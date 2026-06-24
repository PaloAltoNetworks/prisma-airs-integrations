# Monolithic AIRS-on-Apigee proxy — Cloud Run pipeline

Automated deployment of the **self-contained `vertex-simple` proxy** — AIRS
prompt/response scanning **and DLP masking** baked directly into a single Apigee
API proxy, no SharedFlow. This is the Cloud Run automation of the manual proxy
published under [`Google/apigee/apiproxy`](../../apigee/apiproxy).

> **Self-contained by design.** This pipeline keeps its **own copy** of the
> `vertex-simple` bundle under [`bundles/`](bundles/) rather than referencing
> `Google/apigee/apiproxy/`, so each Cloud Run pipeline is a complete
> clone-and-run unit (the Docker build context is this folder only). Trade-off:
> the bundle lives in two places — keep this copy in sync with the canonical
> one in `Google/apigee/apiproxy/` when that changes.

> Sister pipeline: [`../flow`](../flow) deploys the **reusable
> SharedFlow** pattern instead. Pick whichever fits — see the [cloudrun README](../README.md).

## When to choose this over the SharedFlow

| | This (monolithic proxy) | SharedFlow |
|---|---|---|
| Bundles | one self-contained proxy | a SharedFlow + a thin proxy |
| DLP masking/redaction | ✅ built in | ✅ (added via the proxy's write-back policies) |
| Reuse across many proxies / LLMs | ✗ copy per proxy | ✅ edit once, all proxies inherit |
| Mental model | simplest — one thing to deploy | one extra entity (the flow) |

Choose the monolith when you have a **single LLM proxy** and want the simplest
possible footprint. Choose the SharedFlow when you front **multiple** proxies/LLMs
that should share one AIRS posture.

## How it works

```
client ──POST /vertex──> Apigee (vertex-simple proxy)
                           │  PreFlow Request:  scan prompt → (mask|block) → call Vertex
                           │  PostFlow Response: scan response → (mask|block) → return
                           ▼
                         Vertex AI :generateContent   (model from KVM, SA-authed)
```

The pipeline is a **Cloud Build → Cloud Run Job**: Cloud Build builds a
provisioner image and runs it once as a Job. The Job's `provision.sh` enables
APIs, ensures the Vertex SA (with the Apigee tokenCreator binding), upserts the
encrypted `private` KVM, and imports + deploys the proxy.

### The `private` KVM (5 entries)

The monolith reads all config from one env-scoped encrypted KVM named `private`:

| Key | Source | Purpose |
|---|---|---|
| `prisma.airs.token` | Secret Manager `airs-api-token` | AIRS scan auth (`x-pan-token`) |
| `prisma.airs.profile` | `_AIRS_PROFILE` | AIRS security profile |
| `prisma.airs.host` | `_AIRS_HOST` | AIRS endpoint host, region-bound (proxy prefixes `https://`) |
| `vertex.project` | the GCP project | Vertex target project |
| `vertex.model` | `_VERTEX_MODEL` | Vertex model — **baked in**, client doesn't pass it |

## Setup

```bash
# 1. One-time bootstrap (APIs, AR repo, secret, runtime SA + IAM)
./setup/bootstrap.sh --project=YOUR_PROJECT_ID --region=us-central1

# 2. Add the AIRS token to Secret Manager (if not passed via --airs-token)
printf '%s' 'PANW-xxxxxxxx' | gcloud secrets versions add airs-api-token --data-file=- --project YOUR_PROJECT_ID

# 3. Connect the repo to Cloud Build, then create the trigger
#    (bootstrap.sh prints the exact command — note --build-config=Google/cloudrun/proxy/cloudbuild.yaml)
```

Then push to `main` — the trigger runs the pipeline. Watch under **Cloud Build →
History**; the provisioning phases stream under **Cloud Run → Jobs → Logs**.

## Smoke test

Because the model is baked into the KVM, the client just POSTs a prompt to
`/vertex` (no model in the URL):

```bash
curl -i 'https://<your-envgroup-hostname>/vertex' \
  -H 'Content-Type: application/json' \
  -d '{"contents":[{"role":"user","parts":[{"text":"Hello"}]}]}'
```

A malicious prompt is blocked by the proxy's `RF-Block` policy; a prompt with
maskable PII (when the AIRS profile enables masking) is forwarded to Vertex with
the sensitive spans redacted.
