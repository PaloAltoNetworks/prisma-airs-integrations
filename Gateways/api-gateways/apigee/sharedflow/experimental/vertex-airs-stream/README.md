# vertex-airs-stream (experimental)

> **Status: not production-ready.** Do not deploy this in front of real traffic. The bundle is checked in as a starting point for streaming AIRS integration, but it has known reliability issues that are not yet resolved.

## What this bundle is trying to do

Front Vertex AI's `streamGenerateContent` endpoint (SSE) with Prisma AIRS scanning on both sides:

- **User prompt** — scan once at PreFlow Request via a FlowCallout into the `PANW-AIRS` SharedFlow. This part is shared with the sync proxy and works the same way.
- **Model response chunks** — scan inline from an Apigee EventFlow as SSE events arrive from Vertex, using a cumulative buffer (200-character threshold) and a sticky-block flag so once any chunk trips a detector, subsequent chunks are muted.

## Why it's experimental

Streaming on Apigee is materially different from sync:

1. **`FlowCallout` is not available inside an EventFlow.** The per-chunk scan has to call AIRS directly via Rhino `httpClient.send()`, so it can't reuse the SharedFlow for the response side.
2. **`response.streaming.enabled=true` changes the runtime in non-obvious ways.** Request streaming must stay off, or `request.content` is empty by the time the JS extractor runs. `?alt=sse` must be explicitly forwarded to the target.
3. **The Apigee Rhino response-body API varies across runtime versions.** The current code uses a fallback chain (`resp.content.asString` → `String(resp.content)` → `resp.body` → `String(resp)`), which is workable but fragile.

In our lab the happy path renders correctly and mid-stream blocks fire, but we've seen inconsistent results we don't yet trust — partial events being scanned, intermittent silent passes, and behavior that varies by model and prompt shape. Until we can characterize and fix those, we don't recommend using this bundle.

## If you want to experiment with it anyway

1. Create the `airs-config` KVM the same way the main `deploy.sh` does (encrypted, environment-scoped, keys `airs_token` and `airs_profile`).
2. Deploy the `PANW-AIRS` SharedFlow from the repo root first.
3. Zip and import this bundle manually:
   ```bash
   cd experimental/vertex-airs-stream
   zip -r ../../vertex-airs-stream.zip apiproxy
   ```
   Upload under **Develop → API Proxies → Upload Bundle** and deploy with the Vertex service account.
4. Call the proxy with `:streamGenerateContent?alt=sse` and watch the response stream.

Issues, repros, and PRs welcome — that is what this folder is here for.
