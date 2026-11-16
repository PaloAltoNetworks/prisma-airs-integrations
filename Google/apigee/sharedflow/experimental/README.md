# Experimental bundles

> **Superseded by [v3](../../../../Gateways/api-gateways/apigee/sharedflow-v3/).** v3 turns streaming off on the way to the model and scans the whole reply. The stream proxy here fails open when a scan errors, ignores the configured Prisma AIRS region, and never scans a last stretch of under 200 characters when the stream ends without `finishReason: STOP` (A36 in [v3's MIGRATION](../../../../Gateways/api-gateways/apigee/sharedflow-v3/MIGRATION.md#the-findings-a01-to-a39)).

> **Heads up: nothing in this folder is production-ready.** These bundles are work-in-progress reference patterns we've started but haven't validated end-to-end. They are checked in so others can collaborate, learn from, and improve them — not so they can be deployed in front of real traffic.
>
> `deploy.sh` at the repo root **does not** deploy anything from here.

## What's in here

- [`vertex-airs-stream/`](vertex-airs-stream/) — Streaming SSE proxy fronting Vertex `streamGenerateContent`. See [`vertex-airs-stream/README.md`](vertex-airs-stream/README.md) for current status and known issues.
