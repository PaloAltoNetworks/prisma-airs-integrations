# Prisma AIRS for Apigee X

Prisma AIRS scanning for AI traffic through Apigee X: LLM APIs (Gemini and Claude on Vertex AI, the OpenAI-compatible endpoint, Anthropic) and MCP over JSON-RPC, on the request and the reply.

| Version | Folder | Use it for |
|---|---|---|
| v3 | [`sharedflow-v3/`](sharedflow-v3/) | New deployments. The `PANW-AIRS` SharedFlow, called by FlowCallout from any proxy or from the environment's flow hooks, with a deploy script, two example proxies and an offline unit suite |
| V2 | [`sharedflow/`](sharedflow/) | Existing V2 deployments, until they move to v3. Its docs now say where its code differs from what they claimed |

- **Start here:** [sharedflow-v3/README.md](sharedflow-v3/README.md).
- **Moving from V2:** [sharedflow-v3/MIGRATION.md](sharedflow-v3/MIGRATION.md), with every change and the known defects of V2 and V1 (findings A01 to A39).
- **What was measured, and where:** [sharedflow-v3/VERIFICATION.md](sharedflow-v3/VERIFICATION.md).

## Retired

- **V1, the single-bundle Vertex AI proxy** (`apiproxy/`, `vertex-simple.zip`, and this folder's `deploy.sh`, `example.env` and `ARCHITECTURE.md`). v3 scans everything V1 scanned, without its defects (A33 to A35 and A37). It stays in this repository's history.
- **V2's experimental per-event stream proxy** (`sharedflow/experimental/`). It failed open when a scan errored, ignored the configured Prisma AIRS region, and never scanned a last stretch of under 200 characters when the stream ended without `finishReason: STOP` (A36). v3 turns streaming off on the way to the model and scans the whole reply. It stays in this repository's history.
