# Correlation and identity fields

This page covers what the policy puts in each Prisma AIRS scan request, where each value comes from, and how to follow a blocked request from the client to the gateway log to the AIRS scan record.

Everything under "Measured" was observed on a managed Omni Gateway 1.12.12 (Model Proxy, Anypoint trial, Sandbox) in November 2026. The scan records were read back through the AIRS scan-results API.

## The fields

| AIRS field | Where the value comes from, first usable one wins | When there is none |
|---|---|---|
| `transaction_id` | the `x-correlation-id` request header, then `x-request-id` | left out |
| `session_id` | the Session Header (default `x-session-id`), then the verified token claim named in Session Claim | left out (AIRS then assigns its own `pan_<uuid>`) |
| `metadata.app_user` | the verified token claim named in User Claim, then the User Header, then the client application's name, then its client ID | `anonymous` |
| `metadata.app_name` | `MuleSoft`, or `MuleSoft-<suffix>` when Application Name Suffix is set | always sent |
| `metadata.ai_model` | the model the request names (the body's `model`, or the model in a Gemini path) | left out |
| `ai_profile` | the Profile Map entry for the client application's exact name, then the map's fallback; without a map, the configured profile name or ID | always sent |
| `tr_id` | never sent (see below) | |

### Which values are usable

An ID value is used only if it meets these rules:

- After trimming, it is printable ASCII.
- It is at most 100 characters long.

An unusable value is never shortened, because a cut ID would point at the wrong records. Instead the policy moves on to the next source in the table. If no session value is usable, the evidence line records the reason in `session_id_dropped` (`not_printable_ascii` or `too_long`).

### Verified claims

Session Claim and User Claim read the claims of a token that a JWT validation policy has already verified. That policy must run before this one in the chain.

## Measured

### Correlation ID

- A caller's `x-correlation-id` is kept. The reply echoes it back, and AIRS records it as `transaction_id`.
- When the caller sends none, the gateway generates a UUID. It returns that UUID in the reply's `x-correlation-id` header, and the policy sends the same UUID as `transaction_id`.
- Either way, a client can match any reply to its AIRS scan through the reply's `x-correlation-id`.
- A caller can choose its own correlation ID, so treat it as a correlation aid, never as an identity.

### Session ID

- `x-session-id` becomes `session_id`. AIRS also copies it into `tr_id`, the legacy session field.
- Without a session value, the policy sends no `session_id`, and AIRS assigns `pan_<uuid>`.

### JWT claims

MuleSoft's JWT Validation policy 0.11.1 ran before this one:

- The token's `sid` claim, configured as Session Claim, became the AIRS `session_id`.
- When the request also carried `x-session-id`, the header won. A session header comes before the session claim, and a user claim comes before the user header.
- On this gateway, 0.11.1 was the newest JWT Validation version API Manager offered. Version 1.4.1 was refused, because it has no implementation for Flex 1.12.12.

## Following a blocked request

1. **The client.** The error body says `Request blocked by Prisma AIRS security policy. Scan ID: <scan_id>.`, and the reply carries `x-correlation-id`.
2. **The gateway log.** Each request writes one line that starts with `prisma-airs-guardrails evidence ` and continues with a JSON record. The record holds:
   - `transaction_id`, `decision`, `status`, `format`, `streamed` and `routed_model`;
   - one entry in `legs` per scan, with `outcome`, `action`, `scan_id`, `report_id`, `ms` and `detections`.

   The line never contains the API key or the scanned content.

   A managed gateway does not show these lines in Runtime Manager (see the README's Troubleshooting section). There, go from the client's scan ID straight to step 3.
3. **Prisma AIRS.**
   - `GET /v1/scan/results?scan_ids=<scan_id>` returns the verdict, with `session_id` and `report_id`.
   - `GET /v1/scan/reports?report_ids=<report_id>` returns `transaction_id`, `session_id` and the detection results.
   - Both calls use the same API key, in `x-pan-token`.

## Why not `tr_id`

The repo's CONTRIBUTING suggests overriding `tr_id` with the platform's own unique ID. Do not do that here:

- AIRS treats `tr_id` as a legacy alias of the session slot, not of `transaction_id`. The measurement above confirms it: AIRS copied `session_id` into `tr_id`.
- So sending a per-request ID in `tr_id` would turn every request into its own session.

The policy therefore sends `transaction_id` per request and `session_id` per conversation, as the repo's `CLAUDE.md` requires. The live findings behind this rule are in `Hooks/docs/airs-correlation-id-findings.md`.
