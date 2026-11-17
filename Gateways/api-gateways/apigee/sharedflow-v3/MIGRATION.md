# Moving from V2 to v3

V2 is the `PANW-AIRS` SharedFlow in [`../sharedflow/`](../sharedflow/), added by pull request #57. v3 replaces it under the same name. It keeps V2's FlowCallout parameters and setting names, so existing proxies keep calling it, but its defaults are stricter, some answers change, and streaming routes need the request leg in a new place.

This note lists what stays, what changes and what to do. Its last section defines the findings A01 to A39 that [README.md](README.md), [VERIFICATION.md](VERIFICATION.md) and the unit tests cite.

---

## Checklist

1. **Deploy with a service account** that holds `roles/logging.logWriter`. Apigee refuses to deploy v3 without one ([The service account](#the-service-account)).
2. **On routes that can stream,** move the request-leg FlowCallout to the TargetEndpoint PreFlow, after any step that sets `target.url`, and raise `io.timeout.millis` ([Streaming routes](#streaming-routes-where-the-request-leg-goes)).
3. **Check every setting's value.** A value v3 can't read now refuses every request.
4. **Expect refusals where V2 passed content unscanned:** endpoints v3 doesn't read, bodies it can't read, event-stream replies, and MCP batches of more than `mcpBatchLimit` members. MCP methods other than `tools/call`, and every member of a batch, are now scanned, so they can be blocked. Decide whether any route needs a setting that lets such content pass.
5. **Check what reads the answers:** MCP clients (new error codes), clients and dashboards that expect a scanner failure's HTTP 500, the `airs` object or V2's `x-airs-category` values, and proxy steps that read V2's `airs.*` variables.
6. **Set MCP servers to reply in JSON.** v3 withholds MCP event-stream replies, unless `allowOpenStreams=true` lets them pass unscanned. **On each MCP proxy, add `<Property name="success.codes">1xx,2xx,3xx,4xx,5xx</Property>` to the TargetEndpoint**, so the server's 4xx and 5xx replies reach v3's reply leg and are scanned; with Apigee's default they reach the client unscanned (A31, below).
7. **Claude Code proxies:** give Claude Code a proxy of its own and set `truncationFailClosed=false` on it. v3 skips no Claude Code call and removes no `<system-reminder>` text, and each request carries the whole conversation, so a longer session passes the 100,000-character default and, with the default, is refused from then on. With the setting, v3 scans the newest 100,000 characters of each request, lets the older part through unscanned, and logs the cut ([The size limit](README.md#the-size-limit)).
8. **New and optional:** monitor mode for a first rollout, a retry, a circuit breaker and a verdict cache, all off by default ([README, Operations](README.md#operations)), and flow hooks for proxies without a FlowCallout ([README, Flow hooks](README.md#flow-hooks)).
9. **After the upgrade, rotate the Prisma AIRS key** ([Rotate the key](#rotate-the-prisma-airs-key-after-upgrading)).

---

## What stays

- The SharedFlow's name, `PANW-AIRS`, and the FlowCallout parameter `type`, with its values `user-prompt`, `response-prompt` and `both`.
- V2's setting names: `scanType`, `currentProfile`, `toolProfile`, `prismaAirsEndpoint`, `failOpen`, `failClosedOnUnknown`, `blockStatus`, `appName`, `agentId`, `agentVersion`, `airsDescriptions` and `forceClaudeCode`. Only `scanTools` is no longer read.
- The config map `airs-config`, with the entries `airs_token` and `airs_profile`, read for the environment and cached for 300 seconds.
- The scan call: `https://<prismaAirsEndpoint>/v1/scan/sync/request`, with the key in `x-pan-token` and a 5-second timeout.
- Blocks in V2's style: HTTP 200 in the client's own format, with the headers `x-airs-blocked`, `x-airs-category` and `x-airs-scan-id`. `blockStatus` is `native` by default.
- `app_name` as `Apigee-<appName>`, `Apigee-Gateway` by default.
- Failing closed when Prisma AIRS fails: `failOpen` is `false` by default.
- LLM replies outside 2xx are not scanned: they carry no model text (A31). MCP replies outside 2xx now are (A31, below).

---

## Changed defaults

| | V2 | v3 |
|---|---|---|
| What a request's scan reads | The newest message only (A01) | Every user turn and every tool result. System and assistant text only when `scanMessageRoles` adds them |
| A request whose last message isn't a user's | Not scanned (A02) | Scanned |
| The reply's scan | The reply alone | The reply, with the prompt, as forwarded, as context in the same entry. A block on the prompt's detections alone lets the reply through, logged, when the request leg allowed or masked that prompt |
| An endpoint the SharedFlow doesn't read, or a path with a trailing slash | Passed unscanned: `failClosedOnUnknown` was `false` by default (A12) | Refused: `onScanError` is `block` by default |
| A body it can't read at an endpoint it does read: not JSON, another shape, a body the flow can't see | Passed unscanned, even with `failClosedOnUnknown=true` (A13) | Refused |
| Duplicate JSON keys | The last copy was scanned (A20) | Refused |
| A Prisma AIRS answer that isn't a clean verdict | An allow (A14, A15) | A scanner failure: refused unless `failOpen=true` |
| An HTTP 400 or 413 from Prisma AIRS | A scanner failure, so a fail-open proxy let the content through (A27) | Content that can't be inspected: refused unless `onScanError=allow` |
| Size | No limit (A27) | `maxScanChars` is 100,000; over it, the content is refused without a scan |
| Claude Code | Detected by `x-app: cli` or `x-claude-code-session-id`. Background calls weren't scanned, `<system-reminder>` text was removed from the scan, and tool results were dropped (A04) | Not detected: read like any other client's traffic, so background calls are scanned, `<system-reminder>` text stays in the scan, and tool results are read |
| Masking | Prisma AIRS's masked text written into one field, best effort (A22 to A24) | Only where the masked copy can be written back exactly; otherwise a block. `applyDlpMasking`, `false` by default, can turn a block about sensitive data only into a mask |
| A setting's value | Read loosely, without a word: any boolean value but `true` counted as `false`, so `scanTools: TRUE` turned tool scanning off (A39) | A value v3 can't read refuses every request, naming the setting |
| A `type` value other than the three | Treated as `user-prompt` | Refuses every request |
| A `type` that names the other leg, or no `type` on the reply leg | The wrong message scanned and the other passed unscanned: a `user-prompt` FlowCallout in a response flow scanned the request again | Refused, naming `type` |
| No profile in the config map | The profile name `example-profile` | Refuses every request |
| No key in the config map | HTTP 500; with `failOpen=true`, every request passed unscanned | Refuses every request, whatever `failOpen` says |
| Certificate checks on the call to Prisma AIRS | None (A26) | Strict: `SSLInfo` with `Enforce=true` |
| Event-stream replies | Passed unscanned on the runtime measured (A21) | Streaming turned off on the way to the model, the reply scanned, then sent back as one burst. An event-stream reply that still arrives is withheld |
| MCP | `tools/call` only (A17) | Every JSON-RPC message, a batch's members each scanned. `tools/list` answers go as tool events, judged with `toolProfile`, which V2 applied to `tools/call` only, so a `toolProfile` tuned for tool calls now judges tool catalogues too. Other MCP text goes as a prompt with no context on both legs, as MuleSoft sends it, so Prisma AIRS's injection detector reads server text too; the response side's `db_security` detector no longer does, and long repetitive harmless server text can be blocked as a prompt can (L11). Event-stream replies withheld and a GET for an event stream refused with 405, unless `allowOpenStreams=true` |
| WebSocket upgrades | Passed unscanned | Refused |

Settings that bring back part of V2's behaviour let content pass unscanned: `onScanError=allow`, `failClosedOnUnknown=false` (for endpoints v3 doesn't read only), `truncationFailClosed=false` and `allowOpenStreams=true` (V2 passed MCP GET streams and event-stream replies, A18). Each such pass is logged. [README.md](README.md#settings) lists every setting, its default and its values.

---

## Changed answers

### What clients see

| | V2 | v3 |
|---|---|---|
| A block's text | "PRISMA AIRS SECURITY ALERT: REQUEST BLOCKED: " and the threats found | "Request blocked by Prisma AIRS security policy." Then the threats found, and "Scan ID: ..." |
| A block's body | The client's format, plus an `airs` object (`action`, `category`, `scan_id`, `transaction_id`) | The client's format, with no `airs` object. Its ids are `chatcmpl-prisma-airs`, `resp_prisma_airs` and `msg_prisma_airs`, and its model is the request's, or `prisma-airs`. Gemini's `modelVersion` is `prisma-airs` |
| A scanner failure | HTTP 500 with `{"error": "..."}`, which the OpenAI and Anthropic SDKs retry twice by default | Answered like a block: HTTP 200 in the client's format, with `x-airs-kind: failure` |
| Content it can't inspect | Passed. With `failClosedOnUnknown=true`, an unknown endpoint got HTTP 403 with `{"error": "..."}` | A refusal in the client's format, with `x-airs-kind: refused`. An endpoint v3 doesn't read gets HTTP 403 with an OpenAI-style error |
| A configuration problem | HTTP 500 for a missing key | A refusal in the client's format, with `x-airs-kind: config`, naming the setting |
| MCP: a block, or content that can't be inspected | JSON-RPC `-32000` with no id, for a block (A29) | `-32001`, with the caller's own id |
| MCP: a scanner failure, or a configuration problem | JSON-RPC `-32603` with no id, for a failure (A29) | `-32003`, with the caller's own id |
| MCP: a refusal with no id to answer, such as a notification's | No refusal carried an id | `"id": null`, in HTTP 403, or 503 for a scanner failure or a configuration problem |
| MCP: a GET that asks for an event stream | Passed | HTTP 405, or passed with `allowOpenStreams=true` |
| MCP: a batch | Passed unscanned (A17) | Each member scanned, up to `mcpBatchLimit` (8); a larger batch refused |
| A streamed Responses API block | Chat Completions chunks (A30) | Responses API events |
| A streamed Gemini block | One JSON object (A30) | One event-stream event with `alt=sse`; a JSON array without |
| A streamed reply that is allowed | The live stream, unscanned (A21) | The whole reply at once, in the client's stream format, after the scan |
| `blockStatus` | Forced the status of every refusal V2 sent as HTTP 200 JSON: LLM blocks that weren't event streams, and every MCP JSON-RPC error. Any digits | Forces the status of every refusal kind (block, refused, failure, config) to an LLM client that doesn't stream. 100 to 599 only. Never applies to MCP |

The emoji in V2's messages is gone.

### What operators see

| | V2 | v3 |
|---|---|---|
| `x-airs-category` | The detector that fired, in V2's words (`prompt-injection`, `dlp`, `malicious-url` and so on), or `scanner-unavailable` or `unclassified` | The `category` Prisma AIRS returned, such as `malicious`. The detectors are named in the refusal's text and in the log line's `detections` |
| `x-airs-kind` | | New: `block`, `refused`, `failure` or `config` |
| Flow variables | `airs.*`, such as `airs.outcome`, `airs.category` and `airs.scan_id`, and the key in `airs.token` | `airs3.*` and `private.airs3_*`. None of V2's names is set: a proxy step that read them must read `airs3.outcome`, `airs3.category`, `airs3.scanId` or `airs3.detections` instead |
| A log line | | One per leg in Cloud Logging, log `panw-airs`, with no content and no key |
| `transaction_id` | `x-request-id`, else Apigee's `messageid` | `x-correlation-id`, else `x-request-id`, else `messageid`. An id over 100 characters, or with a space or a character outside printable ASCII, is skipped for the next source |
| `session_id` | Derived from session headers, `previous_response_id`, or a hash of the client's IP and first messages; else `messageid`, a new session per request | `Mcp-Session-Id` on MCP traffic, else `x-session-id`, else `x-claude-code-session-id`; else none |
| Scan metadata | `user_ip`; `app_user` from `x-user-id`, else Claude Code's `metadata.user_id`, else `anonymous` | No `user_ip`; `app_user` from `x-user-id`, else `apigee` |
| The profile | Always sent as `profile_name` | A UUID is sent as `profile_id`, any other value as `profile_name` |
| `prismaAirsEndpoint` | Any value | A Prisma AIRS host only |
| Apigee's Debug view | Shows the key (A25) | Never shows the key |
| `Accept-Encoding` on a scanned request | Forwarded as sent | Removed, so that a reply v3 rewrites is not compressed |
| Deployment | No service account needed | A service account is required |

---

## Streaming routes: where the request leg goes

V2's example proxy calls the request leg from the ProxyEndpoint PreFlow. On a route that can stream, v3's request leg belongs in the TargetEndpoint PreFlow, after any step that sets `target.url`.

- **Why:** on the runtime measured, the flow never sees an event stream's body (L1), so v3 turns streaming off on the way to the model. For Gemini's `:streamGenerateContent` with `alt=sse` and Claude on Vertex's `:streamRawPredict`, that means changing the target path, which works only from the TargetEndpoint's request flow. From the ProxyEndpoint, setting `target.url` has no effect (L1).
- **Left in the ProxyEndpoint,** the request leg still scans, but such a streaming call is refused, with a message that names the TargetEndpoint PreFlow. That assumes `target.url` reads empty there, which wasn't measured; if it doesn't, the reply still never passes unscanned.
- **A step of yours that sets `target.url`** must run before the FlowCallout. V2's example proxy, `vertex-airs-sync`, sets it in its TargetEndpoint PostFlow, which runs after the PreFlow: on a streaming route, that step moves into the PreFlow, ahead of the FlowCallout.
- **The reply leg** stays in the response flow. v3's examples call it from the ProxyEndpoint response PreFlow, as V2's example does.
- **Call both legs:** only the reply leg turns the reply back into the client's stream format.
- **`io.timeout.millis`:** the client now gets the reply only once the model has finished, so the whole reply must arrive within the target's timeout, 55 seconds by default. v3's examples set 120000. The ingress limit is 300 seconds.

[README.md](README.md#wiring-it-into-your-own-proxy) shows the placement in XML.

---

## The service account

v3's log step writes to Cloud Logging from inside the SharedFlow, so Apigee refuses to deploy the SharedFlow without a service account (`MISSING_SERVICE_ACCOUNT`). V2 was deployed without one.

- **Its roles:** `roles/logging.logWriter`, and `roles/iam.serviceAccountTokenCreator` on the account for Apigee's service agent, so that Apigee can mint the account's tokens. [README.md](README.md#prerequisites) has the commands.
- **With `deploy.sh`:** the account in `SA` is used for the SharedFlow and the example proxies.
- **By other means:** pass the account with the deployment, as `deploy.sh` does with the `serviceAccount` parameter of Apigee's deployments API.
- **Without one:** remove the log step and deploy by other means, since `deploy.sh` always requires `SA`; v3 then writes no log line ([README.md](README.md#logging)).

---

## Settings and headers that no longer have any effect

| | In V2 | In v3 |
|---|---|---|
| `scanTools` | `false` stopped tool results being scanned | Not read: tool results are always scanned |
| `forceClaudeCode` | Turned on Claude Code handling | Read and checked (`true` or `false`), but changes nothing |
| The headers `x-app: cli` and `x-claude-code-session-id` | Turned on Claude Code handling | Change nothing about what is scanned. `x-claude-code-session-id` is still a source of `session_id` |
| No tools, a `max_tokens` up to 4096, or `[SUGGESTION MODE:` in a Claude Code request | Skipped both legs | Change nothing |
| `previous_response_id` | A source of `session_id` | Not read |

V2 removed `<system-reminder>` blocks from Claude Code's scan text because, by V2's account, they trip the injection detector. v3 scans them as sent. With the lab's profile, the one distinct reminder a measured Claude Code session sent didn't trip it: it was allowed, through v3 and on its own (VERIFICATION.md). Other reminders weren't measured.

---

## Rotate the Prisma AIRS key after upgrading

V2 reads the key into the ordinary flow variable `airs.token`, and sets the `x-pan-token` header on a scan request message with a plain name. Apigee's Debug view shows both (A25). Measured live with v3's own scan request, before it moved to a `private.` name, a header set that way showed the key's value in Debug. So anyone who could start a Debug session on an environment running V2 could read the key, and Debug sessions recorded under V2 can still show it.

v3 holds the key only in `private.airs3_token` and sends it on the message `private.airs3_scan`; Debug then showed it nowhere. After upgrading:

1. Issue a new Prisma AIRS API key.
2. Write it to the config map's `airs_token` entry: run `deploy.sh` again with the new `AIRS_TOKEN`.
3. Wait five minutes, the config map's cache time, so that every request uses the new key.
4. Revoke the old key.
5. Delete any Debug sessions recorded while V2 ran.

---

## Upgrading

**In place.** Run v3's `deploy.sh` against the environment that runs V2. With the default names, it writes the entries of the same config map, `airs-config`, and deploys v3 as a new revision of `PANW-AIRS`. Every proxy whose FlowCallout names `PANW-AIRS` then calls v3. It also deploys the LLM example proxy, `airs-llm-guard`, unless you set `EXAMPLES=none`. V2's revision stays in the organization: to roll back, deploy that revision again ([V2's README](../sharedflow/README.md) shows the call).

**Side by side.** To try v3 first, deploy it under another name, such as `SHAREDFLOW_NAME=PANW-AIRS-v3`. The example proxies follow the name; point a test proxy's FlowCallouts at it too. Both versions read the same config map unless you set `KVM_NAME`, and `deploy.sh` rewrites both of its entries, so V2 then scans with the key and profile in v3's env file.

**What v3's `deploy.sh` does differently from V2's:**

- It reads the key only from the env file or the environment: `--airs-token` is refused.
- The SharedFlow is deployed with the service account in `SA` too, not only the example proxy.
- It reads an env file only when you name one with `--env-file`: a `.env` next to the script isn't loaded on its own.
- `APIGEE_HOST` (`--host`) replaces `HOSTNAME` (`--hostname`), and `EXAMPLES=none` replaces `SKIP_SYNC=1` (`--skip-sync`).
- It deploys the example `airs-llm-guard`, at `/airs-llm`, instead of `vertex-airs-sync`. It leaves V2's example proxy as it is. That proxy calls `PANW-AIRS` from its ProxyEndpoint. For the `generateContent` calls it is meant for, which don't stream, it needs no move; a streaming call through it fails closed. It sets none of v3's settings.

**V2's experimental stream proxy** (`experimental/vertex-airs-stream`) is retired in this release and stays in the repository's history. If you still run a copy, don't run it against v3: it reads the key from the variable `airs.token`, which v3 no longer sets, so it would scan with no key, and since it blocks only on an exact `block`, every stream would pass (A36).

---

## v3 to v3.1

Nothing to change. In API-key mode, the default, v3.1 sends Prisma AIRS the same requests as v3 and gives clients the same answers.

- **New, optional:** an OAuth 2.0 token in place of the API key ([OAuth 2.0 tokens](README.md#oauth-20-tokens)): the setting `prismaAirsAuthMode`, the config map entries `airs_bearer` and `airs_auth_mode`, and in `deploy.sh` `AIRS_AUTH_MODE`, `AIRS_BEARER` and `--bearer-only`.
- **Seen in API-key mode too:** each log line gains `auth`. The key is read only from the config map, as the README already said: v3.1 empties `private.airs3_token` before it reads the map, so a proxy's own variable of that name is never sent. The bundle has 87 policies, 8 more than v3.

---

## The findings, A01 to A39

A review of V2 found these defects: by running V2's own scripts offline with harmless marker text, by reading its code, and from Google's documentation. v3's three phases, this release, address A01 to A39. The unit suite has a case for each of A01 to A31 and A39, except A20: its V2 expectation shows the defect on V2's bundle, and its v3 expectation shows it fixed. A31's own case, the LLM reply decided in phase 3 (it passes unscanned, logged), has a v3 expectation too, and its MCP half has v3 cases (`P2NON2XX`); A20's rule is pinned by v3-only cases ([test/README.md](test/README.md)).

The measurement ids in brackets, such as L1, are defined in [VERIFICATION.md](VERIFICATION.md).

| ID | Before v3 | v3 |
|---|---|---|
| A01 | Only the newest message was read. Earlier user turns, system and developer messages, Anthropic's `system`, Gemini's `systemInstruction` and the Responses API's `instructions` never reached Prisma AIRS | Every user turn and every tool result, on every request. System and assistant text are read when `scanMessageRoles` adds `system` or `assistant`; by default they are not. Those, and the older part of a request over `maxScanChars` when `truncationFailClosed=false`, are the parts of A01 that stay with the proxy |
| A02 | A request whose last message wasn't a user's was not scanned at all: an assistant prefill in Anthropic or Chat Completions, or a system or developer message last in Chat Completions. Gemini still scanned its last turn. Measured on Claude Haiku 4.5: the card in such a request reached the model, and only the reply that repeated it was blocked. Claude Haiku 5.5 refuses a prefill (HTTP 400) | A conversation can end with anyone's message. Its user turns and tool results are scanned |
| A03 | Responses API `input` as a plain string, `input_text` parts and `function_call_output` items were not read, so the commonest Responses calls weren't scanned | Read: a string `input`, every text part, every tool output item as a tool result, `instructions` as system text, a stored prompt's `variables`, and earlier `function_call` items as assistant text |
| A04 | Any caller sending `x-app: cli` or `x-claude-code-session-id` counted as Claude Code. With no tools, a `max_tokens` up to 4096, or the text `[SUGGESTION MODE:` in the last user message, neither leg was scanned. `<system-reminder>` text was removed from the scan but still forwarded. Anthropic `tool_result` and OpenAI `role: tool` results were dropped, so a request ending in one wasn't scanned at all | No header and no text in the body changes what is scanned: there is no background-call skip, `<system-reminder>` text is scanned as sent, and tool results are always read. `forceClaudeCode` is read but has no effect in this release |
| A05 | Anthropic document and search-result blocks were not read | Read: a document's title, context and text (a text source, a content source, or a base64 source whose bytes are text), and a search result's source, title and content |
| A06 | With several choices (`n=2`), only the last choice of a non-streamed reply was scanned | Every choice is read |
| A07 | A non-streamed reply containing the text "data:" was read as an event stream, found no events, and wasn't scanned | A reply is an event stream only when its Content-Type is `text/event-stream` |
| A08 | Streamed Responses API tool-call arguments were not read | Read when v3 rebuilds an event stream. On the runtime measured, v3 turns streaming off, so the reply arrives as JSON and its `function_call` items are read. Unit tests only: no Responses endpoint was available live |
| A09 | An event whose JSON spans several `data:` lines was dropped from the scan. Today's providers send one line per event | An event's `data:` lines are joined before it is read. Unit tests only: the runtime measured never shows the flow an event stream's body |
| A10 | Gemini's reply sources (grounding, citations, URL context) were not read | Read |
| A11 | Keys inside tool arguments and results were dropped; only the values were scanned | Keys and values are scanned |
| A12 | An endpoint V2 didn't recognise passed unscanned by default: embeddings, legacy completions, Amazon Bedrock InvokeModel and Converse, Anthropic batches, a GET, or a path with a trailing slash | Refused by default (`onScanError=block`), a trailing slash included. A request with no body, such as a GET for a model list, still passes, logged, and so does its reply at a path that names no API v3 reads. Elsewhere the reply is read, as a model's answer fetched later is |
| A13 | A body V2 couldn't read at a path it recognised passed unscanned, even with `failClosedOnUnknown=true`: a body that isn't JSON, or another shape at a matching path, such as Gemini's `:batchGenerateContent`. A gzip body is not such a case on runtime 1-18-0-apigee-8: the flow sees it decompressed (L3) | Refused by default, on both legs: a body that isn't JSON, isn't the shape its path names, or arrives compressed in an encoding the flow doesn't decode. `:batchGenerateContent` is an endpoint v3 doesn't read, so it is refused too |
| A14 | A 200 from Prisma AIRS without a clean verdict (an empty body, HTML, no action, or "BLOCK" in capitals) counted as an allow, even with `failOpen=false` | Only HTTP 200 with a JSON object whose action is exactly `allow` or `block` is a verdict. Anything else, other than an HTTP 400 or 413 (A27), is a scanner failure, which `failOpen` decides |
| A15 | An allow that reported a detector error or a time-out counted as a clean allow | A scanner failure |
| A16 | If Prisma AIRS's answer on the response leg couldn't be read, the prompt's verdict variables were still set and decided the reply | Each scan starts clean: the previous verdict is cleared, a fresh response message is created before every scan, and each leg starts with every done flag false |
| A17 | MCP: only `tools/call` was recognised. `tools/list` replies, where poisoned tool descriptions live, passed unscanned, and so did `resources/read`, `prompts/get`, `initialize` and batches. The only switch that stopped them, `failClosedOnUnknown`, blocked the whole protocol | Every JSON-RPC message is MCP, whatever its method. JSON replies to every method are scanned, a `tools/list` answer as a tool event, and so are the params of every method that carries caller text. A batch's members are each scanned, in order |
| A18 | MCP: a tool result in an event-stream reply wasn't scanned. Offline, V2 read only the first event, so a notification sent first hid the result. On the runtime measured, the flow sees no event-stream body at all (L1), so such a result passed with or without a notification | An MCP event-stream reply is withheld, with JSON-RPC `-32001` and the caller's id. Set the server to reply in JSON, or set `allowOpenStreams=true` to pass such replies unscanned |
| A19 | MCP: `structuredContent`, embedded resource text and error replies weren't scanned. The text of an `isError` result was | Scanned, with the rest of the result |
| A20 | Duplicate JSON keys: V2 read the last copy. Google's documentation says proto3 backends such as Vertex AI merge the copies; for two top-level `contents` keys, Gemini answered from the last copy (L4), the one V2 read. Other shapes weren't measured | A body with a duplicate key among the keys v3 reads is refused |
| A21 | An event-stream reply's body doesn't reach the response flow on runtime 1-18-0-apigee-8 (L1), so V2 passed every event-stream reply unscanned, even with `failOpen=false` | v3 turns streaming off on the way to the model and scans the whole reply. Any 2xx reply whose body the flow can't see is withheld, other than a 202 or 204 with no body |
| A22 | Masking wrote Prisma AIRS's masked text into one field, not always the scanned one. With several text blocks, later blocks reached the model unmasked. A request ending in a tool result had the user's message overwritten and the tool result sent unmasked. With `n=2` the masked text landed in the first choice while the scanned last choice went out unmasked. Tool-call arguments were never masked. V2 still recorded the mask as applied | Masking only where the masked copy can be written back exactly, each field getting its own stretch of it. Otherwise the content is blocked |
| A23 | A non-streamed Gemini reply containing "data:" was read as an event stream. A reply on one line was scanned but never masked: it went out unchanged, with the mask recorded as applied. On Vertex AI, whose replies span many lines, V2 found no events and didn't scan the reply at all, as in A07 | A stream is recognised by its Content-Type only. A JSON reply is masked exactly, or blocked |
| A24 | MCP tool-input masking was detected but never applied, so the tool server got the sensitive arguments | MCP text is never rewritten: arguments Prisma AIRS asks to mask are refused with `-32001`, and results it asks to mask are withheld |
| A25 | The Prisma AIRS key was read into an ordinary flow variable, `airs.token`, which Apigee's Debug view shows in clear text. The `x-pan-token` header was set on a message with a plain name, which Debug shows too | The key is held only in `private.airs3_token`, and the scan request is the message `private.airs3_scan`. Measured live, the key appeared nowhere in Debug. Rotate the key after upgrading |
| A26 | The call to Prisma AIRS set no `SSLInfo`, so strict certificate checks were off: Apigee accepted a self-signed certificate (L5) | `SSLInfo` with `Enabled` and `Enforce` set to `true`. A certificate failure is a scanner failure |
| A27 | No size limit. Prisma AIRS refuses a prompt over 2,097,152 characters with HTTP 400 (L10), which V2 handled like an outage, so a fail-open proxy let the oversized prompt through | `maxScanChars`, 100,000 by default, counts the whole text of a scan: a leg's, or on an MCP leg of several scans each scan's; over it, the content is refused without a scan. An HTTP 400 or 413 from Prisma AIRS counts as content that can't be inspected (`onScanError`), never as an outage (`failOpen`) |
| A28 | Base64 image data inside tool results was sent to Prisma AIRS as text, which pushed scans toward A27's limit | Bytes are judged by what they carry. An inline file is scanned as text when its media type is text or its bytes are UTF-8; otherwise only its bytes are left out, while its name, media type and URL are scanned. Long base64 under a data key is left out only when it is binary with a known file signature |
| A29 | MCP refusals (`-32000` for a block, `-32603` for a scanner failure) carried no request id, so the client couldn't match them to its call | `-32001` for a block or content that can't be inspected, and `-32003` for a scanner failure or a configuration problem, each with the caller's own id, in HTTP 200 |
| A30 | A streamed Responses API block came back as Chat Completions chunks, and a streamed Gemini block as one JSON object | Each streaming client gets its own format: Responses API events, Anthropic events, Chat Completions chunks, a Gemini event stream with `alt=sse`, or a JSON array without |
| A31 | Non-2xx replies were never scanned | MCP, phase 2: a reply outside 2xx is read as a 2xx one is, as MuleSoft does; only a body that is empty or not JSON passes, logged. The MCP TargetEndpoint must count 4xx and 5xx as success (`success.codes`, as the example proxy does): with Apigee's default, a 4xx or 5xx target reply runs the error flow, so the reply leg doesn't run and no line is written (measured with the lab's MCP server's HTTP 400, VERIFICATION.md). LLM, phase 3: decided to keep V2's rule, unscanned and logged, since no provider puts model text into an error reply (as MuleSoft) |
| A32 | The unit harness's copy of the verdict step didn't match the real policy: it missed the MCP input-masking variable and couldn't express an unreadable verdict, so A14 and A24 couldn't fail a test | v3's test harness runs the SharedFlow's own XML and JavaScript, the verdict step included, against recorded Prisma AIRS replies ([test/README.md](test/README.md)) |
| A33 | The V1 proxy sends the caller's `X-Session-ID` as `tr_id`, or Apigee's per-request `messageid` when there is none. Prisma AIRS uses `tr_id` as a legacy session field, so without that header every request most likely becomes its own session | Phase 3 retired the V1 proxy; it stays in the repository's history. v3 itself never sends `tr_id`, and sends `session_id` only from a session header |
| A34 | The V1 proxy's masking writes the whole masked text into every text part | Phase 3 retired the V1 proxy |
| A35 | V1's `deploy.sh` creates its config map without the encrypted flag, and passes the API key on the command line, where the process list and the shell history can show it. Apigee most likely encrypts the map anyway | Phase 3 retired V1's `deploy.sh`. v3's `deploy.sh` creates the map encrypted, and takes the key only from the env file or the environment |
| A36 | The experimental stream proxy fails open when a scan errors, ignores the configured Prisma AIRS region, and never scans a last stretch of under 200 characters when the stream ends without `finishReason: STOP` | Phase 3 retired the experimental stream proxy; it stays in the repository's history. v3 turns streaming off and scans the whole reply |
| A37 | V1's `vertex-simple.zip` doesn't match the `apiproxy/` source | Phase 3 retired `vertex-simple.zip` with the V1 proxy |
| A38 | Claims in V2's README and ARCHITECTURE that the code doesn't keep, among them: that the token never appears to operators; that streaming and tool calls are fully covered; that a streamed block is a native SSE refusal; that masking rewrites in place; that the fail-closed default keeps unscanned content from the model; that poisoned tool output can't fake a skip; and V1's `tr_id` correlation | Phase 3 corrected V2's README and ARCHITECTURE where they stand, each with its finding's number. v3's README and this note describe v3 as its code behaves |
| A39 | A setting V2 couldn't read was silently replaced: any value but `true` counted as false, so `failClosedOnUnknown: True` or `scanTools: TRUE` turned a protection off without a word. V2's only check was for a missing API key, and it skipped even that when `failOpen` was on | Every setting is read strictly: booleans in any letter case, numbers within their range. Any other value refuses every request, with a message that names the setting and never its value |
