# Prisma AIRS SharedFlow for Apigee X (v3)

`PANW-AIRS` is an Apigee X SharedFlow that scans AI traffic with Prisma AIRS (AI Runtime Security) and enforces the verdict inline. A proxy calls it with a FlowCallout on each leg:

- **The request** is scanned before it reaches the model or the MCP server.
- **The reply** is scanned before it reaches the client.

It reads five APIs, streamed and not, tool calls included:

- OpenAI Chat Completions, including Azure OpenAI and Vertex AI's OpenAI-compatible endpoint;
- the OpenAI Responses API;
- Anthropic Messages, including Claude on Vertex;
- Gemini and Vertex AI `generateContent`;
- MCP over JSON-RPC.

It fails closed by default: content that Prisma AIRS can't scan, or that v3 can't inspect, is refused, not passed. The few things it passes unscanned, such as an LLM reply outside 2xx and a request with no body, are each logged ([What v3 doesn't read, refuses or passes](#what-v3-doesnt-read-refuses-or-passes)).

This is v3, phases 1 to 3: phase 2 reads MCP completely, batches included, and phase 3 adds the [operations settings](#operations) and [flow hooks](#flow-hooks). It keeps V2's SharedFlow name and FlowCallout parameters, so existing proxies keep calling it, but its defaults are stricter and some answers change. Read [MIGRATION.md](MIGRATION.md) before you upgrade. V2 stays in [`../sharedflow/`](../sharedflow/).

---

## v3 and V2 at a glance

A proxy calls v3 the way it calls V2. What changes is what happens to its traffic:

| | V2 | v3 |
|---|---|---|
| **Request text scanned** | The newest message only | Every user turn and every tool result, on every request |
| **Claude Code** | Background calls skipped and tool results dropped. Any caller could get the same skip by sending a header | Scanned like any other client. No header or body text turns a scan off |
| **Responses API** | The commonest requests not read: a plain-string `input`, `input_text` parts, tool outputs | Read in full |
| **Streamed replies** | Passed unscanned: on the runtime measured, the flow can't see a stream's body | Streaming turned off on the way to the model. The whole reply is scanned, then sent in the client's own stream format, all at once |
| **MCP** | `tools/call` only | Every JSON-RPC message in both directions, tool lists and batches included |
| **Content it can't read** | Passed unscanned | Refused, unless a setting lets it pass, logged |
| **An unclear answer from Prisma AIRS** | Counted as an allow | A scanner failure, which `failOpen` decides (closed by default) |
| **Size limit** | None | 100,000 characters per scan, adjustable |
| **Masking** | Best effort: some text went out unmasked | Exact, or the content is blocked |
| **A setting value it can't read** | Quietly treated as `false` | Every request refused, with a message that names the setting |
| **The Prisma AIRS key** | Shown in Apigee's Debug view | Never shown |
| **A scanner failure, as the client sees it** | HTTP 500, which the OpenAI and Anthropic SDKs retry | A refusal in the client's own format, with `x-airs-kind: failure` |
| **Log lines** | None | One per leg in Cloud Logging, with no content and no key |

### New in v3

Each is off until you turn it on:

| Feature | What it does | Turn it on |
|---|---|---|
| **Monitor mode** | Scans and logs as usual, but refuses and masks nothing: a safe first rollout | `enforcementMode=monitor` |
| **Retry** | One more try when Prisma AIRS doesn't answer, or answers 429 or a 5xx | `scanRetries=1` |
| **Circuit breaker** | After a run of failures, stops calling Prisma AIRS for a cooldown; `failOpen` decides in the meantime | `breakerFailures`, `breakerCooldownS` |
| **Verdict cache** | Keeps each allow for a time you set, up to 5 minutes, so the same text isn't scanned twice | `verdictCacheTtlS` |
| **Flow hooks** | Scans proxies that have no FlowCallout of their own, from the environment's flow hooks | `HOOK_ROUTES` in `deploy.sh` |

The cache and the breaker keep their state in the environment's cache, which every proxy deployed there shares: read [Operations](#operations) before you turn them on.

New settings also choose what is scanned: `scanMessageRoles` adds system and assistant text, `maxScanChars` and `truncationFailClosed` set the size limit and what happens past it, `applyDlpMasking` turns a block for sensitive data alone into a mask, and `allowOpenStreams` and `mcpBatchLimit` tune MCP ([Settings](#settings)).

Upgrading from V2 takes a few steps, among them a service account and a key rotation: see [Moving from V2](#moving-from-v2).

---

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | Yes | Every user turn and every tool result of the request is scanned before it is forwarded, not only the newest, in every LLM API above. Text inside non-text parts is read too: Anthropic documents and search results, inline files that hold text, and the text a data URI carries. System and assistant text are scanned only when `scanMessageRoles` adds them. |
| Response | Yes | The reply is scanned before it reaches the client, with the prompt as context: every choice or candidate, the tool calls it makes, and the sources it cites. |
| Streaming | Partial | On the runtime measured, the flow can't see an event stream's body. So v3 turns streaming off on the way to the model, scans the whole reply, and sends it back as one burst in the client's own stream format. The client gets the reply all at once, not token by token. An MCP reply sent as an event stream is withheld. |
| Pre-tool call | Yes | Tool calls in the model's reply are scanned, arguments included, before they reach the agent that would run them. MCP `tools/call` arguments are scanned before the MCP server runs them, and a block is refused in-protocol with JSON-RPC error `-32001`. |
| Post-tool call | Yes | Tool results the agent sends back are scanned on every request: OpenAI `role: tool`, Anthropic `tool_result`, Gemini `functionResponse` and Responses API tool outputs. MCP tool results and tool lists are scanned before they reach the client, when the server replies in JSON. |

**Legend:** Yes: full support. Partial: supported, with the conditions in the description. No: not supported.

[VERIFICATION.md](VERIFICATION.md) lists each claim and where it was measured: live on Apigee X with Gemini and Claude on Vertex AI, Vertex AI's OpenAI-compatible endpoint, an MCP server and a Prisma AIRS tenant, or in the offline unit suite. A Responses API endpoint was not available for the live tests, so some Responses API rows are unit-tested only; VERIFICATION.md names them.

---

## How it works

1. **Request leg.** The proxy calls the SharedFlow from its TargetEndpoint PreFlow with `type=user-prompt`. v3 works out the API from the path (or from the body, for MCP), reads the text the request carries, and calls the Prisma AIRS synchronous scan API: once, or for some MCP messages up to 8 times, one after another (see [MCP messages](#mcp-messages)).
   - **Allowed:** the request goes on to the model. If the client asked for a stream, v3 first turns streaming off (see [Streaming](#streaming)).
   - **Masked:** the masked copy goes on instead (see [Masking](#masking)).
   - **Blocked:** the client gets a refusal in its own format, and the model is never called.
2. **Reply leg.** The proxy calls the SharedFlow from its response flow with `type=response-prompt`. v3 scans the reply, with the prompt as context. MCP text goes without context (see [MCP messages](#mcp-messages)).
   - **Allowed:** the reply goes to the client, in the client's stream format if v3 turned streaming off.
   - **Blocked:** the reply is replaced with a refusal.
3. **No verdict, or content it can't inspect.** If Prisma AIRS gives no clean verdict, the content is refused unless `failOpen=true`. If v3 can't inspect the content (an endpoint it doesn't read, a body it can't parse, content over the size limit), it is refused unless a setting lets it pass: `onScanError=allow`, `failClosedOnUnknown=false` for an endpoint v3 doesn't read, or `truncationFailClosed=false`, which scans part of content over the size limit.

Nothing the caller sends decides what gets scanned. No header switches scanning off or changes the reader, and the API is never taken from a header.

---

## Prerequisites

- **Apigee X**, with an environment that allows shared flows and the JavaScript and ServiceCallout policies: Intermediate or Comprehensive. A Pay-as-you-go Base environment allows none of them.
  - v3 was measured on runtime 1-18-0-apigee-8, on an evaluation organization ([VERIFICATION.md](VERIFICATION.md)).
  - Not covered: Apigee hybrid, Apigee Edge, and the Apigee Extension Processor, where a ServiceCallout can't run.
- **A service account** for the deployment. The SharedFlow's log step writes to Cloud Logging, so Apigee refuses to deploy it without one (`MISSING_SERVICE_ACCOUNT`). It needs:
  - `roles/logging.logWriter`;
  - `roles/aiplatform.user`, for the LLM example's calls to Vertex AI.

  Apigee's service agent (`service-<project number>` in `gcp-sa-apigee.iam.gserviceaccount.com`) needs `roles/iam.serviceAccountTokenCreator` on the account, so that Apigee can mint the account's tokens at runtime (Google's prerequisite for [Google authentication in Apigee](https://cloud.google.com/apigee/docs/api-platform/security/google-auth/overview)).
- **Prisma AIRS:** an API key and a security profile (its name or its UUID). Keys are bound to a region: set `prismaAirsEndpoint` to that region's host.
- **To deploy with `deploy.sh`:** bash, `gcloud` signed in with Apigee admin rights on the organization, `curl`, `jq` and `zip`. Deploying with a service account also takes `iam.serviceAccounts.actAs` on that account, for example through `roles/iam.serviceAccountUser` (an owner of the project already has it).
- **To run the unit tests:** Node.js. No packages, no network.

The service account, with the names `example.env` uses:

```bash
PROJECT=your-gcp-project-id
PROJECT_NUMBER="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')"
SA="apigee-airs@${PROJECT}.iam.gserviceaccount.com"

gcloud iam service-accounts create apigee-airs --project="$PROJECT"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA}" --role="roles/logging.logWriter"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:${SA}" --role="roles/aiplatform.user"
gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT" \
  --member="serviceAccount:service-${PROJECT_NUMBER}@gcp-sa-apigee.iam.gserviceaccount.com" \
  --role="roles/iam.serviceAccountTokenCreator"
```

---

## Quick start

Copy the settings file, fill in `PROJECT`, `ENV`, `SA`, `AIRS_TOKEN` and `AIRS_PROFILE`, and deploy. The file holds the Prisma AIRS key: keep it private and out of version control.

```bash
cp example.env .env
chmod 600 .env
./deploy.sh --env-file=.env
```

`deploy.sh`, in order:

1. Creates the config map `airs-config` in the environment, encrypted, unless it exists, and writes its two entries, `airs_token` and `airs_profile`. It never prints the key.
2. Imports the SharedFlow as a new revision of `PANW-AIRS` (or of `SHAREDFLOW_NAME`) and deploys it with the service account.
3. Imports and deploys the example proxies named in `EXAMPLES` (`llm` by default), with the same service account.
4. Waits until each deployment reports READY, up to five minutes each, and stops if one reports ERROR.
5. With `HOOK_ROUTES` set, sets up the [flow hooks](#flow-hooks) after the SharedFlow and before the example proxies.
6. With `APIGEE_HOST` set and `llm` in `EXAMPLES`, prints smoke-test commands for the LLM example.

It asks `gcloud` for a fresh access token before each call. If `gcloud` gives none, it stops and asks you to run `gcloud auth login`.

Run it again to change the key or the profile, or to deploy a new revision: it rewrites its entries (`airs_hook` too, with `HOOK_ROUTES`) and deploys with `override=true`. `./deploy.sh -h` lists the options.

| Variable | Option | Default | What it is |
|---|---|---|---|
| `PROJECT` | `--project=ID` | (required) | The Google Cloud project; also the Apigee organization unless `ORG` is set |
| `ENV` | `--env=NAME` | (required) | The Apigee environment to deploy into |
| `SA` | `--sa=EMAIL` | (required) | The service account the SharedFlow and the example proxies run as |
| `AIRS_TOKEN` | none | (required) | The Prisma AIRS API key. Accepted only from the env file or the environment: `--airs-token` on the command line is refused, because other users of the machine could see it. The script hands the key on to jq and curl the same way, never on their command lines, and never prints it |
| `AIRS_PROFILE` | `--airs-profile=NAME` | (required) | The security profile: its name or its UUID |
| `ORG` | `--org=NAME` | `PROJECT` | The Apigee organization, if it isn't the project id |
| `KVM_NAME` | `--kvm-name=NAME` | `airs-config` | The config map's name. The SharedFlow's copy is changed to match |
| `SHAREDFLOW_NAME` | `--sharedflow-name=NAME` | `PANW-AIRS` | The SharedFlow's name. The example proxies' FlowCallouts follow it |
| `EXAMPLES` | `--examples=LIST` | `llm` | The example proxies to deploy: `llm`, `mcp`, `llm,mcp` or `none` |
| `LLM_PROXY_NAME`, `MCP_PROXY_NAME` | none | `airs-llm-guard`, `airs-mcp-guard` | The example proxies' names |
| `MCP_URL` | `--mcp-url=URL` | (required with `mcp`) | The MCP server the MCP example forwards to: `https://host[:port][/path]`, with no query string |
| `APIGEE_HOST` | `--host=HOST` | none | Your environment group's host name, to print smoke-test commands |
| `SMOKE_MODEL` | none | `gemini-3.8-flash` | The Gemini model the smoke tests name |
| `HOOK_ROUTES` | `--hook-routes=LIST` | none | [Flow hooks](#flow-hooks): the base paths v3 scans from the environment's hooks, comma-separated, each exactly as the proxy's base path (`/airs-llm`, no `/` at the end) |
| `HOOK_SETTINGS` | `--hook-settings=JSON` | `{}` | Settings for those routes, a JSON object of names and values |
| `HOOK_ATTACH` | `--hook-attach=yes\|no` | `yes` | `no` writes `airs_hook` and deploys the hook SharedFlows without attaching them, for hook points that hold a SharedFlow of yours |

Options on the command line override the env file. `KVM_NAME`, `SHAREDFLOW_NAME`, `LLM_PROXY_NAME` and `MCP_PROXY_NAME` take letters, digits, `.`, `_` and `-` only.

### The example proxies

| Proxy | Base path | Forwards to | For |
|---|---|---|---|
| [`airs-llm-guard`](examples/airs-llm-guard/apiproxy/) | `/airs-llm` | `https://aiplatform.googleapis.com`, with a Google access token for the deployment's service account | Gemini, Claude on Vertex, and Vertex AI's OpenAI-compatible endpoint |
| [`airs-mcp-guard`](examples/airs-mcp-guard/apiproxy/) | `/airs-mcp` | `MCP_URL` | An MCP server over Streamable HTTP, set to reply in JSON |

Both examples:

- set the main settings, each at its default, in `AM-AirsSettings`, in the ProxyEndpoint request PreFlow, so you can see and change them;
- call the request leg from the TargetEndpoint PreFlow and the reply leg from the ProxyEndpoint response PreFlow;
- set `io.timeout.millis` to 120000.

The MCP example also counts every status as success on its TargetEndpoint (`success.codes`), so an MCP server's 4xx or 5xx reply reaches the reply leg and is scanned.

Clients reach the LLM example on Vertex AI's own paths, after the base path:

- **Gemini:** `https://apigee.example.com/airs-llm/v1/projects/your-gcp-project-id/locations/global/publishers/google/models/gemini-3.8-flash:generateContent`, or `:streamGenerateContent`.
- **Vertex AI's OpenAI-compatible endpoint:** base URL `https://apigee.example.com/airs-llm/v1/projects/your-gcp-project-id/locations/global/endpoints/openapi`, model `google/gemini-3.8-flash`. The OpenAI SDK adds `/chat/completions`.
- **Claude on Vertex:** `.../publishers/anthropic/models/YOUR_CLAUDE_MODEL:rawPredict`, or `:streamRawPredict`.

Here `apigee.example.com` stands for your environment group's host name (`APIGEE_HOST`) and `your-gcp-project-id` for your project.

For the MCP example, set `MCP_URL` to the server's base URL and point MCP clients at `https://apigee.example.com/airs-mcp/mcp`: a path suffix that ends in `/mcp` marks the route as MCP. If the server's endpoint isn't at `/mcp`, set `MCP_URL` to its full URL, point clients at `https://apigee.example.com/airs-mcp` with nothing after the base path (Apigee appends the path suffix to `MCP_URL`), and add `<Parameter name="apiFormat">mcp</Parameter>` to both of the example's FlowCallouts.

---

## Wiring it into your own proxy

Each leg is one FlowCallout to `PANW-AIRS`. The examples hold both:

```xml
<FlowCallout continueOnError="false" enabled="true" name="FC-AirsRequest">
  <Parameters>
    <Parameter name="type">user-prompt</Parameter>
  </Parameters>
  <SharedFlowBundle>PANW-AIRS</SharedFlowBundle>
</FlowCallout>
```

`FC-AirsResponse` is the same, with `response-prompt`.

| Leg | FlowCallout | Where | Why |
|---|---|---|---|
| Request | `type=user-prompt` | The TargetEndpoint PreFlow, Request, after any step of yours that sets `target.url`. With several TargetEndpoints, in each one's PreFlow | To turn a Gemini `alt=sse` or Claude on Vertex stream off, v3 changes `target.url`. That works only from the TargetEndpoint's request flow: from the ProxyEndpoint, setting `target.url` has no effect (L1). A step that sets `target.url` after v3 would undo the change |
| Reply | `type=response-prompt` | The ProxyEndpoint PreFlow, Response | The placement the examples use, and the one every live test used |

```xml
<TargetEndpoint name="default">
  <PreFlow name="PreFlow">
    <Request>
      <Step><Name>FC-AirsRequest</Name></Step>
    </Request>
    <Response/>
  </PreFlow>
  <HTTPTargetConnection>
    <URL>https://YOUR_PROVIDER_HOST</URL>
    <Properties>
      <Property name="io.timeout.millis">120000</Property>
    </Properties>
  </HTTPTargetConnection>
</TargetEndpoint>
```

```xml
<ProxyEndpoint name="default">
  <PreFlow name="PreFlow">
    <Request>
      <Step><Name>AM-AirsSettings</Name></Step>
    </Request>
    <Response>
      <Step><Name>FC-AirsResponse</Name></Step>
    </Response>
  </PreFlow>
  <!-- HTTPProxyConnection and RouteRule as usual -->
</ProxyEndpoint>
```

What to keep in mind:

- **`type` must match the flow the FlowCallout sits in.** Use `user-prompt` in a request flow, and `response-prompt` or `both` in a response flow. v3 checks this: the reply's status exists only on the reply leg. A FlowCallout whose `type` names the other leg, or a reply-leg FlowCallout with no `type` (whose default is `user-prompt`), is refused with a `config` refusal that names `type`, so a misplaced FlowCallout never scans one message and passes the other.
- **Call both legs on a route that can stream.** The request leg turns streaming off; only the reply leg puts the reply back into the client's stream format. Without it, a client that asked for a stream gets plain JSON.
- **Settings** are flow variables, set before the request-leg FlowCallout. They last the whole call, so the reply leg reads the same values. The examples set them with an AssignMessage step, `AM-AirsSettings`, in the ProxyEndpoint request PreFlow.
- **`apiFormat`.** v3 knows the API by the end of the path suffix, the part of the path after the proxy's base path: `/chat/completions`, `:generateContent` and so on (see [What v3 reads](#what-v3-reads)). If a route's path suffix doesn't end in the provider's own path, for example a proxy whose base path is the whole path, set `apiFormat` on both FlowCallouts. The path also tells v3 that a Gemini or Claude on Vertex call streams, so keep the provider's path on routes that stream that way: otherwise their event-stream replies are withheld.
- **`io.timeout.millis`.** With streaming turned off, the whole reply must reach Apigee within the target's `io.timeout.millis`: 55 seconds by default. The examples set 120000. The ingress limit of 300 seconds can't be changed.
- **Keep `continueOnError="false"` on both FlowCallouts,** as the examples and every live test do. v3 refuses by raising a fault (RaiseFault).
- **Fault rules.** A refusal puts the proxy into its error flow. A FaultRule or DefaultFaultRule of yours that assigns its own response replaces v3's refusal.
- **A proxy that calls only the reply leg** gets no prompt scan, and its event-stream replies are withheld, since nothing turned streaming off. Remove `Accept-Encoding` from the request yourself, as the request leg does, so that a reply v3 masks is not compressed. The reply of an endpoint v3 doesn't read, to a request that had a body, is withheld unless `onScanError` lets it pass.
- **Flow hooks:** for proxies with no FlowCallout of their own, v3 can run from the environment's flow hooks instead: see [Flow hooks](#flow-hooks).

---

## Settings

v3 reads each setting from the flow variable of that name, and in [hook mode](#flow-hooks) from `airs_hook`'s settings alone. An unset or empty variable takes the default. A value v3 can't read refuses every request, in the client's format, with a message that names the first such setting and never its value; MCP clients get JSON-RPC error `-32003`. Booleans are `true` or `false` in any letter case.

**Settings that let content pass unscanned:** `failOpen=true`, `onScanError=allow`, `failClosedOnUnknown=false` `truncationFailClosed=false`, `allowOpenStreams=true` and `enforcementMode=monitor`. Each pass they allow writes a log line. Separately, with the default `scanMessageRoles`, system and assistant text is never scanned.

| Setting | Default | Values | What it does |
|---|---|---|---|
| `type` (FlowCallout parameter) | `user-prompt` | `user-prompt`, `response-prompt`, `both`, exactly as written | The leg. `user-prompt` scans the request before it is forwarded. `response-prompt` scans the reply before it reaches the client, with the prompt as context. `both`, on the reply leg, judges the prompt and the reply together, so a detection in either blocks the reply; the prompt has reached the model by then. On MCP, the request's own scans run first, then the reply's, all in the 8 scan slots (a request with no body, such as a `GET` or a `DELETE`, has none): a request tool event that the reply's tool event repeats within `maxScanChars` is judged once, and a batch of 5 text requests needs 10 scans, so it is refused, or with `onScanError=allow` the request scans past the slots pass unscanned, logged. Any other value refuses, and so does a value that names the other leg |
| `apiFormat` (FlowCallout parameter) | unset | `openai-chat`, `openai-responses`, `anthropic`, `gemini`, `mcp` | The API, for a route whose path suffix doesn't name it. Used only when the path doesn't decide. `mcp` also makes the route an MCP route, so that a refusal with no JSON-RPC body to go by is a JSON-RPC error, and a GET for an event stream gets 405 |
| `scanType` | unset | `prompt`, `response`, `both` | V2's form of `type`, read only when `type` is unset. It must match the leg too |
| `failOpen` | `false` | `true`, `false` | What happens when Prisma AIRS gives no verdict: no answer within 5 seconds, a refused connection or certificate, an HTTP status other than 200, 400 or 413, or a 200 without a clean `allow` or `block`. `false` refuses. **`true` lets the content pass unscanned**, logged |
| `onScanError` | `block` | `block`, `allow` | What happens to content v3 can't inspect: an endpoint it doesn't read, a body that isn't JSON or isn't the shape its path names, duplicate keys, a body the flow can't see, a body or scan text over the size limits, an LLM request with nothing v3 can read, an event-stream reply, an MCP batch over `mcpBatchLimit`, an MCP leg that needs more than 8 scans, a body on an MCP route that isn't JSON-RPC, a WebSocket upgrade, an ambiguous path, or an HTTP 400 or 413 from Prisma AIRS. `block` refuses. **`allow` lets all of it pass unscanned**, logged; content over `maxScanChars` then passes with no scan at all, unless `truncationFailClosed=false`, which still scans part of it. On an MCP leg of several scans, a gap counts for its own scan only: `allow` lets that scan pass unscanned and the others still run, and past 8 scans the first 8 still run |
| `failClosedOnUnknown` | unset (refuses, as `true` does) | `true`, `false` | V2's setting, still read. `true` is the same as `onScanError=block`. **`false` lets requests to endpoints v3 doesn't read, and their replies, pass unscanned**, logged; a path with a trailing slash counts as such an endpoint. A body v3 can't read at an endpoint it does read is still refused, and so is a body on an MCP route that isn't a JSON-RPC message or batch. When both are set, `onScanError` wins |
| `scanMessageRoles` | `user` | a comma-separated list of `user`, `tool`, `system`, `developer`, `assistant` | What the request leg reads besides user turns and tool results, which it always reads. `system` (or `developer`) adds system text: system and developer messages, Anthropic's top-level `system`, Gemini's `systemInstruction` and the Responses API's `instructions`. A message with role `system` inside Anthropic's `messages` is read like a user turn, whatever this setting says. `assistant` adds the assistant's earlier turns, its tool calls and a prefill. Any other word refuses |
| `maxScanChars` | `100000` | a whole number from 1 to 2097152 | The most characters one scan holds: the request's text on the request leg, the reply's on the reply leg. The prompt sent with a reply as context is cut to the same number and doesn't count. On an MCP leg of several scans each scan has this limit, so the leg can scan up to 8 times as much. See [The size limit](#the-size-limit) |
| `truncationFailClosed` | `true` | `true`, `false` | Over `maxScanChars`, `true` refuses without a scan. **`false` scans part and lets the rest pass unscanned**, logged: the newest part of a request, the first part of a reply, and the first part of any MCP text, as MuleSoft does. Set `false` on a proxy for Claude Code or another agent: see [The size limit](#the-size-limit) |
| `applyDlpMasking` | `false` | `true`, `false` | `true` turns a block whose detections are all sensitive data into a mask, when Prisma AIRS returned a masked copy. See [Masking](#masking) |
| `blockStatus` | `native` | `native`, or an HTTP status from 100 to 599 | `native` keeps v3's own statuses: HTTP 200 in the client's format for every API it reads (see [What clients see](#what-clients-see)). A status forces that code on every refusal to an LLM client that doesn't stream. It never applies to MCP, to a streaming client, or to an endpoint v3 doesn't read |
| `currentProfile` | the config map's `airs_profile` | a profile name, or its UUID | The security profile for LLM and MCP text scans. A UUID is sent as `profile_id`, anything else as `profile_name` |
| `toolProfile` | the profile above | a profile name, or its UUID | The profile for MCP tool events: `tools/call`, and the answer to `tools/list` |
| `prismaAirsEndpoint` | `service.api.aisecurity.paloaltonetworks.com` | `service.api.aisecurity.paloaltonetworks.com`, or `service-XX.api.aisecurity.paloaltonetworks.com` where `XX` is a two-letter region code, such as `de` | The Prisma AIRS host for your key's region. A host name only, with no scheme or path. Any other host refuses, so the key can't be sent anywhere else |
| `appName` | `Gateway` | 1 to 64 letters, digits, spaces, `.`, `_` or `-` | Sent as `app_name`: `Apigee-<appName>` |
| `agentId` | the request's `X-Agent-ID` header, else `x-claude-code-agent-id` | up to 100 characters | Sent as `agent_meta.agent_id`. A longer value is left out |
| `agentVersion` | unset | text; the first 100 characters are sent | Sent as `agent_meta.agent_version`, with `agentId` |
| `airsDescriptions` | V2's texts | a JSON object that maps a detection name to its text | The text that names a detection in a block message, for example `{"dlp":"Sensitive data detected"}`. The names are `url_cats`, `dlp`, `injection`, `toxic_content`, `malicious_code`, `agent`, `topic_violation`, `db_security` and `ungrounded` |
| `mcpBatchLimit` | `8` | a whole number from 1 to 8 | The most messages an MCP batch may hold. A larger batch is refused before any scan, as content v3 can't inspect (`onScanError`); on a proxy that calls v3 on its reply leg only, its reply is withheld. At most 8, the SharedFlow's scan slots (see [MCP messages](#mcp-messages)) |
| `allowOpenStreams` | `false` | `true`, `false` | **`true` lets an MCP GET for an event stream, and an MCP reply sent as an event stream, pass unscanned**, logged: only on an MCP route (a path ending in `/mcp` or `/mcp/`, or `apiFormat=mcp`) or to a JSON-RPC request at a path that names no API v3 reads, and only when the request is all JSON-RPC, so an LLM body dressed as JSON-RPC opens nothing. A GET for an event stream needs an MCP route. `false` answers the GET with 405 and withholds the reply. See [MCP messages](#mcp-messages) |
| `forceClaudeCode` | `false` | `true`, `false` | Read and checked, but it changes nothing in this release: v3 scans Claude Code traffic like any other, `<system-reminder>` text included |
| `enforcementMode` | `enforce` | `enforce`, `monitor` | **`monitor` lets everything through**: every leg is still scanned, and logged as what v3 would have done, but nothing is refused or masked. See [Operations](#operations) |
| `scanRetries` | `0` | `0`, `1` | `1` makes one more call when a scan gets no answer, HTTP 429 or a 5xx |
| `breakerFailures` | `0` (off) | a whole number from 0 to 100 | After this many scanner failures in a row, Prisma AIRS isn't called for `breakerCooldownS` seconds, and each leg is a scanner failure, which `failOpen` decides |
| `breakerCooldownS` | `30` | a whole number from 1 to 3600 | How long the circuit breaker stays open |
| `verdictCacheTtlS` | `0` (off) | a whole number from 0 to 300 | Keeps each allow this many seconds, so the same scan isn't sent twice. Off with `applyDlpMasking=true` |

V2's `scanTools` is no longer read: tool results are always scanned.

### The config map

The SharedFlow reads its entries from the environment's config map `airs-config` (`KVM-GetAIRSConfig.xml`). `deploy.sh` creates the map encrypted and writes them.

| Entry | Value |
|---|---|
| `airs_token` | The Prisma AIRS API key. It is read into `private.airs3_token`, which Apigee's Debug view never shows, and sent only to Prisma AIRS, in `x-pan-token` |
| `airs_profile` | The default security profile, by name or UUID. `currentProfile` overrides it |
| `airs_hook` | Only for [flow hooks](#flow-hooks): JSON, `{"routes": [base paths], "settings": {name: value}}` |

v3 caches them for 300 seconds, so a change can take up to five minutes to reach every request. A missing key or profile refuses every request, whatever `failOpen` says.

---

## What clients see

### A refusal

By default a refusal is HTTP 200 in the client's own format, so the client's SDK reads it as a normal reply; the exceptions are below. Every refusal carries these headers:

| Header | Value |
|---|---|
| `x-airs-blocked` | `true` |
| `x-airs-kind` | `block`, `refused`, `failure` or `config` (below) |
| `x-airs-category` | The `category` Prisma AIRS returned, such as `malicious`, when there was a verdict |
| `x-airs-scan-id` | The scan ID, when there was a scan |

| Kind | When | Message, on the request leg |
|---|---|---|
| `block` | Prisma AIRS blocked the content | "Request blocked by Prisma AIRS security policy." Then what was found and the scan ID, for example "Sensitive data (PII, credentials, secrets) detected. Scan ID: ..." |
| `refused` | v3 can't inspect the content, and `onScanError=block` | "Prisma AIRS could not inspect this request, so it was not forwarded.", usually with the reason, such as "(its body is not JSON)" |
| `failure` | Prisma AIRS gave no verdict and `failOpen=false`, or a step of v3 didn't finish | "Prisma AIRS could not scan this request, so it was not forwarded." |
| `config` | A setting v3 can't read, a missing key or profile, or a FlowCallout in the wrong place for streaming | "Prisma AIRS is not configured correctly, so it refused this request. Check the setting: failOpen.", for example |

On the reply leg, the `block`, `refused` and `failure` messages say "Response blocked" and "so it was withheld"; a `config` message reads the same on both legs. Allowed and masked traffic carries no `x-airs-*` header.

The body, per client:

| Client | A client that doesn't stream | A streaming client |
|---|---|---|
| Chat Completions | A `chat.completion` whose assistant message is the refusal, `finish_reason: stop` | `text/event-stream`: a chunk with the refusal, a finish chunk, then `data: [DONE]` |
| Responses API | A `response`, `status: completed`, whose output text is the refusal | Responses API events, `response.created` to `response.completed` |
| Anthropic Messages | A `message` whose text block is the refusal, `stop_reason: end_turn` | Anthropic events, `message_start` to `message_stop` |
| Gemini | `candidates` whose model text is the refusal, `finishReason: STOP` | With `alt=sse`, one event-stream event with that body; without, a JSON array that holds it |
| An endpoint v3 doesn't read | HTTP 403, `{"error":{"message":"...","type":"prisma_airs_refused","param":null,"code":"prisma_airs_refused"}}`, with `config` or `failure` in place of `refused` for those kinds | The same |

A streaming client is one whose request has `stream: true`, or calls `:streamGenerateContent` or `:streamRawPredict`, or whose reply arrived as an event stream. Refusals of content v3 can't inspect, such as duplicate keys or an oversized body, use the client's format too.

**`blockStatus`** forces its status code on every refusal kind to an LLM client that doesn't stream. It never applies to MCP, to a streaming client (an event stream, or Gemini's JSON array), or to an endpoint v3 doesn't read, which always gets 403. A 5xx code can make the OpenAI and Anthropic SDKs retry the call.

If v3's own refusal writer doesn't finish, the client gets HTTP 503 with `{"error":{"message":"Prisma AIRS could not complete its check, so this was not passed on.","type":"prisma_airs_unavailable","code":"prisma_airs_unavailable"}}` and `x-airs-kind: failure`.

### MCP refusals

MCP refusals stay inside the protocol, so the session survives:

- **The codes:** JSON-RPC error `-32001` for a block or content v3 can't inspect, and `-32003` for a scanner failure or a configuration problem.
- **The id:** each refusal carries the caller's own request id, as sent: a number stays a number.
- **The status:** HTTP 200. `blockStatus` doesn't apply.
- **No id to answer** (a notification, or the client's own reply to a server's request, whose id is the server's): the error carries `"id": null`, in HTTP 403 for a block or content v3 can't inspect, or HTTP 503 for a scanner failure or a configuration problem.
- **A batch:** one error per member that has a method and an id, in an array, in the batch's order. A batch with no such member (notifications and client replies only) gets one error with `"id": null`, in HTTP 403 or 503 as above.
- **A GET that asks for an event stream:** HTTP 405, with `Allow: POST, DELETE` and the message "This MCP endpoint does not stream replies through Prisma AIRS: send each request with POST.", unless `allowOpenStreams=true` lets it pass.

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Request blocked by Prisma AIRS security policy. Sensitive data (PII, credentials, secrets) detected. Scan ID: <scan id>."}}
```

---

## What v3 reads

### APIs and paths

v3 knows the API by the end of the path suffix. The query string doesn't count.

| API | Path suffix ends in |
|---|---|
| OpenAI Chat Completions, Azure OpenAI, Vertex AI's OpenAI-compatible endpoint | `/chat/completions` |
| OpenAI Responses API | `/responses` |
| Anthropic Messages | `/messages` |
| Claude on Vertex | `/publishers/anthropic/models/<model>:rawPredict` or `:streamRawPredict` |
| Gemini and Vertex AI | `:generateContent` or `:streamGenerateContent` |
| MCP | anything: a JSON-RPC 2.0 body is MCP on any path |

- **A model's answer fetched later** is read on the reply leg, although the call has no body: `GET .../responses/<id>`, `POST .../responses/<id>/cancel`, `GET .../conversations/<id>/items` and `GET .../chat/completions/<id>`.
- **Count-tokens calls** (`/count_tokens`, `:countTokens`, Claude on Vertex's `/models/count-tokens:rawPredict`) pass on both legs, logged, because the model writes nothing. Only the end of the path counts, so a model or deployment name that contains "count-tokens" is still scanned.
- **Every other endpoint** is refused by default, unless the request has no body (see [What v3 doesn't read, refuses or passes](#what-v3-doesnt-read-refuses-or-passes)).
- Gemini field names are read in both forms, camelCase and snake_case.

### The request leg

By default v3 reads:

- every user turn, not only the newest. A conversation may end with anyone's message;
- every tool result, in every turn: OpenAI `role: tool` messages, Anthropic `tool_result` blocks and server tool results (web fetch, web search, code execution, MCP), Gemini `functionResponse` parts and code-execution results, and Responses API tool output items;
- text inside parts: Anthropic documents and search results, inline files and data URIs that carry text, a Chat Completions message's `name`, and a Responses API stored prompt's `variables`;
- keys as well as values inside tool arguments and results;
- the JSON of images, audio and files, with their bytes left out (see [Bytes](#bytes)).

With `scanMessageRoles`, it also reads:

- `system`: system and developer messages, Anthropic's top-level `system`, Gemini's `systemInstruction` and the Responses API's `instructions`;
- `assistant`: the assistant's earlier turns, the tool calls it made, its refusals and reasoning, and a prefill.

In Anthropic Messages, a message with role `system` inside `messages`, as Claude Code sends, is read like a user turn, not as system text, so the defaults scan it.

### The reply leg

On the reply leg, v3 reads:

- every choice or candidate, not only the last;
- the tool calls it makes, with their arguments;
- refusals, reasoning text and summaries, and audio transcripts;
- the sources it cites: Anthropic citations, Chat Completions and Responses API annotations, Azure OpenAI's On Your Data `context`, and Gemini's grounding, citation and URL-context metadata;
- Anthropic server tool results and Gemini code-execution results.

On LLM traffic, the prompt, as it was forwarded (masked, if v3 masked it), goes with the reply as context, in the same `contents` entry. Prisma AIRS judges only the last entry of `contents` (K3, K4), so v3 always sends one.

On LLM traffic, a block whose detections are all the prompt's lets the reply through, logged, when the request leg allowed or masked that prompt: only the reply's own detections block it. With `type=both`, the prompt's detections count too. MCP text goes as a prompt with no context, so its `prompt.*` detections are the reply's own and this rule never applies to it.

### MCP messages

Every JSON-RPC message is MCP, whatever its method.

**What Prisma AIRS sees.** `tools/call` and the answer to `tools/list` go as tool events. Every other MCP text goes as a prompt, with no context, on both legs, as MuleSoft sends it: MCP text reaches a model as input, and Prisma AIRS reads prompt injection on the prompt side only. So on the reply leg too, MCP detections show as `prompt.*`. Two costs come with it: the prompt side's blocks of long, repetitive harmless text (L11) now apply to server text such as a long log or listing, and the response side's `db_security` detector no longer reads it.

| Message | Request leg | Reply leg |
|---|---|---|
| `tools/call` | A tool event: the arguments, scanned with `toolProfile` | A tool event: the arguments and the result, its text, `structuredContent`, resources and error results included, and a text block's other members (`_meta`, `annotations`). What the answer carries besides its result (an error, params) is a second scan, as text |
| `tools/list` | Params not scanned | A tool event whose output is the tool list as a bare array, scanned with `toolProfile`: poisoned tool descriptions are caught here. Other members of the result, but `nextCursor` and `_meta`, are a second scan, as text |
| `initialize`, `resources/list`, `resources/templates/list`, `prompts/list`, `roots/list` | Params not scanned | The answer, as text |
| `ping`, `initialized`, `logging/setLevel`, `notifications/*` | Params not scanned | The answer, as text. A ping's empty result has nothing to scan |
| `resources/read`, `prompts/get`, `completion/complete`, and every other method | The params but `_meta`, as text | The answer, as text |
| A client's answer to a server's request | The result (a string as written), the error and any params, as text | |
| A server's request or notification inside a JSON reply | | Its params, and any result or error it carries, as text |
| A JSON-RPC error answer | | The error, as text, whatever the reply's HTTP status (below) |

- **An answer** is a message with a result or an error; a method beside them changes nothing (MuleSoft's rule). On the request leg, a result or an error is scanned whatever the method, and a `tools/call` that carries one is scanned whole, as the tool event's input.
- **Members outside the JSON-RPC envelope** (anything but `jsonrpc`, `id`, `method`, `params`, `result` and `error`) are always scanned: such a message is scanned whole, as text, on either leg; a `tools/call` answer with such members stays a tool event, whose output is the whole message. So an LLM body that adds JSON-RPC members gains no skip: over the size limit it keeps its newest part, as LLM text does.
- **A `tools/call` whose params hold members beyond** `name`, `arguments` and `_meta` is scanned whole, as the tool event's input.
- **The tool event** carries `ecosystem: mcp`, the method, the tool's name, and `server_name`: the name of the Apigee proxy.
- **Batches** (a JSON array of messages; MCP 2025-06-18 has none, earlier versions do): each member is its own scan, in order, on both legs, and the first refusal refuses the whole batch, with one error per member that has an id. Control and catalogue members scan nothing. A batch with more members than `mcpBatchLimit` (default 8) is refused before any scan.
- **In a reply array,** each answer is matched to its request member by its id, as a JSON value (`"1"` doesn't answer `1`), and scanned as that member's answer. Messages that answer no member (notifications, the server's own requests, answers to ids nobody sent) are scanned together, as one text, after the answers; so is an element that isn't a JSON-RPC message. A single JSON reply is taken as the answer, whatever its id.
- **The scan slots:** a SharedFlow's steps are fixed when it is built, so v3 has 8 scan slots, and a leg makes at most 8 scans, one after another: 8 harmless scans took 2.1 s in the lab, about 0.25 s each. Once one would refuse the leg, the slots after it don't run; the step that stops them and the verdict judge an answer by the same rules. A leg that would need more than 8 scans (the reply to a full batch of 8 that also carries a notification, say) is content v3 can't inspect: refused, or with `onScanError=allow` scanned in its first 8 and the rest passed, logged. So `mcpBatchLimit` goes up to 8, where MuleSoft's goes to 100. Each slot keeps the 5-second timeout, so a leg of 8 scans can wait about 40 seconds when Prisma AIRS doesn't answer.
- **A reply sent as an event stream is withheld,** with `-32001` and the caller's id, because the flow can't see its body (L1). The server chooses the reply type, so v3 can't turn the stream off: configure the server to reply in JSON. With `allowOpenStreams=true`, such a reply on an MCP route passes unscanned instead, logged: nothing in it is scanned, so use it only for a server you trust. MuleSoft's setting of that name passes GET streams only; MuleSoft holds an event-stream reply and scans it, which Apigee's flow can't.
- **Sampling and elicitation:** a tool that asks the client for one mid-call sends its request in an event stream, so through v3 the call can't finish: the stream is withheld, and the GET stream gets 405. `allowOpenStreams=true` lets both pass, unscanned.
- **A reply with an HTTP status outside 2xx** is read as a 2xx one is, as MuleSoft does: an error reply is server text the client receives (the lab's MCP server quotes the value it refused). Only a body that is empty or not JSON passes, logged. Apigee sends a 4xx or 5xx reply to v3's reply leg only when the MCP target counts them as success, as the example proxy does (see [Logging](#logging), replies outside 2xx).
- **The session:** an `initialize` reply's scan carries the `Mcp-Session-Id` the server issues, when no session was known yet.
- **A GET that asks for an event stream** gets 405, or with `allowOpenStreams=true` passes unscanned, logged.
- **MCP text is never rewritten** (see [Masking](#masking)).

### Bytes

Bytes are judged by what they carry:

- **A provider's inline file** (Gemini `inlineData`, an Anthropic base64 source, an MCP image, audio or blob) is decoded and scanned as text when its media type is text or its bytes are valid UTF-8. Otherwise only its bytes are left out: its name, media type and URL are still scanned.
- **A data URI** that carries text, base64 or not, is scanned as that text. One whose bytes are binary is scanned as written, except that bytes starting with a known file signature are left out in LLM traffic and in what an MCP client sends.
- **Long base64 under a data key** (`data`, `file_data`, `b64_json`, `bytes`, `image_data`, `audio_data`, `blob`) is left out only when its bytes aren't UTF-8 and start with a known binary file signature, such as an image's, a PDF's or an archive's.
- **An MCP icon's data URI** is left out; an icon given as a link is scanned.
- **Every other string** is scanned as written, however binary it looks.

---

## What v3 doesn't read, refuses or passes

**Not read:**

| What | Why |
|---|---|
| Text inside images, audio and PDFs | Prisma AIRS scans text. The part's JSON is scanned, without its bytes |
| Tool definitions on LLM requests (`tools`, Gemini `functionDeclarations`) | A poisoned tool description is caught where its MCP `tools/list` reply passes through v3 as JSON |
| System and assistant text, by default | The one default that leaves text unscanned. `scanMessageRoles` adds it |
| Anthropic's encrypted content (`redacted_thinking`, `encrypted_*` values) | Only Anthropic can read it |
| Log probabilities | Their tokens spell text v3 already reads. A reply that carries them is never masked |
| The params of MCP control and catalogue methods | See the [MCP table](#mcp-messages) |

**Refused by default** (`onScanError=block`):

| What | Why |
|---|---|
| An endpoint v3 doesn't read: embeddings, legacy completions, Amazon Bedrock's InvokeModel and Converse, Anthropic batches, Gemini's `:batchGenerateContent`, and others. A path with a trailing slash counts as one | No reader means no inspection |
| A path with dot segments, `%2e`, `%2f`, `%5c` or a backslash | It can name one endpoint to v3 and another to the provider |
| A body that isn't JSON, isn't the shape its path names, or arrives compressed in an encoding the flow doesn't decode | It can't be read. On runtime 1-18-0-apigee-8 the flow sees gzip bodies, and deflate request bodies, decompressed (L3) |
| JSON with a duplicate key among the keys v3 reads | v3 and the model could read different copies |
| A POST, PUT or PATCH whose body the flow sees as empty, at an endpoint that takes a body or with headers that say a body was sent (`Content-Length` above 0, or `Transfer-Encoding`) | A body the flow can't see is not a request with no body |
| A body over 10,485,760 characters | v3 checks the size itself before parsing, because a proxy can raise Apigee's own limit |
| Scan text over `maxScanChars` | See [The size limit](#the-size-limit) |
| An LLM request in which v3 finds nothing to read, such as a Gemini request with empty `contents`, or one with only a system message under the default roles | Its text, if any, is where v3 doesn't read |
| A WebSocket upgrade: any request with an `Upgrade` header | After the handshake no Apigee policy sees the traffic |
| A 2xx reply whose body the flow can't see, unless it says it has none: a 202 or 204, or `Content-Length: 0` with no `Transfer-Encoding`. On this runtime, that is any event stream (L1) | Its content can't be inspected |
| An MCP event-stream reply | Withheld, or with `allowOpenStreams=true` passed unscanned: see [MCP messages](#mcp-messages) |
| An MCP batch over `mcpBatchLimit`, or an MCP leg that needs more than 8 scans | The SharedFlow has 8 scan slots: see [MCP messages](#mcp-messages) |
| A body on an MCP route that isn't a JSON-RPC message or batch, such as an array that mixes messages with anything else | It can't be read as MCP, so `failClosedOnUnknown=false` doesn't open it |
| An HTTP 400 or 413 from Prisma AIRS, such as its answer to a prompt over 2,097,152 characters (L10) | Prisma AIRS refused the scan request, so v3 counts it as content that can't be inspected, never as an outage, whatever the cause. A fail-open proxy still refuses it |

**Passed, each with a log line:**

- a request with no body (a model list, an MCP `DELETE`), and its reply when the path names no API v3 reads and `apiFormat` isn't set. Otherwise the reply is read, as a model's answer fetched later is, and withheld if v3 can't read it;
- a count-tokens call and its reply;
- an LLM reply outside 2xx, which carries no model text (A31), and an MCP one whose body is empty or not JSON. With Apigee's default `success.codes`, a 4xx or 5xx target reply runs the error flow, so v3's reply leg doesn't run and writes no line (measured with an MCP server's HTTP 400);
- a 2xx reply with no body that says so: a 202 or 204, or `Content-Length: 0` with no `Transfer-Encoding` (an MCP server may end a session with HTTP 200 and no body);
- an MCP message with nothing to scan, and a reply with nothing to scan, such as a Gemini reply that holds only prompt feedback;
- on the reply leg, a block whose detections are all the prompt's, as above;
- whatever a setting that lets content pass unscanned lets through.

---

## Streaming

On runtime 1-18-0-apigee-8 the response flow runs and sees an event-stream reply's headers, but its body is empty, while the client still gets the whole stream (L1). So v3 never lets a stream through unread. It turns streaming off on the way to the model:

| Call | v3 forwards |
|---|---|
| `stream: true` (Chat Completions, Responses API, Anthropic Messages) | `stream: false`; for the two OpenAI APIs, without `stream_options` |
| Gemini `:streamGenerateContent?alt=sse` | `:generateContent`, without `alt` |
| Claude on Vertex `:streamRawPredict` | `:rawPredict` |

The model then answers in JSON. v3 scans the whole reply and sends it back as one burst of the client's own stream: Chat Completions chunks, Responses API events, Anthropic events, or one Gemini event. A Gemini `:streamGenerateContent` call without `alt=sse` is left as it is: it answers with a JSON array, which the flow reads whole (L1), and a refusal is a JSON array too.

- **What clients see:** the whole reply at once, after the model has finished and both scans are done. Measured through v3, the OpenAI SDK's streaming Chat Completions call, the Google Gen AI SDK's `generate_content_stream`, the Anthropic SDK's streaming Messages call on Vertex, and Claude Code all read the answer (VERIFICATION.md).
- **Timeouts:** the whole reply must arrive within the target's `io.timeout.millis` (see [Wiring](#wiring-it-into-your-own-proxy)).
- **Placement:** from the ProxyEndpoint, v3 can't change the target path, so a Gemini `alt=sse` or Claude on Vertex `:streamRawPredict` call fails closed there: v3 refuses it with a `config` refusal whose message names the TargetEndpoint PreFlow. That refusal assumes `target.url` reads empty in the ProxyEndpoint, which wasn't measured; if it doesn't, the reply still never passes unscanned. Turning a body's `stream` flag off was measured from the TargetEndpoint only (L1).
- **A stream that arrives anyway,** for example because a later step set `target.url` back, is withheld: its body can't be seen.
- **MCP event-stream replies** can't be turned off this way, and are withheld, or with `allowOpenStreams=true` passed unscanned (see [MCP messages](#mcp-messages)).
- **A runtime that shows event-stream bodies:** v3 already rebuilds LLM event streams event by event, joining each event's `data:` lines. That is tested offline only.
- **A reply that can't go back into the stream:** with `onScanError=allow`, a de-streamed reply v3 can't read passes as the model sent it, logged; a reply outside 2xx (an error, A31) always does.

---

## Masking

Prisma AIRS decides what is sensitive, and can return a masked copy of the scanned text. v3 forwards that copy instead of the original:

- when the verdict is allow and carries a masked copy, as V2 did; or
- when the verdict is block, every detection is sensitive data (`dlp`), and `applyDlpMasking=true`.

v3 writes a masked copy back only where it can do so exactly: the copy must have the scanned text's length, with every separator in place, and each field gets its own stretch of it. Otherwise the content is blocked, because partial masking can leak. In particular, a mask becomes a block when:

- the masked text touches text v3 reads but never rewrites: tool calls, decoded payloads, the JSON of images and files, citations and annotations, reasoning text, audio transcripts;
- the reply carries log probabilities, whose tokens would still spell the original;
- the reply arrived as an event stream;
- the traffic is MCP: arguments to mask are refused (`-32001`), and results to mask are withheld;
- `truncationFailClosed=false` cut the scan.

A reply whose stream v3 turned off arrives as JSON, so it can be masked, and is then sent back as one burst. A masked prompt is also the prompt that goes with the reply as context. Measured live with `applyDlpMasking=true`, a reply carrying the test card reached the client with the card masked, streamed and not (VERIFICATION.md).

---

## The size limit

`maxScanChars`, 100,000 characters by default and at most 2,097,152, bounds the text one scan holds. A leg makes one scan, except on MCP, where each of a leg's scans has its own limit (see [MCP messages](#mcp-messages)).

- **What counts:** on the request leg, every user turn and every tool result together, plus the roles you add; on the reply leg, the reply's text. The prompt that goes with a reply as context doesn't count; v3 sends at most its newest `maxScanChars` characters.
- **Over the limit:** refused without a scan (`truncationFailClosed=true`). With `truncationFailClosed=false`, v3 scans the newest part of a request, or the first part of a reply, lets the rest through unscanned, logged, and never masks: where Prisma AIRS would mask, the content is blocked instead ([Masking](#masking)).
- **MCP tool events:** a tool event whose arguments and result together pass the limit is scanned as text instead, under the same limit and with the text profile (`currentProfile`), not `toolProfile`.
- **MCP text** over the limit keeps its first part on both legs, as MuleSoft does. On an MCP leg of several scans with `onScanError=allow`, a scan over the limit passes unscanned, logged, and the others still run. On the reply leg, a `tools/call` answer's tool event over the limit goes as the text of its result alone, where MuleSoft's text holds the arguments too.
- **Long conversations grow:** every user turn and tool result is scanned on every request, so an agent's conversation passes the limit after a few tool results, and with the default each request after that is refused.
- **Proxies for Claude Code and other agents:** set `truncationFailClosed=false`. v3 then scans the newest `maxScanChars` characters of each request, where the new turn and tool results are, and logs the cut in the line's `note` ("scanned the newest 100000 characters" at the default). v3 keeps nothing between requests. When the client adds each new turn at the end, as Claude Code does, a turn is scanned on the request that brings it, if it fits in the limit, and left out of later scans once it is older than the newest `maxScanChars` characters; of a single turn longer than the limit, only the end is scanned. Anything a caller puts before the newest `maxScanChars` characters of a request is never scanned, so give the agent a proxy of its own. A Claude Code session that read 12 files of natural prose passed the limit on its 10th of 14 calls, and every call was allowed, the last 5 scanned by their newest 100,000 characters (VERIFICATION.md).
- **Harmless long text can be blocked,** in a prompt and, since MCP text goes as a prompt, in an MCP server's answer. With the test tenant's profile, natural prose (a novel's opening) was allowed at 50,000, 87,500 and 100,000 characters, but text built from a few sentences used over and over was blocked as prompt injection: one sentence repeated, at 50,000; sentences built from short word lists, allowed up to 81,950 and blocked from 87,500; six sentences in turn, at 100,000 (L11). Choose the limit for your traffic and your profile.
- **Body sizes:** with its default parse limits, Apigee refuses a request body over about 10 MB with its own HTTP 413, before any step runs (L2). v3 also refuses any body over 10,485,760 characters before parsing it.

---

## Logging

v3 writes one line per leg to Cloud Logging, from inside the SharedFlow (`ML-Airs3Log`), refusals included. The log is `projects/<organization>/logs/panw-airs`, where `<organization>` is your Apigee organization's name, with resource type `api`.

- **The service account:** the lines land only when the SharedFlow is deployed with a service account that can write logs (L13). The log step runs with `continueOnError=true`, so a logging failure never blocks traffic: check that the lines arrive after you deploy.
- **What a line never holds:** the scanned text, the key, the profile, the session id, or any header value other than the transaction id.
- **Reading them,** where the organization's name is the project id: `gcloud logging read 'logName="projects/your-gcp-project-id/logs/panw-airs"' --project=your-gcp-project-id --limit=20`

The blocked smoke test below logs a line of this form:

```text
{"v":"panw-airs-v3","leg":"request","mode":"enforce","hook":false,"format":"gemini","route":"scan","stream":"none","outcome":"block","kind":"block","detections":"prompt.dlp","scan_id":"<scan id>","airs_status":"200","transaction_id":"<transaction id>","chars":"58","scans":"1","retries":0,"cached":0,"masked":false,"destreamed":"","ms":<milliseconds>,"note":""}
```

| Field | Value |
|---|---|
| `v` | `panw-airs-v3` |
| `leg` | `request` or `response` |
| `mode` | `enforce`, or `monitor` (see [Operations](#operations)) |
| `hook` | `true` when a [flow hook](#flow-hooks) ran v3 |
| `format` | `openai-chat`, `openai-responses`, `anthropic`, `gemini`, `mcp`, `count-tokens` or `unknown`. An MCP GET for an event stream is `mcp` |
| `route` | `scan`, `pass`, `refuse` or `mcp405` |
| `stream` | How the call streams: `none`, `body`, `gemini-sse`, `gemini-array`, `rawpredict` or `event-stream-reply` |
| `outcome` | `allow`, `block`, `mask`, `failure` or `refused`. For a refusal before any scan, `refused` or `config`. Empty for a pass with no scan. In monitor mode, what v3 would have done: `monitored_block`, `mask_not_applied`, `failed_open`, `gap_unenforced`, or `config_unenforced` for a setting it can't read |
| `kind` | The refusal's kind, as in `x-airs-kind` |
| `detections` | What Prisma AIRS flagged, as `<side>.<detector>`, comma-separated: `prompt.dlp`, `response.dlp`, `tool_input.dlp`. MCP text goes as a prompt on both legs, so its detections show as `prompt.*` on the reply leg too |
| `scan_id` | Prisma AIRS's scan ID. On an MCP leg of several scans, one of them: the refusing scan's, else the first that passed only by `failOpen` or `onScanError`, else the last |
| `airs_status` | The HTTP status of the scan call, or `none` when there was no answer |
| `transaction_id` | The id sent to Prisma AIRS |
| `chars` | The characters scanned on this leg, in the scans that ran |
| `scans` | How many scans ran on this leg: 1, or up to 8 on an MCP leg of several scans (a batch, a reply array, a `tools/list` answer with other members, an answer that carries more than its result). Empty when nothing was scanned |
| `retries` | How many scans got a second try (`scanRetries`) |
| `cached` | How many scans the verdict cache answered (`verdictCacheTtlS`). A scan answered from the cache leaves no new record in Prisma AIRS: `scan_id` is the scan it was first answered by |
| `masked` | `true` when v3 wrote a masked copy back |
| `destreamed` | The kind of stream v3 turned off, if any |
| `ms` | Milliseconds from the start of the leg to the log step |
| `note` | Why a leg passed, failed open or was refused, or that its scan was cut, in words: "a request with no body passes", "failed open: ...", "gap allowed: ...", "monitor mode, gap not enforced: ...", "a batch of 3 messages", "an open stream passes unscanned (allowOpenStreams)", "scanned the newest 100000 characters" (a request; a reply, and MCP text, say "the first"). A refusal before any scan has the client's message, which holds no content, header or key, at most a limit's number. On an MCP leg of several scans, what the scan step logged (a part cut, or passed unscanned) comes first, then the verdict's reason |

**Replies outside 2xx:** with Apigee's default `success.codes`, a 4xx or 5xx target reply runs the error flow, so v3's reply leg doesn't run and writes no line, and an MCP server's error reply reaches the client unscanned. On an MCP proxy, count them as success on the TargetEndpoint, `<Property name="success.codes">1xx,2xx,3xx,4xx,5xx</Property>`, as the example proxy does: the reply leg then runs and scans the MCP error reply (measured, L16). An LLM reply outside 2xx passes unscanned, logged: no provider puts model text into an error reply (A31). Apigee then no longer treats them as errors: it raises no fault for them, so FaultRules, and anything else keyed on target faults, don't see them, and the proxy's other response steps run on them too.

**Without a service account:** remove the `ML-Airs3Log` step from `sharedflows/default.xml`, and its policy file, and deploy by other means: `deploy.sh` always requires `SA`. v3 then writes no line of its own, so the passes this page calls logged leave no record. Each leg's line is still built in the flow variable `airs3.logLine`, which holds the line of the leg that ran last; your proxy can write it with a logging step of its own.

---

## Operations

Four settings from MuleSoft's policy, each off by default.

- **Monitor mode** (`enforcementMode=monitor`), for a first rollout: v3 scans as usual and logs what it would have done, but nothing is refused or masked, an MCP GET for an event stream isn't answered 405, and every scan of a leg runs (an MCP part v3 can't inspect is passed over, logged, and the rest scanned). Streaming is still turned off on the way to the model and back on for the client, so replies are read, whatever let the leg pass. A value of `enforcementMode` itself that v3 can't read refuses, so the mode is never guessed. It takes any letter case, as v3's other choices do (MuleSoft takes only lowercase).
- **A retry** (`scanRetries=1`): one more call after no answer, HTTP 429 or a 5xx; never after a verdict or any other 4xx. Each try can take 5 seconds, so on a leg of 8 scans an unreachable Prisma AIRS can add 80 seconds. The circuit breaker bounds that for later legs only: it is read once per leg, so the leg that meets the outage still makes its calls (MuleSoft asks it before each call).
- **A circuit breaker** (`breakerFailures`, `breakerCooldownS`): after that many scanner failures in a row, Prisma AIRS isn't called for the cooldown, and each leg is a scanner failure that `failOpen` decides. After the cooldown, the next leg's calls are a trial: an answer closes it, a failure opens it again. With `failOpen=true` such a leg passes as any failure under `failOpen` does, streaming turned off and back on. Its state sits in the environment's cache under a hash of the endpoint and the key, so tenants never share one. It is read once per leg, and legs that run at once may count from the same state. A 400 or 413 (Prisma AIRS refusing the content) resets the count, where MuleSoft counts it as a failure: the state is shared by every proxy on the tenant, so one client's content would otherwise open it for all of them.
- **A verdict cache** (`verdictCacheTtlS`): each allow is kept for the TTL under a SHA-256 of everything that can change it (the key, the endpoint, the profile, the leg, the size settings and the text), so a repeated scan isn't sent again. Blocks, failures and allows that carry a masked copy are never kept, and the cache is off with `applyDlpMasking=true`. A profile change in Strata Cloud Manager reaches cached text only when its entry expires. A scan answered from the cache leaves no new record in Prisma AIRS; v3's log line counts it in `cached`. Inside a SharedFlow the cache is shared by every proxy that calls it (L19); the key keeps tenants and profiles apart.
- **Trust:** the config map, the verdict cache and the breaker's state belong to the environment. Any proxy deployed there can read the Prisma AIRS key from the config map and write entries under v3's cache keys: an allow for text it chooses, or an open breaker. MuleSoft keeps both in each worker's memory. Deploy v3 only in an environment whose proxies, and whoever deploys them, you trust with the key.

---

## Flow hooks

For proxies with no FlowCallout of their own, v3 can run from the environment's pre-target and post-target flow hooks. A hook passes no parameters, so two small SharedFlows ship beside v3, `PANW-AIRS-hook-request` and `PANW-AIRS-hook-response`, each a FlowCallout to v3 with one parameter, `hookMode`, that names the leg (`request` or `response`). A FlowCallout's parameters stay set after it returns (L6), so v3 clears `hookMode` at once and passes nothing else: a proxy's own variables keep their values.

- **Which proxies:** only those whose base path the config map entry `airs_hook` lists, `{"routes": ["/airs-llm", "/airs-mcp"], "settings": {}}`, each exactly as the proxy's base path (no `/` at the end). Every other proxy in the environment passes untouched, with no log line. With no readable entry, nothing is scanned, and each run is logged. A listed proxy with no TargetEndpoint (one that reaches its model with its own ServiceCallout or JavaScript) runs neither hook (L20), so nothing scans it and no line says so: give it its own FlowCallouts.
- **Settings:** from `airs_hook`'s `settings` alone, read as strictly as a proxy's, for every listed route: a flow variable a listed proxy sets, under any setting's name, takes no part. Values are JSON: text, numbers and booleans as written, and a JSON object where the setting is one (`airsDescriptions`). `settings` itself must be a JSON object; anything else refuses the listed routes, naming it.
- **Never twice:** a leg a proxy's own FlowCallout already enforced a verdict on isn't scanned again by the hook, and the other way round, logged. A run that failed open, let a gap pass, scanned only part of the text (`truncationFailClosed=false`) or only monitored leaves the leg to the other, which scans it with its own settings, so the stricter of the two holds. When the earlier run put the reply back into the client's stream, the later one reads the reply as the earlier one did, the JSON it kept, unless something changed the reply in between; then it reads the event stream as it is and passes it as it is. The proxy's request-leg FlowCallout runs before the pre-target hook, and the post-target hook before the proxy's reply-leg FlowCallout. Two FlowCallouts on one leg still both scan.
- **Deploying:** `HOOK_ROUTES=/airs-llm,/airs-mcp ./deploy.sh --env-file=.env` writes `airs_hook` (with `HOOK_SETTINGS`, a JSON object), deploys the two SharedFlows, and attaches them with `continueOnError=false`, the post-target hook first. A hook point holds one SharedFlow, and `deploy.sh` never replaces another one: it reads both hook points before anything else, and stops with nothing changed if either holds another SharedFlow. Then run it with `HOOK_ATTACH=no`: it writes `airs_hook` and deploys the two SharedFlows without attaching them, and you add a FlowCallout to `PANW-AIRS-hook-request` (or `-response`) to your SharedFlow on that point, and attach the other one, or call it the same way.
- **Where they run:** the pre-target hook after the TargetEndpoint's request PreFlow, just before the call; the post-target hook just after the reply, before the TargetEndpoint's response flow. A refusal from either ends the request, and streaming is turned off from the pre-target hook as from a FlowCallout (L20, L21).
- **Timing:** a hook change reaches the runtime's instances one by one, within about a minute, and `airs_hook` is cached with the rest of the config map, for 300 seconds.
- **Removing:** detach both hooks (in the Apigee console under Environments, Flow hooks, or with the `flowhooks` API), then delete `airs_hook`. Detach them before you undeploy v3 or the hook SharedFlows.

---

## Validation

`deploy.sh` prints the first two checks, filled in, when `APIGEE_HOST` is set and `llm` is in `EXAMPLES`.

**Allowed:** the model answers.

```bash
curl -sS 'https://apigee.example.com/airs-llm/v1/projects/your-gcp-project-id/locations/global/publishers/google/models/gemini-3.8-flash:generateContent' \
  -H 'Content-Type: application/json' \
  --data '{"contents":[{"role":"user","parts":[{"text":"What is the capital of France? Answer in one word."}]}]}'
```

**Blocked before the model,** by a profile that detects sensitive data: HTTP 200, a refusal in Gemini's format, and the headers `x-airs-blocked: true`, `x-airs-kind: block` and `x-airs-scan-id`.

```bash
curl -sSi 'https://apigee.example.com/airs-llm/v1/projects/your-gcp-project-id/locations/global/publishers/google/models/gemini-3.8-flash:generateContent' \
  -H 'Content-Type: application/json' \
  --data '{"contents":[{"role":"user","parts":[{"text":"My card number is 4111 1111 1111 1111. Please remember it."}]}]}'
```

```json
{"candidates":[{"content":{"role":"model","parts":[{"text":"Request blocked by Prisma AIRS security policy. Sensitive data (PII, credentials, secrets) detected. Scan ID: <scan id>."}]},"finishReason":"STOP","index":0}],"usageMetadata":{"promptTokenCount":0,"candidatesTokenCount":0,"totalTokenCount":0},"modelVersion":"prisma-airs"}
```

**Streamed,** through Vertex AI's OpenAI-compatible endpoint: Chat Completions chunks and `data: [DONE]`, arriving together.

```bash
curl -sSN 'https://apigee.example.com/airs-llm/v1/projects/your-gcp-project-id/locations/global/endpoints/openapi/chat/completions' \
  -H 'Content-Type: application/json' \
  --data '{"model":"google/gemini-3.8-flash","stream":true,"messages":[{"role":"user","content":"What is the capital of France? Answer in one word."}]}'
```

**MCP,** with the MCP example deployed: HTTP 200 with JSON-RPC error `-32001` and your request id, before the server runs the tool, when the profile detects sensitive data.

```bash
curl -sS 'https://apigee.example.com/airs-mcp/mcp' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"YOUR_TOOL","arguments":{"text":"Card 4111 1111 1111 1111"}}}'
```

Prisma AIRS keeps a record of each scan; the scan ID in a refusal identifies it in Strata Cloud Manager.

### Unit tests

The offline suite runs the SharedFlow's own XML and JavaScript in an emulator of Apigee, against Prisma AIRS replies recorded from a tenant. It needs Node.js only. From this folder:

```bash
node test/run.js --v3
```

The last line reads `v3: <n> pass, 0 fail, <n> with no v3 expectation`. [test/README.md](test/README.md) explains the suite, its options and its case labels.

---

## Technical requirements

1. **`app_name`** is `Apigee-<appName>`, `Apigee-Gateway` by default, in the `<VENDOR>-<CUSTOMER_APP>` form.
2. **Correlation.** v3 sends:
   - `transaction_id`, per request, the same on both legs: from `x-correlation-id`, else `x-request-id`, else Apigee's `messageid`;
   - `session_id`, per conversation: on MCP traffic from `Mcp-Session-Id`, else from `x-session-id`, else from `x-claude-code-session-id`; an `initialize` reply's scan with no session yet takes the `Mcp-Session-Id` the server issues. Without one, v3 sends none;
   - never `tr_id`.

   An id is never cut. One over 100 characters, or with a space or a character outside printable ASCII, is skipped and the next source is used, because Prisma AIRS refuses a longer id with HTTP 400 (L12).
3. **Metadata:** `ai_model` is the body's `model`, else the model named in the path, else `unknown`. `app_user` is the `x-user-id` header, up to 100 characters, else `apigee`. `agent_meta` is sent when `agentId` is set.
4. **The profile:** a UUID is sent as `ai_profile.profile_id`, any other value as `ai_profile.profile_name`.
5. **One `contents` entry per scan:** the prompt, the reply with the prompt as context, an MCP tool event, or MCP text as a prompt with no context.
6. **The API key** sits only in the encrypted config map and in `private.airs3_token`. The scan request that carries it is the message `private.airs3_scan` (`private.airs3_scan2` to `private.airs3_scan8` for the other scan slots), so Debug shows the key nowhere: measured live (VERIFICATION.md). The key is never logged.
7. **TLS:** the call to `https://<prismaAirsEndpoint>/v1/scan/sync/request` checks the certificate strictly (`SSLInfo` with `Enforce=true`), with no trust store of your own (L5). A certificate failure is a scanner failure.
8. **Timeout:** 5 seconds per scan, set in each slot's ServiceCallout: `SC-Airs3Scan.xml`, and `SC-Airs3Scan2.xml` to `SC-Airs3Scan8.xml`. Change all eight together. `scanRetries=1` adds one more try after no answer, a 429 or a 5xx ([Operations](#operations)).
9. **Fails closed by default:** no verdict refuses (`failOpen=false`), and content v3 can't inspect is refused (`onScanError=block`). Every pass that a setting allows is logged.

---

## Know before you deploy

- **System prompts and assistant text are not scanned by default.** Add `system` and `assistant` to `scanMessageRoles` to scan them. System text repeats on every call, so it adds to every scan's size. A message with role `system` inside Anthropic's `messages`, as Claude Code sends, is not system text to v3: it is read like a user turn, so it is scanned whatever `scanMessageRoles` says, and adds to every scan's size (see [The request leg](#the-request-leg)). With `truncationFailClosed=false`, as this page advises for Claude Code, it is among the oldest text, so a long session's later scans leave it out ([The size limit](#the-size-limit)).
- **Streaming is buffered.** A streaming client waits for the prompt scan, the whole reply and the reply scan, then gets the reply at once.
- **MCP servers should reply in JSON.** Event-stream replies are withheld and a GET for an event stream gets 405, unless `allowOpenStreams=true` lets both pass unscanned. So a tool that asks the client for sampling or elicitation mid-call can't finish through v3. Batches are scanned member by member, up to 8 members, one scan after another.
- **Text only.** Images, audio and PDFs can't be scanned; their names, media types and URLs are.
- **Not scanned, by design:** LLM replies outside 2xx (they carry no model text, A31), MCP replies outside 2xx whose body is empty or not JSON, any 4xx or 5xx reply on a proxy that keeps Apigee's default `success.codes` (it never reaches v3's reply leg), requests without a body, and their replies at paths that name no API v3 reads, count-tokens calls, and tool definitions.
- **Claude Code** gets no special handling: no header or body marker skips a scan, and its `<system-reminder>` text is scanned as sent. A short session through v3 worked, and the one reminder block it sent passed the lab's profile. Each request carries the whole conversation, so a longer session passes the 100,000-character default, and with the default every request from then on is refused. Set `truncationFailClosed=false` on its proxy ([The size limit](#the-size-limit)). Through such a proxy, a session that read 12 files of natural prose passed the limit on its 10th of 14 calls and worked; each of the last 5 calls was scanned by its newest 100,000 characters only (VERIFICATION.md).
- **A refusal on the request leg ends the call:** the model is never called, and the reply leg doesn't run.
- **The config map is cached** for 300 seconds.
- **Prisma AIRS keys are bound to a region.** A key works only against its own region's host. A wrong key gets HTTP 403 from Prisma AIRS (L10), which v3 treats as a scanner failure; what another region's host answers wasn't measured.
- **Settings and placement belong to the proxy.** A setting that lets content pass, or a proxy that calls v3 on one leg only, opens a skip for every caller of that proxy. A `type` that names the wrong leg is refused, but a FlowCallout left out entirely can't be noticed by v3.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| Every request: "Prisma AIRS is not configured correctly, so it refused this request. Check the setting: X." (`x-airs-kind: config`; MCP `-32003`) | Setting X has a value v3 can't read, or the config map lacks `airs_token` or `airs_profile`. The message names the setting, never its value |
| "Prisma AIRS could not turn streaming off for this call: the request leg must run in the TargetEndpoint PreFlow." | The request-leg FlowCallout runs in the ProxyEndpoint. Move it to the TargetEndpoint PreFlow |
| "Prisma AIRS could not scan this request" (`x-airs-kind: failure`; MCP `-32003`) | Prisma AIRS was unreachable, took over 5 seconds, answered an error status other than 400 or 413, or gave no clean verdict; or a step of v3 didn't finish. The log line's `airs_status` says which: `none` means no answer, `403` a wrong key or a key from another region |
| "Prisma AIRS could not inspect this request (...)" (`x-airs-kind: refused`) | The reason is in the brackets. "an endpoint it does not read": check the path, or set `apiFormat` |
| HTTP 403 with `"type":"prisma_airs_refused"` | An endpoint v3 doesn't read |
| A streamed reply is withheld: "could not inspect this response" | The reply came back as an event stream: the request leg didn't run in the TargetEndpoint PreFlow, a later step set `target.url` back, or the path suffix doesn't show the stream method. Or an MCP server replied with an event stream |
| A streamed reply arrives all at once | Expected: see [Streaming](#streaming) |
| A streaming client gets plain JSON | The route has no reply-leg FlowCallout |
| MCP: 405 on a GET | Expected: MCP over POST only, unless `allowOpenStreams=true` |
| MCP: "could not inspect this batch (more than N messages)", or "the reply to this batch" | The batch holds more members than `mcpBatchLimit`: raise it, up to 8, or send fewer |
| MCP: "could not inspect this request (it needs more than 8 scans)", or "this response" | The leg needs more scans than the SharedFlow's 8 slots: a full batch whose reply also carries notifications, say. Send smaller batches |
| MCP: "could not inspect this request (it is not a JSON-RPC message or batch)" | A body on an MCP route that isn't JSON-RPC: an array that mixes messages with anything else, or a message without `"jsonrpc": "2.0"` |
| MCP: `-32001`, "could not inspect this response", or, where the flow sees the stream's body, "does not inspect MCP event-stream replies" | The server replied with an event stream. Configure it to reply in JSON, or set `allowOpenStreams=true` to pass such replies unscanned |
| HTTP 413, "Body buffer overflow" | Apigee's own body limit, before any step runs |
| HTTP 503, `"type":"prisma_airs_unavailable"` | v3's refusal writer didn't finish; the call was refused anyway |
| Deployment fails with `MISSING_SERVICE_ACCOUNT` | Deploy the SharedFlow with a service account (see [Prerequisites](#prerequisites)) |
| The LLM example answers HTTP 500, `GoogleTokenGenerationFailure` | Apigee's service agent can't mint tokens for the service account: add the `roles/iam.serviceAccountTokenCreator` binding |
| No log lines | The SharedFlow's service account lacks `roles/logging.logWriter` |

In Debug, the `airs3.*` variables show each step's work: `airs3.format`, `airs3.route`, `airs3.stream`, `airs3.outcome`, `airs3.detections`, `airs3.refuseMsg`, `airs3.logNote` and `airs3.logLine`. The key never shows.

---

## Inside the SharedFlow

The steps of [`sharedflows/default.xml`](PANW-AIRS/sharedflowbundle/sharedflows/default.xml), in order. The same steps run on both legs; `type` picks the leg (in hook mode, `hookMode`).

| # | Step | Runs when | What it does |
|---|---|---|---|
| 1 | `AM-Airs3Reset` | Always, first | Sets every done flag, slot flag, retry flag and cache flag to false, and the mode to enforce, so each leg starts clean |
| 2 | `KVM-GetAIRSConfig` | Always | Reads `airs_token` into `private.airs3_token`, `airs_profile` into `airs3.kvmProfile`, and `airs_hook` into `airs3.kvmHook` |
| 3 | `JS-Airs3Init` | Always | In hook mode, whether this proxy is listed and no run has enforced a verdict on the leg yet; on the reply leg, the JSON an earlier run kept when it put the reply back into a stream; then the leg, every setting (strictly), the endpoint, the profile and the ids |
| 4 | `JS-Airs3Detect` | After Init, unless Init passed the leg (an unlisted route, or never twice) | The API, the stream kind, the MCP method and id, and the route: `scan`, `pass`, `refuse` or `mcp405` |
| 5 | `AM-Airs3StripEncoding` | Request leg, a scan | Removes `Accept-Encoding` from the forwarded request, so a reply v3 rewrites is never compressed |
| 6 | `JS-Airs3Read` | A scan | The scan text, the size limit and the scan request body |
| 6a | `JS-Airs3CacheKeys`, then `LC-Airs3Verdict` and `LC-Airs3Verdict<k>`, then `JS-Airs3CacheHits` | A scan, the verdict cache on; the lookups and the hits only once every key was made | Each scan's key, each slot's lookup, then the slots this leg's own lookups answered |
| 6b | `LC-Airs3Breaker`, `JS-Airs3BreakerCheck` | A scan, the circuit breaker on | While it is open, no call: the leg is a scanner failure |
| 7 | `AM-Airs3ScanRequest` | A scan | The scan request, in the message `private.airs3_scan`, with `x-pan-token` |
| 8 | `AM-Airs3ClearScan` | A scan | A new `airs3ScanResponse`, so a leg that gets no answer never reads the other leg's. Apigee gives a new message status 200 and no body (L14), and the call's failed flag then marks it as no answer |
| 9 | `SC-Airs3Scan` | A scan, not answered by the cache | Calls Prisma AIRS: 5-second timeout, strict TLS, `continueOnError=true` |
| 9r | `JS-Airs3Retry<k>`, then the slot's clear and call steps again | `scanRetries=1`, no answer, 429 or a 5xx | One more try, the same callout |
| 9a | `JS-Airs3Slot1` | A leg of several scans (MCP) | Stops the slots after it if this answer would refuse the leg, judged by the verdict's own rules (`AIRS3.decide`) |
| 9b | `AM-Airs3ClearScan<k>`, `AM-Airs3ScanRequest<k>`, `SC-Airs3Scan<k>`, `JS-Airs3Slot<k>`, for slots 2 to 8 | The leg needs slot k, and no slot before it would refuse | As slot 1, into `private.airs3_scan<k>` and `airs3ScanResponse<k>`; the clear step also marks that this leg ran slot k |
| 10 | `JS-Airs3Verdict` | A scan | The outcome (`allow`, `block`, `mask`, `failure`, `refused`), the detections, the scan ID and the masked text. With several scans, the slots that ran, in order: the first that would refuse decides |
| 10a | `JS-Airs3BreakerRecord`, `PC-Airs3Breaker` | The circuit breaker on | Counts this leg's calls, in slot order, and writes the state when it changed |
| 10b | `JS-Airs3CacheRecord`, then `PC-Airs3Verdict<k>` | The verdict cache on | Writes each slot's clean allow |
| 11 | `JS-Airs3Mask` | Outcome `mask` | Writes the masked copy back exactly, or makes the outcome `block` |
| 12 | `JS-Airs3Destream` | Request leg, a pass, a stream asked for | Turns streaming off |
| 13 | `JS-Airs3Restream` | Reply leg, a pass, streaming turned off, a 2xx reply not already an event stream | Sends the reply back as one burst of the client's stream, and keeps the JSON for a later run on the leg |
| 14 | `JS-Airs3Respond` | A refusal, or a step that didn't finish | Writes the refusal in the client's format; in monitor mode, logs it and lets the leg pass |
| 14a | `JS-Airs3Destream`, `JS-Airs3Restream` again | Monitor mode, a pass `JS-Airs3Respond` decided | As 12 and 13 |
| 15 | `JS-Airs3LogLine` | Always, but for an unlisted route in hook mode | Builds the log line |
| 16 | `ML-Airs3Log` | Always, but for an unlisted route in hook mode | Writes it to Cloud Logging |
| 17 | `RF-Airs3Mcp405` | An MCP GET for an event stream | HTTP 405 |
| 18 | `RF-Airs3Block` | A refusal is ready | Returns it, with the `x-airs-*` headers |
| 19 | `RF-Airs3Backstop` | A refusal was needed, but its writer didn't finish | HTTP 503, plain JSON |

Every JavaScript step runs with a `timeLimit` and `continueOnError=true`, and sets its done flag, `airs3.done<Step>`, as its last statement. Later steps check the flags they depend on. A step that ran out of time or failed leaves its flag false, and the leg is refused in the client's format, or with the plain HTTP 503 above if the refusal writer itself failed, never with Apigee's bare HTTP 500 (L2). The log-line step is the exception: no step checks its flag, so if it fails the leg goes on without its line. Phase 3's steps need no refusal: one that doesn't finish leaves the leg as it would be without its setting. A retry step that doesn't finish makes no second try, a breaker step reads or changes nothing, and a cache step makes no hit and writes nothing, so every slot makes its call.

**Variables:**

- Every flow variable of v3's own is named `airs3.<name>`, with no further dot, or `private.airs3_<name>`. Outside those names, v3 changes only the request and the reply themselves (masking, streaming, `Accept-Encoding`), to turn a stream off, `target.url`, `target.copy.pathsuffix` and `target.copy.queryparams`, and in hook mode it clears the `hookMode` parameter its hook SharedFlows pass. Apigee silently drops a variable whose name extends one already set (L6), so no v3 name extends another.
- The key is only in `private.airs3_token`, and the scan request is the message `private.airs3_scan` (`private.airs3_scan<k>` for slots 2 to 8). Prisma AIRS's answer is the message `airs3ScanResponse` (`airs3ScanResponse<k>`).
- `airs3.promptContext` carries the prompt, as forwarded, from the request leg to the reply leg; `airs3.destreamed` carries the kind of stream v3 turned off; `airs3.plainReply` carries a reply, as JSON, from the step that put it back into the client's stream to a later run on the same leg.
- The JavaScript is ES5, for Apigee's Rhino engine. The format readers are in [`resources/jsc/`](PANW-AIRS/sharedflowbundle/resources/jsc/), one `airs3-fmt-*.js` file per API, and every setting, with its default and its values, is in [`airs3-init.js`](PANW-AIRS/sharedflowbundle/resources/jsc/airs3-init.js).

---

## Layout

| Path | What it is |
|---|---|
| `PANW-AIRS/sharedflowbundle/` | The SharedFlow |
| `PANW-AIRS-hook-request/`, `PANW-AIRS-hook-response/` | The [flow hook](#flow-hooks) SharedFlows |
| `examples/airs-llm-guard/apiproxy/` | The LLM example proxy, in front of Vertex AI |
| `examples/airs-mcp-guard/apiproxy/` | The MCP example proxy |
| `deploy.sh`, `example.env` | The deploy script and its settings file |
| `test/` | The offline unit suite: [test/README.md](test/README.md) |
| [MIGRATION.md](MIGRATION.md) | Moving from V2, and the findings A01 to A39 |
| [VERIFICATION.md](VERIFICATION.md) | Each claim and where it was measured, and the measurement ids (L1, K3 and so on) that these pages cite |

---

## Moving from V2

V2 is the `PANW-AIRS` SharedFlow in [`../sharedflow/`](../sharedflow/). v3 keeps its name, its FlowCallout parameters and its setting names. What changes:

- **Placement:** on routes that can stream, the request-leg FlowCallout moves to the TargetEndpoint PreFlow.
- **Deployment:** the SharedFlow needs a service account.
- **Defaults:** stricter, from what is read to what is refused.
- **Answers:** some change, for clients and for operators.
- **The key:** rotate it after upgrading, because V2 lets Apigee's Debug view show it.

[MIGRATION.md](MIGRATION.md) has each change, and the findings A01 to A39 that v3 addresses.
