# Prisma AIRS for Databricks Unity AI Gateway

Puts Prisma AIRS runtime scanning on the traffic Unity AI Gateway governs: prompts and replies on model services, and tool calls and tool results on MCP services. A request or reply that AIRS flags is blocked, and the caller gets the reason and the AIRS report id. Clean traffic passes. Unity AI Gateway's service policies are in Beta.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | Yes | Before the call reaches the model, every message the policy receives is scanned: the prompt, earlier turns, the system prompt and assistant turns. By default the policy receives the last 10 messages; with "Evaluate the entire conversation" ticked, the whole history (see "What changes for callers"). |
| Response | Yes | The model's reply is scanned before it reaches the caller. A flagged reply is replaced by a refusal. |
| Streaming | Partial | Streamed replies are scanned. Full response evaluation holds the whole reply until it is scanned. Streaming evaluation releases text that has passed a check: it never releases the flagged part, but what was already sent can't be recalled. |
| Pre-tool call | Yes | On MCP services, a tool call's arguments are scanned before the tool runs, and a flagged call never reaches the MCP server. Tool calls in a chat conversation are scanned with its messages. |
| Post-tool call | Yes | On MCP services, tool results are scanned before they reach the caller. Tool results sent back in a chat conversation are scanned with its messages. Tool lists are not scanned (see "Known limits"). |

## How it works

```
caller --> Unity AI Gateway --> model or MCP service
                 |
                 | service policy, before the call (prompt, tool call) and after it (reply, tool result)
                 v
   Python Policy:           Python policy (a Unity Catalog function in the workspace) ------------------> Prisma AIRS
   Databricks App Adapter:  External policy --> UC HTTP connection --> Databricks App ------------------> sync scan API
   AWS Adapter:             External policy --> UC HTTP connection --> AWS HTTP API + Lambda function -->
```

- One scanning core, `src/airs_core.py` (standard library only), runs in all three deployment options. Only the wrapper differs: `src/python_policy/` (the function), `src/app_adapter/app.py` (the App), `src/aws_adapter/lambda_adapter.py` (the Lambda function and its token issuer).
- The policy answers ALLOW or DENY. Neither policy type can change a payload, so there is no masking.
- It fails closed. AIRS errors, timeouts, content it can't read and oversized requests are all denied. Databricks also denies when the External policy doesn't answer within 5 seconds.

## Which deployment option

| Option | Runs in | Use it when | Needs |
|---|---|---|---|
| Python Policy | A Python service policy in the workspace | You want the quickest start, with nothing extra to run | Python service policies in your region: see Databricks' list for [AWS](https://docs.databricks.com/aws/en/data-governance/unity-catalog/service-policies/python-policies) or [Azure](https://learn.microsoft.com/en-us/azure/databricks/data-governance/unity-catalog/service-policies/python-policies) (on 24 November 2026: ap-southeast-1, ap-southeast-2, us-east-1 and us-west-2 on AWS; eastus, eastus2, centralus and westeurope on Azure; Databricks' Google Cloud documentation offers no Python policies). Also serverless egress to the AIRS API. Not available in workspaces that use the compliance security profile, a serverless network policy that restricts internet access or blocks specific destinations, a private network gateway, or serverless private endpoints: Databricks then denies every request in Enforce mode (Log mode only records it), so use one of the Adapters. Databricks checks the region and these settings on the workspace that sends the request |
| Databricks App Adapter | A Databricks App called by an External policy | You want everything to stay inside Databricks | Databricks Apps and HTTP connections in your region (App compute is billed while it runs) |
| AWS Adapter | AWS API Gateway and Lambda, called by an External policy | Any cloud, or when Apps or Python policies aren't available | HTTP connections in your region, an AWS account, and a public HTTPS endpoint protected by OAuth client credentials |

## Prerequisites

- A Prisma AIRS API key and a security profile. The profile decides what is blocked. Data loss prevention (DLP) and prompt injection detection are the usual minimum.
- Unity Catalog and serverless compute.
- Previews:
  - in the account console (Previews): **Enhanced Unity AI Gateway (Beta)**;
  - in the workspace (user menu > Previews): **Unity Gateway Service Policies (Beta)**, which is on once the account preview is;
  - the Python Policy also needs **Unity Gateway Custom Python Service Policies (Beta)** and **Enable networking for isolated workloads in serverless SQL warehouses**. The second one lets the function reach the AIRS API. It opens a path for data to leave the workspace, so agree it with your security team. It takes up to 15 minutes to apply.
- Network egress, if the workspace restricts it with a serverless network policy: the Python Policy is not an option (above). Allow the AIRS API host for the Databricks App Adapter (its App calls AIRS), and, for both Adapters, the adapter's host, which the policy calls. Our lab had no egress restrictions, so this is from Databricks' documentation, not tested.
- Both Adapters: start each policy in Log mode, check the verdicts in the trace table, then switch to Enforce. The Python Policy's form has no Log mode; the service config's `dry_run` setting (API only) gives one, with the verdicts in the trace table.
- The trace table: a metastore admin sets it up (AI Gateway > Govern > Traces > Set up tracing). It holds the full text of every request and reply, for all users, and takes its access from its schema, so put it in a schema only the security team can read.

## Configuration Steps

### Python Policy

1. Store the AIRS key as a Unity Catalog secret (here `main.airs.airs_api_key`). Put the request body in a file, so the key never appears in a command line or SQL: `databricks api post /api/2.1/unity-catalog/secrets --json @secret.json`, where `secret.json` holds `{"catalog_name": "main", "schema_name": "airs", "name": "airs_api_key", "value": "<key>"}`. Delete the file afterwards.
2. Render the function: `python3 src/python_policy/build_function.py --function main.airs.airs_policy --secret main.airs.airs_api_key --profile <AIRS profile> > airs_policy.sql`. Options: `--airs-url` (your region's sync scan URL; the US one by default), `--app-name` (your app's name, sent as `Databricks-<name>`) and `--budget` (seconds for the scans, default 20).
3. Run `airs_policy.sql` in the SQL editor on a serverless warehouse. Then, on the service, add a policy: Custom, then Custom function, then select this function. The form has no phase choice: the function sees both the request and the reply, and the whole conversation. Choose Full response evaluation.
4. To change the code or settings, create the function under a **new name** and point the policy at it. If you replace the function the policy was saved with, every request fails with HTTP 400 until you save the policy again.

### Databricks App Adapter

1. Create a secret scope holding the AIRS key (for example, scope `airs`, key `airs_api_key`).
2. Create a service principal for the connection to sign in as, and give it an OAuth secret.
3. Create the App. Give it one secret resource named `airs-key`, pointing at that scope and key with READ permission. In `src/app_adapter/app.yaml`, set `ALLOWED_CALLER` to `<service principal SCIM id>@<workspace id>`. That is the value the Apps proxy sends as `X-Forwarded-User`. The App answers 403 to any other caller.
4. Deploy `src/app_adapter/app.py`, `src/app_adapter/app.yaml`, `src/airs_core.py` and `src/airs_adapter.py` together as the App's source. Then give the service principal CAN USE on the App.
5. Create a Unity Catalog HTTP connection with OAuth machine-to-machine sign-in:
   - host: the App URL; port: 443; base path: `/api/policy`;
   - token endpoint: `https://<workspace host>/oidc/v1/token`; scope: `all-apis`;
   - client id and secret: the service principal's.

### AWS Adapter

1. Store the AIRS key as an SSM SecureString in the account and region you deploy to, from a file so it stays out of your shell history: `aws ssm put-parameter --profile <profile> --region <region> --name /dbx-airs/airs_api_key --type SecureString --value file://airs-key.txt`. Delete the file afterwards. Leading and trailing spaces and newlines are ignored.
2. Run `AWS_PROFILE=<profile> AWS_REGION=<region> src/aws_adapter/deploy.sh` (needs the AWS CLI, `python3` and `zip`). It creates a random client id, client secret and token signing key in SSM (never shown), deploys `src/aws_adapter/template.json`, uploads the code, and prints `TokenUrl` and `ApiEndpoint`.
3. Create a Unity Catalog HTTP connection with OAuth machine-to-machine sign-in:
   - host: `ApiEndpoint`; port: 443; base path: `/policy`;
   - token endpoint: `TokenUrl`; scope: `policy`;
   - client id and secret: the values of `/dbx-airs/c_client_id` and `/dbx-airs/c_client_secret`.
   The adapter's tokens last one hour. Databricks fetches one token per connection and renews it about 5 minutes before it expires.

### Attach the policy (both Adapters)

On the service, add an External service policy:
- the connection;
- both phases;
- policy config `{"profile": "<AIRS profile>"}`;
- Full response evaluation;
- "Evaluate the entire conversation" on chat services.

Then grant USE CONNECTION on the connection (see "Grants and side doors").

Keep the policy's own `on_error` option at DENY, the default. It is Databricks' choice when our adapter can't answer (a timeout, a stopped App, a refused token); ALLOW there lets traffic through unscanned. It can be changed through the API, so check it after changes. It is not the `on_error` in the policy config.

## Settings

- **Policy config** (both Adapters):
  - `profile` (required);
  - `app_name`: your app's name. Prisma AIRS receives `Databricks-<app_name>`, or `Databricks` when it isn't set;
  - `on_error` (`deny` by default).
- **Adapter environment** (both Adapters):
  - `AIRS_URL`: another https scan endpoint; the US one by default.
  - `ALLOW_FAIL_OPEN`: with `on_error: allow` in the policy config and this set to `true`, a request passes unscanned when AIRS times out, can't be reached, or answers HTTP 5xx or 429 (its rate limit), even when only one chunk of a long request times out. A 4xx, a redirect, a flagged or malformed answer, and any local error always deny. Off (the default), all of these deny.
  - `ALLOW_UNSCANNED_PARTS`: `true` lets parts it can't read (images, audio, files) through, instead of denying the request.
- **Size:** text is scanned in parallel chunks of 50,000 characters, up to about 398,000 characters per call. Anything larger is denied as too large to scan.
- **AIRS rate limit:** AIRS limits each tenant's requests. When it answers 429, every call is denied (unless fail-open is on, above). Each chat call makes two scans or more, so size your AIRS quota to the traffic.

## What changes for callers

- **Blocks:** a blocked chat call returns HTTP 200 with a refusal (`finish_reason` `content_filter`) and a `databricks_service_policy` field: the policy's name, action and phase, and our reason, for example `Blocked by Prisma AIRS: dlp. Report R...`. A blocked MCP call returns a JSON-RPC error whose message is our reason. A blocked embeddings call returns HTTP 400.
- **When the policy can't decide:** callers see our reason, such as `Prisma AIRS could not scan this request.`, `Prisma AIRS policy configuration error: ...` or `Blocked: the Prisma AIRS policy failed.`, or Databricks' own `external policy evaluation failed: ...` when the adapter can't be reached, refuses its token, or is throttled.
- **Requests refused before the policy runs:** Databricks answers HTTP 400 when
  - a request asks for more than one choice (`n` > 1);
  - the request tags header isn't a JSON map;
  - the tags are over 10,240 bytes.
- **Conversation window:** by default the policy sees only the last 10 messages. A card or injection in an older message passes unless "Evaluate the entire conversation" is ticked. With it ticked, the whole history is scanned on every turn, and very long chats reach the size cap and are refused.
- **Streaming:**
  - Full response evaluation holds the whole reply until it is scanned.
  - Streaming evaluation releases text that has already passed a check. It never releases the flagged part, but what was already sent can't be recalled.
- **Latency** (both Adapters, warm): AIRS adds about 0.4 s per phase. A blocked prompt comes back in about 1 s. The Python Policy's own timings were not measured separately.

## Grants and side doors

- **USE CONNECTION.** Every caller of a service with an External policy needs USE CONNECTION on the policy's connection. Databricks checks it for each caller. Holding it also lets that caller send requests through the connection's proxy straight to the adapter. Those requests only get verdicts back and never reach a model, but each one costs AIRS scans. Grant it to exactly the policy's callers (a group), and watch the audit log. Removing it is slow to take effect. In our test, about half of the caller's calls still went through for 40 minutes afterwards, and the last one 68 minutes later. Every call that reached our adapter was scanned (checked against its logs). For an urgent cut-off, plan for that delay.
- **Shared models outside the gateway.** By default all account users can call Databricks' shared models directly, with no policy:
  - through `system.ai` services;
  - through the pay-per-token `/serving-endpoints` paths;
  - from SQL with `ai_query`;
  - from SQL with `ai_gen`.

  Two controls close all but the last, and both were tested:
  - Revoke `EXECUTE` on `system.ai` from account users, and grant it only to those who need it. This closes `system.ai` through the gateway and `ai_query` on `system.ai` names. Your gateway services keep working.
  - Turn on "Enforce Unity Gateway" (workspace settings, Advanced). This closes the pay-per-token `/serving-endpoints` paths and `ai_query` on the old names. Per Databricks' documentation it leaves existing provisioned-throughput and external-model endpoints callable, stops all traffic to legacy pay-per-token endpoints, and some features don't work with it yet (Knowledge Assistant and Multi-Agent Supervisor on AI Search, and automatic authentication passthrough for agents on model serving). Check both before turning it on.

  `ai_gen` stays open to anyone with SQL access, so limit SQL access: the `databricks-sql-access` and the `workspace-consume` entitlements both grant it.
- **Admins are covered.** Workspace admins' calls go through the same policies (tested on the Python Policy and the AWS Adapter).
- **The AWS Adapter's endpoint is public.** Databricks calls `/policy/` (with a trailing slash), which goes through the API's `$default` route. Its throttle (burst 20, 10 requests a second) is shared with any other traffic to the API host, and anyone who knows the host can send traffic to it. In our test, 30 junk requests a second for 10 seconds (measured) made API Gateway throttle 187 of the 300, and every guarded call made during the flood was refused (`external policy evaluation failed: Too Many Requests`): nothing passed unscanned, but service was denied while the flood lasted. For production: raise the stage throttle to fit your traffic (in `template.json`), put CloudFront with AWS WAF rate rules in front (an HTTP API can't take a WAF directly), and disable the default `execute-api` endpoint once CloudFront or a custom domain serves the API.

## Technical Requirements

1. **`app_name`** is `Databricks`, or `Databricks-<app_name>` when `app_name` is set: in the policy config on both Adapters, or with `--app-name` on the Python Policy. At most 64 characters.
2. **`tr_id`** is Databricks' trace id for the call on both Adapters. The Python Policy sends a new random id each time its function runs.
3. **Fails closed by default.** AIRS errors, timeouts, content it can't read and oversized requests are denied. See "Settings" for the narrow fail-open option.
4. **The API key** is kept in a Unity Catalog secret (Python Policy), in a secret scope read through the App's secret resource (Databricks App Adapter), or in an SSM SecureString (AWS Adapter). It is sent only to the Prisma AIRS API and never logged.
5. **Regional endpoints** (from the pan.dev scan API specification). The US one is the default. Set another with `AIRS_URL` on both Adapters, or `--airs-url` on the Python Policy:

| Region | Sync scan URL |
|---|---|
| US (default) | `https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request` |
| EU (Germany) | `https://service-de.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request` |
| India | `https://service-in.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request` |
| Singapore | `https://service-sg.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request` |

## Known limits

- **Card numbers are matched as AIRS's DLP sees them.** Digits split by newlines, or hidden in base64, are not flagged as a card. Base64 in prompts and tool data was flagged as injection instead; in replies it passed.
- **Long, repetitive clean text** (tens of thousands of characters) can be flagged as injection by the security profile. Tune the profile if your traffic looks like that.
- **A tool with no arguments still runs during an AIRS outage.** There is nothing to scan on the call, so it is allowed; its result is then denied.
- **Tool data is scanned whole.** Tool arguments, tool inputs in a conversation and structured tool results are sent to AIRS as JSON, field names included, so nothing hides under a name like `type` or `model`.
- **Requests over the size cap are denied,** never passed unscanned.
- **MCP tool lists are not scanned.** Listing a server's tools runs no policy, so tool descriptions pass unchecked.

## Rotating secrets

- **The AIRS key:**
  - Python Policy: update the UC secret's value. Our test: the function saw the new value after about a minute (the value is cached briefly), so keep the old key valid for a few minutes;
  - Databricks App Adapter: update the secret in the scope, then redeploy the App (the key is injected when the App starts);
  - AWS Adapter: put the new value in `/dbx-airs/airs_api_key`; warm containers pick it up within 5 minutes, or start new ones as below.
- **Databricks App Adapter client secret:** create a new OAuth secret for the service principal, update the connection's client secret, then delete the old one. Our test: no interruption. The old secret was refused about a minute after it was deleted, and calls kept working for the next 70 minutes, past the hour Databricks' token lasts.
- **AWS Adapter client secret:**
  1. Put a new value in `/dbx-airs/c_client_secret`.
  2. Start new Lambda containers, so none still holds the old value: change the function's description, or wait 5 minutes (warm containers re-read SSM every 5 minutes).
  3. Update the connection's client secret. Databricks fetches a new token with it at once.

  Our test: no interruption (16 calls over the next 5 minutes, none refused). The token Databricks already held stayed valid throughout.
- **AWS Adapter signing key:**
  1. Put a new value in `/dbx-airs/c_signing_key`.
  2. Start new containers, as above.
  3. Straight away, update the connection. Any update works, even one that keeps every setting.

  Tokens signed with the old key are refused from step 2. Databricks does not fetch a new token after a refusal; it only fetches one when the connection is updated, or when its token expires (up to an hour later). Until then every call is refused, never passed. Our test (checked every 20 s): refused for about 2 to 2.5 minutes, most of it our deliberate wait to see whether Databricks recovers by itself (it doesn't). Calls worked again within 20 s of the connection update.

## Validation

The offline tests run with `python3 -m pytest` in this folder (see "Files and tests"). The live tests below ran on Unity AI Gateway services in a Databricks trial (AWS):
- the Python Policy in us-west-2;
- the Databricks App Adapter and the AWS Adapter in us-east-2, with the AWS Adapter's API and Lambda function in AWS us-west-2.

| Test | Python Policy | Databricks App Adapter | AWS Adapter |
|---|---|---|---|
| A card in the prompt, an earlier turn, the system prompt or an assistant turn, or split across two parts: blocked; clean text passes | yes | yes | yes |
| A card the real model writes in its reply, plain and streamed: blocked | yes | yes | yes |
| A card in an MCP tool's arguments (the tool never runs) or in its result: blocked | yes | yes | yes |
| A card in a fake model's reply, plain, streamed and in the OpenAI format: blocked | | yes | yes |
| Log mode: would-block verdicts recorded, nothing blocked | yes (trace table, API) | yes (App log) | yes (trace table) |
| A card older than 10 messages, with "Evaluate the entire conversation" ticked: blocked | yes (sees all) | yes | yes |
| The same card with the default 10-message window: passes | | yes | yes |
| Failures: every call refused, no internal details shown | key rejected | key rejected, AIRS unreachable, App stopped | key rejected, AIRS unreachable, adapter down, broken settings |
| Admins' calls go through the policies | yes | | yes |
| 75 minutes of steady traffic across a token renewal: nothing unexpected | | yes | yes |
| Secret and key rotation (results under "Rotating secrets") | | yes | yes |
| 5, 10 and 20 questions at once: each answer had its own scanned prompt and reply, nothing unscanned (checked against the App's and the adapter's logs) | | yes | yes |
| 30 junk requests a second at the API for 10 seconds: guarded calls refused while it lasted, none passed unscanned | | | yes |
| Deployed from this package into a fresh region: signs in, allows clean text, blocks the card | | | yes |

Timings, warm, end to end through the gateway: a blocked prompt about 1 s; a full answer about 2.4 s, of which our scans took about 0.4 s per phase. On the AWS Adapter, a cold start added about 0.8 s (Lambda start-up about 0.15 s, and a first scan of about 1 s instead of 0.3 to 0.4 s).

Under bursts, Databricks' own per-workspace rate limit on its shared model refused some calls with HTTP 429 (Databricks App Adapter 9 of 35, AWS Adapter 8 of 35, mostly at 20 at once). The prompt had already been scanned, and no answer came back unscanned. That limit is Databricks' own, on the model endpoint, not the policy's.

## Files and tests

- `src/airs_core.py`: the scanning core (extraction, chunking, the AIRS client, verdicts, the log line).
- `src/airs_adapter.py`: the External policy contract, shared by both Adapters.
- `src/python_policy/`, `src/app_adapter/`, `src/aws_adapter/`: the three wrappers, and the AWS Adapter's template and deploy script.
- `tests/`: offline tests. Run `python3 -m pytest` (Python 3.10 or later, pytest 7 or later). They never call AIRS or Databricks: only the loopback address resolves while they run.

Both Adapters log one line per call, with fixed fields only: event type, verdict, scan and report ids, error class, latency and trace id. They never log content, headers or secrets. The Python Policy's function logs nothing: its verdicts are only in the trace table. On the AWS Adapter, API Gateway's access log also records each request's source IP, path, status and User-Agent.
