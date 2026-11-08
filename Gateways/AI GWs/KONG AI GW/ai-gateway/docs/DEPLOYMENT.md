# Deployment

Prisma AIRS enforcement on Kong AI Gateway 2.x, deployed as configuration: no custom plugin, no
rebuilt image. `kongctl` is the primary path; the same work in the Konnect console is section 5.

Claims are tagged **DOCUMENTED** (from Kong or Palo Alto Networks documentation), **MEASURED**
(established first-hand; unless stated otherwise the date is 2026-09-12 and the runtime is
AI Gateway 2.0.3), or **UNVERIFIED** (believed, not tested — do not build a control on it). No
tenant value appears below: replace `<AI_GATEWAY_ID>`, `<REGION>`, `my-profile`, `my-model` and
`my-mcp` with your own.

**Read [section 7, Limitations](#7-limitations), before you deploy.** There are two measured
coverage gaps, one structural MCP limit and one defect; a reader who skips them will believe this
covers traffic it does not.

---

## 1. Prerequisites

| You need | Notes |
| --- | --- |
| An AI Gateway control plane | Created in Konnect through a three-step wizard: control plane, data plane type, deploy instances. There is no region field; the region comes from the organisation. (MEASURED) |
| A self-managed data plane | Section 2. Only Self-managed ships today. |
| `kongctl` | Konnect's declarative CLI. Every command and every trap below was measured with kongctl 1.15.1. |
| A Prisma AIRS security profile and API key | From an AIRS API Intercept application. The profile name is what you export as `PRISMA_AIRS_PROFILE_NAME`; the key is `PRISMA_AIRS_API_KEY`. |
| A Konnect personal access token | Exported as `KONGCTL_DEFAULT_KONNECT_PAT`. kongctl reads it from the environment, which keeps the token out of the process table and out of your shell history. |
| Your AI Gateway id | MEASURED: AI Gateways are **not** in `/v2/control-planes`. They live at `https://<REGION>.api.konghq.com/v1/ai-gateways`. Export it as `AI_GATEWAY_ID`; every config file resolves the gateway with `!lookup { id: !env AI_GATEWAY_ID }`. |

The AIRS scan endpoint shipped in the configs is
`https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`; if your profile is in a
region with a different hostname, take it from onboarding rather than guessing.

---

## 2. The data plane

MEASURED: only the **Self-managed** data plane type ships — "Serverless" and "Dedicated Cloud" both
show "Coming soon". Its runtime options are Docker, Linux binary and Kubernetes, and the image
`kong/kong-ai-gateway:2.0.3` is multi-arch (amd64 and arm64).

MEASURED, and worth knowing before you debug anything: the data plane's telemetry URL reports
`node_version=3.14.0.3` alongside `kong_aigw_version=2.0.3`; `kong version` inside the container
answers "Kong AI Gateway 2.0.3"; the image's OCI label is `org.opencontainers.image.title=kong-ee`;
and `/usr/local/share/lua/5.1/kong/plugins/` carries the full classic plugin set (100+, including
`ai-custom-guardrail`, `request-callout`, `post-function`, `pre-function`, `ai-proxy`,
`ai-proxy-advanced`, `ai-mcp-proxy`, `ai-prompt-guard`). State the conclusion carefully: the runtime
is Kong Gateway 3.14 with the classic plugin loader intact. What AI Gateway 2.x removes is the
control plane surface for *declaring* a custom plugin, not the runtime's ability to run Lua.

### The uid 1001 trap

MEASURED: the container runs as uid/gid **1001**, not 1000 like the classic Kong image. A cluster
certificate private key mounted `600` and owned by `1000` fails with

```
failed reading the cluster certificate private key file: Permission denied
```

and the container restart-loops with no other clue in the log. Fix the ownership on the host before
looking for anything else: `chown 1001:1001 cluster.key cluster.crt`.

### Optional: keep the data plane private key on the host

The wizard issues a certificate and hands you the private key. To keep the key on the host, generate
the pair there and register only the certificate:
`POST https://<REGION>.api.konghq.com/v1/ai-gateways/<AI_GATEWAY_ID>/data-plane-certificates` with a
Konnect bearer token. MEASURED: the body is `{"title", "cert"}`, `title` is **required** (400
without it), and a self-signed EC P-256 certificate works.

MEASURED: the sub-resources under `/v1/ai-gateways/{id}` are `policies`, `models`,
`model-providers`, `mcp-servers`, `agents`, `consumers`, `nodes`, `certificates`,
`data-plane-certificates`, `auth-strategies` and `config-stores`. `dp-client-certificates` and
`data-planes` return 404.

---

## 3. Where the AIRS key rests

Both policies reference the key as `{vault://airs/prisma-airs-api-key}`. That reference is identical in both
shapes; only the Vault entity changes, and the Vault entity decides **where the key rests**.

**Shape A — Konnect config store.** Written at apply time from a deferred `!secret` source. Nothing
is needed on the data plane host; the key does rest in Kong's control plane. This is what
`config/lab/airs-secret.yaml` ships:

```yaml
ai_gateway_config_stores:
  - ref: airs-store
    name: airs-store
    ai_gateway: !lookup { id: !env AI_GATEWAY_ID }
    display_name: prisma-airs-credentials   # MEASURED: spaces rejected; letters, numbers,
    secrets:                                # periods, hyphens, underscores and tildes only
      - {ref: prisma-airs-api-key, key: prisma-airs-api-key, value: !secret {source: !env PRISMA_AIRS_API_KEY}}

ai_gateway_vaults:
  - ref: airs
    name: airs
    ai_gateway: !lookup { id: !env AI_GATEWAY_ID }
    type: konnect
    config: {config_store_id: !ref airs-store}
```

kongctl will not read the value back, so the key exists in exactly two places: your shell, and
Konnect.

**Shape B — environment vault on the data plane.** The key is an environment variable on the data
plane and never reaches Kong's control plane at all. Replace the vault above with `type: env`, set
the key in the data plane's own environment, and deploy no config store. Get the prefix right — the
rule is in section 5. With no `config.prefix`, `{vault://airs/prisma-airs-api-key}` resolves the environment
variable `PRISMA_AIRS_API_KEY`; with `config.prefix: AIRS_` the same reference resolves `AIRS_PRISMA_AIRS_API_KEY`.

**Which to choose.** Shape B where a security vendor's credential must not sit in a SaaS control
plane; that is the recommendation here. Its cost: the key becomes part of data plane provisioning,
so every host needs it and rotation is a deployment rather than an apply. Shape A where one place to
rotate is worth the control plane holding the key, and for data planes that should carry nothing.

DOCUMENTED: `ai-custom-guardrail`'s `request.auth.value` is the only field in that schema marked
both referenceable and encrypted, so on the LLM path the stored value is encrypted at rest.
`request-callout` has no documented equivalent slot for its `x-pan-token` header, and whether that
vault reference is stored encrypted is UNVERIFIED. Shape B removes the question.

---

## 4. Deploy with kongctl

### Build `dist/` first

`dist/` is generated and **not** committed. `scripts/build-config.py` inlines each file from `lua/`
at its `__INLINE__` marker, so the Lua stays in real files where it is linted and unit tested. The
MCP callout cannot read its own policy config at runtime, so the AIRS profile name and MCP server
name are pinned into its Lua at build time — which is why a committed `dist/` would carry one
deployment's tenant values.

```bash
export AI_GATEWAY_ID="YOUR_AI_GATEWAY_ID"
export PRISMA_AIRS_PROFILE_NAME="YOUR_PROFILE_NAME"
export AIRS_MCP_SERVER_NAME="YOUR_MCP_SERVER_NAME"
export PRISMA_AIRS_API_KEY="YOUR_AIRS_API_KEY"
export KONGCTL_DEFAULT_KONNECT_PAT="YOUR_KONNECT_PAT"

python3 scripts/build-config.py          # rebuild dist/ from config/ + lua/
python3 scripts/build-config.py --check  # fail if dist/ is stale (use in a pipeline)
```

A missing variable stops the build rather than emitting a config that would send the literal text
`!env PRISMA_AIRS_PROFILE_NAME` to AIRS as a profile name. Apply from `dist/`, never `config/`.

### Apply, in order

Vault before policy (the policy resolves a vault reference), policy before binding (a binding names
a policy).

```bash
# 1. config store and vault (Shape A; for Shape B apply the vault alone)
kongctl apply -f dist/lab/airs-secret.yaml

# 2. the two policies
kongctl apply -f dist/llm/airs-guardrail.yaml
kongctl apply -f dist/mcp/airs-mcp-request-scan.yaml

# 3. bind them to the AI Model and the AI MCP Server -- below
```

None of those commands carries the token: kongctl reads `KONGCTL_DEFAULT_KONNECT_PAT` from the
environment. `--pat "$SOME_VAR"` works on every command as an alternative, at the cost of putting
the token in the process table and in your shell history; prefer the environment form.

Dry run with `kongctl plan -f <file>`. MEASURED: with deferred `!env` values
present, `plan` prints a **warning line before the JSON**, so piping it into a JSON parser fails.

### Scaffold before you write a new entity

MEASURED: `kongctl explain <resource> --extended` **omits union selector fields**. Model providers,
models and MCP servers are all discriminated unions with a top-level `type:` the field list never
mentions, and the apply fails with `missing required union selector type`. `kongctl scaffold
<resource>` is the authoritative shape.

| Entity | `type:` values (MEASURED) |
| --- | --- |
| model provider | `openai`, `azure`, `bedrock`, … |
| model | `model`, `api` |
| MCP server | `conversion-only`, `conversion-listener`, `listener`, `passthrough-listener`, `upstream-server` |

MEASURED: kongctl refuses an inline credential literal in a provider auth field — `field
/config/auth/headers/0/value is write-only and requires !secret with a deferred source`. Use
`value: !secret {parts: ["Bearer ", !env SOME_KEY]}`; a credential cannot be committed by accident.

### Bind the policy

MEASURED: a policy defaults to `global: false` and then **intercepts nothing**. It is created, it is
enabled, it appears in the UI, and no traffic reaches it — the single most common reason a
deployment looks finished and enforces nothing. Bind it by listing the policy's **`name`**, not its
`ref`, in the entity's `policies` list.

```yaml
ai_gateway_models:
  - ref: my-model
    name: my-model
    ai_gateway: !lookup { id: !env AI_GATEWAY_ID }
    type: model                       # union selector; only `scaffold` shows it
    policies: [airs-scan]
    targets:                          # upstream_url is the FULL endpoint URL, not a base
      - {name: my-model-target, provider: my-provider, config: {type: openai,
          upstream_url: http://upstream.internal:9100/v1/chat/completions}}
    config:
      response_streaming: deny        # closes Gap 1 -- section 7
      route: {paths: [/v1]}           # BASE path; Kong appends /chat/completions

ai_gateway_mcp_servers:
  - ref: my-mcp
    name: my-mcp
    ai_gateway: !lookup { id: !env AI_GATEWAY_ID }
    type: passthrough-listener
    policies: [airs-mcp-scan]
    config: {url: http://mcp.internal:9200, route: {paths: [/mcp]}}
```

MEASURED: `ai-custom-guardrail` **cannot** be attached to an MCP server — the Konnect control plane
refuses the update with a 400, quoted in full in section 5. `request-callout` **is** accepted at
`mcp-servers` scope. That contrast is the reason this integration has two halves.

`global: true` on the policy instead covers every model, MCP server and agent on the gateway. Naming
it on one entity keeps the blast radius small while you prove the integration; global is the
production answer once you have.

---

## 5. The same work in the Konnect console

For a reader who would rather click than run `kongctl`, and for a reader of `config/` who wants to
know what each key looks like on screen. All of it was seen on AI Gateway 2.0.3 with a Konnect
control plane and a self-managed data plane.

### Do not build the two policies here

The guardrail carries four Lua functions. They live in `lua/guardrail/` as real files,
`spec/verdict_spec.lua` exercises them offline, and `scripts/build-config.py` inlines
them into the policy YAML under `dist/`. Paste those function bodies into a console form and that
chain is broken: the Lua becomes a string in a SaaS form field — not linted, not unit tested, not
reviewed line by line, not reproducible. `airs_verdict.lua` is the only code here that decides
whether traffic continues, and it should not be maintained by copy and paste. The same holds for the
MCP callout's three `by_lua` hooks, covered by `spec/mcp_callout_spec.lua`. The two spec files are
106 assertions in total — 40 in `verdict_spec.lua`, 66 in `mcp_callout_spec.lua`.

| Task | Console | `kongctl` |
| --- | --- | --- |
| Create the AI Gateway, deploy a data plane | Yes | No control plane surface for it |
| Providers, models, MCP servers, consumers | Yes | Either |
| Vault and secret for the AIRS key | Yes | Either |
| The two policies and their Lua | First look only | Yes — automate these |

An entity created in the console is not in the declarative configuration, and `kongctl apply` will
not adopt, reconcile or delete it. That is fine for the gateway itself, which the declarative files
reference with `!lookup` and never create. It is harmful for a **policy**: two definitions of the
control that decides whether traffic passes, with test coverage on one. Delete any console-built
policy before applying the declarative version.

### Creating the gateway

A three-step wizard (MEASURED). **Control plane**: name the gateway; there is no region field, the
region comes from the organisation, which is also why the API host is
`https://<REGION>.api.konghq.com`. **Data plane type**: three options are shown and only
**Self-managed** can be selected — Serverless and Dedicated Cloud both display "Coming soon".
**Deploy instances**: choose Docker, Linux binary or Kubernetes; the console issues a data plane
certificate and key and hands you a run command. Read the uid 1001 trap in section 2 before you run
it. The gateway's tabs mirror the sub-resources listed in section 2; this integration uses Models
(the guardrail attaches here), Providers, MCP servers (the callout attaches here), Policies, Vaults,
and Overview for `config_version` when debugging a 404.

### A model provider — Amazon Bedrock

Bedrock is the worked example because a self-managed data plane on EC2 is the common shape, and the
credential handling is the part people get wrong. Create a provider and choose **Amazon Bedrock**;
declaratively that is the union selector `type: bedrock`.

**Choose AWS IAM, not API key.** Bedrock authenticates with SigV4 request signing, not a bearer
token, so the API-key path does not apply. DOCUMENTED (AWS).

**Then leave every credential field empty.** For a data plane on EC2 the correct configuration is to
fill in nothing: the gateway falls back to the ambient AWS credential chain, which resolves to the
instance profile. Nothing static is stored in Konnect and rotation is AWS's problem. What you are
declining, MEASURED (console):

| Field | What it is for | Why empty here |
| --- | --- | --- |
| Access key ID | Static IAM user or exported role credential | Long-lived static credentials in a control plane; the instance profile supersedes it |
| Secret access key | The matching secret | As above |
| Session token | Third element of a temporary credential triple | Temporary credentials expire; an instance profile refreshes itself |
| Assume role ARN | A role to assume before calling Bedrock | Only for cross-account Bedrock, or when the instance role is deliberately minimal and a second role holds the Bedrock grants |
| Role session name | The name that appears in CloudTrail for that session | Only meaningful with an assume role ARN set |
| STS endpoint URL | Override for the STS endpoint used to assume the role | Only for a VPC STS endpoint or a non-standard partition |
| Batch role ARN | Role for Bedrock batch inference jobs | This integration is synchronous inference only |

For role assumption, fill in the assume role ARN and role session name and leave the three static
credential fields empty; the "no stored secret" property survives. The instance role needs at
minimum, DOCUMENTED (AWS):

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
    "Resource": "arn:aws:bedrock:<REGION>::foundation-model/<MODEL_ID>"
  }]
}
```

`InvokeModelWithResponseStream` is needed even if you forbid streaming at the gateway: the
permission and the gateway setting are independent controls.

The part that catches people: **a cross-region inference profile needs permission on two kinds of
ARN.** DOCUMENTED (AWS). `bedrock:InvokeModel` on the inference profile ARN *and* on the underlying
foundation-model ARN in **every region the profile can route to**, not just the region your instance
sits in. A policy granting only the profile ARN, or only the home region's model ARN, fails
intermittently — it works until the profile routes elsewhere, which looks like a gateway fault and
is an IAM one. One property you give up in the console: it stores whatever is typed into a
credential field, where kongctl refuses it outright (section 4).

### A model

Create a model of type **Model** (declaratively `type: model`; the alternative is `type: api`).

- **Route path** is a **base** path (`/v1` exposes `POST /v1/chat/completions`) while the **target
  upstream URL** is the **full** endpoint URL. Getting either wrong costs an afternoon — see
  troubleshooting.
- **Model values** are gateway-facing aliases: the `model` field of the request body must match one.
  They need not equal the Bedrock model id; the target carries that.
- **Format** `openai` is what makes the appended `/chat/completions` suffix correct;
  **capabilities** `generate` is what a chat-completions model needs. Other values are UNVERIFIED.
- **`response_streaming` lives here, on the model.** MEASURED: it is `config.response_streaming` on
  the AI Model, **not a field on any policy**, and it is what closes Gap 1 (section 7). Set it to
  `deny` on every model carrying this guardrail. If some models genuinely must stream, give those an
  INPUT-only policy and state plainly that their coverage is prompt-only; do not attach the BOTH
  policy and assume the response is inspected.

### The AIRS key — Vaults tab

Section 3 applies unchanged; only the entry point differs. The `konnect` vault type needs a config
store id, and the tab strip lists Vaults but no Config stores tab; UNVERIFIED whether a config store
can be created from the console at all, though `config-stores` exists on the API, which is what
`config/lab/airs-secret.yaml` uses. The `env` vault is the console-friendly route and the better
choice anyway, but the reference does **not** resolve identically. DOCUMENTED (Kong): the `env`
vault prepends `config.prefix` to the key in the reference and reads the environment variable of
that combined name, uppercased with hyphens turned into underscores. So `{vault://airs/prisma-airs-api-key}`
on a vault with `prefix: AIRS_` resolves `AIRS_PRISMA_AIRS_API_KEY`, not `PRISMA_AIRS_API_KEY`. Two combinations
work; use one of them as written:

| Vault `config.prefix` | Reference in the policy | Environment variable on the data plane |
| --- | --- | --- |
| unset | `{vault://airs/prisma-airs-api-key}` | `PRISMA_AIRS_API_KEY` |
| `PRISMA_AIRS_` | `{vault://airs/api-key}` | `PRISMA_AIRS_API_KEY` |

Both shipped policies reference `{vault://airs/prisma-airs-api-key}`, so the first row is the combination
that works with them unchanged: a vault named `airs`, type `env`, no prefix, and `PRISMA_AIRS_API_KEY`
exported on the data plane host.

### The guardrail policy — Policies tab

Guardrails are a group in the policy list, nine of them (MEASURED, console). **There is no Palo Alto
Networks entry** — Kong's hub ships guardrail integrations for AWS, Azure, GCP, Lakera and NVIDIA
NeMo (DOCUMENTED). `ai-custom-guardrail` is the documented generic hook, described by Kong as
"Integrate with any 3rd-party Guardrail service", so this is a supported path rather than a
workaround. Select **AI Custom Guardrail**.

The wizard asks for a scope: **Global**, or **Scoped** and then attached to named entities. Scoped
is the one to choose, and it carries the trap from section 4 — a scoped policy that nothing
references is enabled and inert, with no warning. DOCUMENTED: the scopes `ai-custom-guardrail`
supports are AI Models, AI Consumers, AI Consumer Groups and Global; AI MCP Servers is not one.

Field defaults come from the AI Gateway 2.x **policy** schema, a different and larger contract from
the Kong Gateway 3.x **plugin** schema of the same name; `scripts/check-policy-schema.py` validates
against the policy schema for that reason. Every setting this integration uses, and why, is
commented field by field in `config/llm/airs-guardrail.yaml` and in [docs/DESIGN.md](DESIGN.md).

### An MCP server

Create one of type **passthrough-listener** — the type that fronts an existing MCP server rather
than converting REST APIs into one, which is the case Prisma AIRS needs to cover. Fill in the
upstream URL and a route base path such as `/mcp`, using the address your MCP server actually serves
on, including its path if it has one; UNVERIFIED which shape the passthrough listener requires in
general.

MEASURED, and the fact that shapes the whole MCP half of this integration: attaching
`ai-custom-guardrail` here is refused by the Konnect control plane.

```
400 Bad Request
policies: policy "airs-scan" of type "ai-custom-guardrail" is not supported for
scope "mcp-servers"
```

That is the API confirming, rather than prose implying, the gap Kong documents in the `ai-mcp-proxy`
scope-of-support table, where AI Guardrails on MCP requests and responses are listed as "Not
supported". **`request-callout` IS accepted at `mcp-servers` scope** (MEASURED). Attach
`airs-mcp-scan` here, and read
[Gap 3 — the MCP response leg is unreachable](#gap-3--the-mcp-response-leg-is-unreachable-measured)
before relying on it.

---

## 6. Verify

### LLM path

```bash
curl -sS -i http://<data-plane-host>:8000/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"my-model","messages":[{"role":"user","content":"Summarise the CAP theorem in one sentence."}]}'
```

MEASURED: a benign prompt returns **HTTP 200** with the answer. A prompt injection returns **HTTP
400**, body exactly:

```json
{"error":{"message":"Blocked by Prisma AIRS [scan_id=<uuid>]"}}
```

Note the status: **400, not 403.** That is `rejection_mode: none` behaviour, where the Kong Gateway
3.x custom plugin returns 403. Clients that special-case 403 as a security block will not recognise
it; that belongs in your client integration notes.

MEASURED: the `scan_id` in the client's error matches the `scan_id` in Strata Cloud Manager exactly,
so an operator can go from a user complaint to the detection record. MEASURED: with
`guarding_mode: BOTH` both legs genuinely run — two separate SCM transactions, one showing Prompt
and one Response. MEASURED: SCM shows `model_name: None` and `user_id: None` on every scan, because
a guardrail function cannot reach the model name or the calling consumer; do not plan correlation
work on either field.

### MCP path

MEASURED: the MCP route requires `Accept: application/json, text/event-stream`. Without it the MCP
proxy answers **406 Not Acceptable** before anything else happens.

```bash
curl -sS -i http://<data-plane-host>:8000/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"get_customer","arguments":{"id":"42"}}}'
```

MEASURED: clean arguments return **200**. An injection in the arguments returns **403** with an
in-protocol JSON-RPC error carrying the caller's own id:

```json
{"jsonrpc":"2.0","error":{"message":"Blocked by Prisma AIRS [scan_id=...]","code":-32001},"id":1}
```

The codes match the Kong 3.x custom plugin: `-32001` policy block, `-32003` scanner unavailable.
MEASURED: the fail-closed design works — with a misconfigured profile every `tools/call` was refused
with `-32003 "Prisma AIRS scan unavailable"` and the upstream never reached.

### A trap when writing your own test fixtures

MEASURED: delimiter-dense machine syntax in a prompt can itself trip the AIRS prompt-injection
detector, even when the content is meaningless.

| Prompt | Result |
| --- | --- |
| `do it @@toolcall@@` | 200 |
| `do it @@canned:p0@@` | 200 |
| `do it @@toolcall@@@@canned:p0@@` | **400 blocked** |
| `please answer the word injection` | 200 |
| `please answer @@canned:injection@@` | **400 blocked** |

Neither token alone triggers it; the combination does. Steering tokens in a prompt can therefore
silently turn a response-leg test into a request-leg test: the request is blocked, the upstream is
never called, and the test appears to pass while proving nothing. The lab fixtures in
`scripts/lab-echo-server.py` use plain uppercase words (`LAB0`..`LAB3`, `LABTOOL`) for that reason.

---

## 7. Limitations

Read this before you tell anyone the gateway is protected. Two measured coverage gaps — streamed
responses are not scanned, and LLM tool-call arguments are not scanned — one structural MCP limit,
the unreachable response leg, and one defect.

### Gap 1 — streaming bypass (MEASURED)

With `response_streaming: allow` on the AI Model, an identical payload is blocked when buffered and
delivered when streamed:

| Request | Result |
| --- | --- |
| payload in message content, buffered | HTTP 400, blocked on the response leg |
| payload in message content, streamed | HTTP 200, content delivered |

There is no error and no warning: any caller can opt itself out of response scanning by setting one
flag in its own request body. The remedy is `response_streaming: deny` on the AI Model. MEASURED
(2026-09-12): with `deny`, a `stream: true` request is refused at the gateway with HTTP 400 and the
body `{"error":{"message":"response streaming is not enabled for this LLM"}}` before any scan runs,
while buffered traffic is unaffected. Frame this honestly: the bypass is closed by **refusing**
streaming, not by scanning streams. Streaming and response-leg scanning cannot both be had on this
policy today. Found first by the prior art — see [docs/CREDITS.md](CREDITS.md).

### Gap 2 — tool calls are invisible on the LLM path (MEASURED)

A buffered reply with `content: null` and the payload only inside `tool_calls[].function.arguments`
is **allowed**. Kong's text extraction does not include tool-call arguments under any value of
`text_source`, so AIRS never sees them. The same applies to `tools[].function.description`: tool
definitions are not message content and never reach the scanner. This is **not fixable in
configuration** — the Kong 3.x custom plugin can read `tool_calls` directly, this config-only policy
cannot.

### Gap 3 — the MCP response leg is unreachable (MEASURED)

All three of `request-callout`'s Lua hooks — `callouts[].request.by_lua`,
`callouts[].response.by_lua` and `config.upstream.by_lua` — run **before** the upstream request.
`callouts[].response.by_lua` handles the reply from AIRS, not the reply from the MCP server. There
is no response-phase hook of any kind, so:

| MCP message | Result |
| --- | --- |
| `tools/call`, clean arguments | 200, allowed |
| `tools/call`, injection in arguments | 403, JSON-RPC `-32001` |
| `tools/call`, payload in the **result** | **200, delivered** |
| `initialize` | 200, bypassed unscanned |
| `tools/list` | 200, bypassed on the request leg |

Tool results and the tool catalogue are not inspected. State it the right way round: AIRS itself
**can** detect tool poisoning and malicious tool results today — MEASURED, a poisoned `tools/list`
catalogue submitted as `tool_event.output` returns `action: block` and names the poisoned tool. The
limitation is Kong's: `request-callout` cannot see the response leg to feed them to AIRS.

`config.upstream.by_lua` runs in the access phase, the only place the Kong PDK permits
`kong.response.exit` with a body, which is why an in-protocol JSON-RPC error is possible at all — an
MCP client that receives a bare 403 sees a dead transport, while a JSON-RPC error carrying its own
id is a tool failure the session survives.

### Defect — block reason metrics are dropped (MEASURED)

`metrics.block_reason` and `metrics.block_detail` wired to a string expression produce, on every
block:

```
[ai-custom-guardrail] metric input_block_detail has unexpected type string, expected table
```

and the metric is **dropped**. Blocking itself is unaffected; the operator-facing reason does not
reach Kong telemetry. Kong's own policy reference documents these fields as `type: string`, which
contradicts the runtime, and the shape the runtime wants is not documented. Unresolved: do not build
a dashboard or an alert on these metrics. Strata Cloud Manager, correlated by `scan_id`, remains the
complete record.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Every request gets Kong's generic `no Route matched with those values`. Reads exactly like a data plane sync failure, and is not one. | A **full** path in `config.route.paths`. MEASURED: `paths` is a BASE path and Kong appends the format's own suffix, so `paths: [/v1/chat/completions]` produces a route at `/v1/chat/completions/chat/completions`. | Use the base: `paths: [/v1]` exposes `POST /v1/chat/completions`. |
| The upstream receives `POST /` and answers 404 or 405. | A bare `host:port` in `targets[].config.upstream_url`. MEASURED: this field is the **full** endpoint URL, not a base. | `upstream_url: http://upstream.internal:9100/v1/chat/completions` |
| Apply fails with `missing required union selector type`, and the field is nowhere in the documentation you just read. | MEASURED: `kongctl explain <res> --extended` omits union selector fields. Model providers, models and MCP servers are all discriminated unions with a top-level `type:`. | Run `kongctl scaffold <res>`. Scaffold is authoritative where `explain --extended` is not. |
| Apply fails with `field /config/auth/headers/0/value is write-only and requires !secret with a deferred source`. | MEASURED: kongctl refuses inline credentials. Provider auth values are write-only. | `value: !secret {parts: ["Bearer ", !env SOME_KEY]}`. A credential cannot be committed to a declarative config by accident. |
| `406 Not Acceptable` on the MCP route, before any scan happens. | MEASURED: the MCP transport requires the Accept header. | Send `Accept: application/json, text/event-stream`. |
| Data plane container restart-loops with `failed reading the cluster certificate private key file: Permission denied` and nothing else in the log. | MEASURED: the AI Gateway container runs as uid/gid **1001**, not 1000 like the classic Kong image. A key mounted 600 owned by 1000 is unreadable. | `chown 1001:1001 cluster.key cluster.crt` on the host. |
| A route 404s and you cannot tell whether the data plane is behind or the control plane never compiled the config. | Ambiguous by default. | MEASURED diagnostic: compare the data plane's `/status` `configuration_hash` with the gateway's `config_version`. **Equal** means the data plane is current, so the 404 is a control plane compile problem, not a sync problem. Unequal means the data plane has not caught up. |
| The policy exists, is enabled, and nothing is ever scanned. | MEASURED: a policy defaults to `global: false` and then intercepts nothing. | Name the policy in the entity's `policies: []` (by **name**, not `ref`), or set `global: true`. |
| Attaching the guardrail to an MCP server fails with `400 ... policy "airs-scan" of type "ai-custom-guardrail" is not supported for scope "mcp-servers"`. | MEASURED and expected. No Kong guardrail policy is scoped to MCP. | Use the `request-callout` policy for MCP traffic, and understand its limits — [Gap 3](#gap-3--the-mcp-response-leg-is-unreachable-measured). |
| Config store apply rejected on `display_name`. | MEASURED: only letters, numbers, periods, hyphens, underscores and tildes are allowed. | Remove the spaces: `prisma-airs-credentials`. |
| Piping `kongctl plan` into `jq` fails to parse. | MEASURED: with deferred `!env` values present, plan prints a warning line **before** the JSON. | Strip the leading non-JSON line, or read the plan by eye. |
| AIRS answers `415` to the scan POST. | The request carries no content type. | `Content-Type: application/json` on the callout. Both shipped configs already set it; check any variant you wrote yourself. |
| Build fails saying a placeholder is needed and the variable is not set. | `scripts/build-config.py` resolves `!env` values for anything it bakes into Lua, because `!env` is resolved by kongctl at apply time — too late for inlined code. | `export PRISMA_AIRS_PROFILE_NAME=my-profile` and `export AIRS_MCP_SERVER_NAME=my-mcp` before building. |
| Every block logs `[ai-custom-guardrail] metric input_block_detail has unexpected type string, expected table`. | Known defect, unresolved. See [Defect](#defect--block-reason-metrics-are-dropped-measured). | Blocking is unaffected. Use SCM, correlated by `scan_id`, as the record of why. |

