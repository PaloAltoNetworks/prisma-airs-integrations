# Prisma AIRS on Kong AI Gateway 2.x

Palo Alto Networks Prisma AIRS enforcement on Kong AI Gateway 2.x, expressed entirely as
configuration: no custom plugin, no rebuilt image, nothing installed on a data plane host. Two
AI Policies applied with `kongctl` — an `ai-custom-guardrail` policy scoped to AI Models, which
scans LLM prompts and responses, and a `request-callout` policy scoped to AI MCP Servers, which
scans MCP tool calls. Both carry Lua, but it lives in real `.lua` files under `lua/`, is
unit-tested offline, and is inlined into the applied YAML by `scripts/build-config.py`.

## Coverage

> For detection categories and use cases, see the
> [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | The `ai-custom-guardrail` policy scans the prompt before the AI Model route forwards it. A block is HTTP 400. |
| Response | ✅ | Scanned on the response leg under `guarding_mode: BOTH`; both legs genuinely run. Buffered replies only — see Streaming. |
| Streaming | ❌ | GAP 1. A streamed reply bypasses the response leg entirely. Close it with `response_streaming: deny` on the AI Model, which refuses streaming rather than scanning it. |
| Pre-tool call | ⚠️ | MCP only, and requests only. The `request-callout` policy scans `tools/call` arguments before the MCP server sees them. LLM `tool_calls[].function.arguments` are unreachable — GAP 2. |
| Post-tool call | ❌ | GAP 3. All three `request-callout` hooks run before the upstream call, so no tool result and no tool catalogue can be inspected. |
| Unclassifiable MCP body | ✅ | GAP 4, **closed by default**. A JSON-RPC batch, a non-JSON-RPC body or an undecodable body cannot be inspected, so it is refused rather than forwarded. `params.unclassified_action: allow` opts back into pass-through. |

**Legend:** ✅ Full support | ⚠️ Partial support | ❌ Not supported

Every ❌ and ⚠️ above is a measured platform limit with the evidence in
[Limitations](#limitations), not an omission. GAP 4 is the one entry that is a
choice rather than a limit, which is why it is the one that defaults closed.

## Why this exists

Kong's own hub ships guardrail integrations for AWS, Azure, GCP, Lakera and NVIDIA NeMo. There is
no Palo Alto Networks entry (DOCUMENTED). `ai-custom-guardrail` is Kong's documented generic hook
for exactly this case — "Integrate with any 3rd-party Guardrail service." This repository is that
hook filled in for Prisma AIRS, plus the separate mechanism MCP traffic needs, because a guardrail
policy cannot be attached to an MCP server at all.

## What works

MEASURED 2026-09-12 on a live gateway: Kong AI Gateway 2.0.3, Konnect control plane, self-managed data plane in Docker.

| Case | Result |
| --- | --- |
| Benign prompt through the AI Model route | HTTP 200, answer returned |
| Prompt injection on the request leg | HTTP 400, block body below |
| `guarding_mode: BOTH` | Both legs genuinely run — two separate transactions in Strata Cloud Manager, one Prompt, one Response |
| Correlation | The `scan_id` in the client's error matches the `scan_id` in SCM exactly |
| MCP `tools/call`, clean arguments | HTTP 200, allowed |
| MCP `tools/call`, injection in arguments | HTTP 403, JSON-RPC error below |
| AIRS refuses the scan — profile misconfigured, callout answered HTTP 400 | Every `tools/call` refused with `-32003`, upstream never reached |

The block a client sees on the LLM path:

```json
{"error":{"message":"Blocked by Prisma AIRS [scan_id=<uuid>]"}}
```

That is HTTP **400**, not 403 — `rejection_mode: none` behaviour on AI Gateway 2.x. The Kong
Gateway 3.x custom plugin returns 403 for the same event, so clients moving between the two must
expect a different status. The block an MCP client sees, at HTTP 403, with the caller's own
request id echoed back so the client surfaces a tool failure rather than a dead transport:

```json
{"jsonrpc":"2.0","error":{"message":"Blocked by Prisma AIRS [scan_id=<uuid>]","code":-32001},"id":<caller's id>}
```

Codes match the Kong Gateway 3.x plugin: `-32001` policy block, `-32003` scanner unavailable.
A callout that fails at the transport layer, or that returns 429, 500, 502, 503 or 504, is
refused earlier still by the callout's own `error` block — a bare HTTP 502 carrying
`Prisma AIRS scan unavailable`, not a JSON-RPC error. UNVERIFIED: that branch was not induced
here; see [docs/DESIGN.md](docs/DESIGN.md). The upstream is not reached either way, so an MCP
client has to handle both shapes.
On both paths the client is told only that Prisma AIRS blocked the call, never which detector
fired — the same text on a fail-closed block as on a real detection, because naming the
detector turns the block response into a probe for mapping the profile. The detail is in the
SCM scan log, reachable by `scan_id`.

## Limitations

Read this before deploying: three open coverage gaps and one closed by default.

### GAP 1 — streaming bypasses response scanning (MEASURED)

With `response_streaming: allow` on the AI Model, an identical payload is blocked when the
response is buffered and delivered when it is streamed:

| Request | Outcome |
| --- | --- |
| payload in message content, buffered | HTTP 400, blocked on the response leg |
| payload in message content, `stream: true` | HTTP 200, content delivered |

Any caller can opt itself out of response scanning by setting one flag in its own request
body. The remedy is `response_streaming: deny`, a field on the AI Model and not on the policy.
MEASURED 2026-09-12: with `deny`, a `stream: true` request is refused at the gateway before
any scan runs, with HTTP 400 and the body
`{"error":{"message":"response streaming is not enabled for this LLM"}}`, while buffered
traffic is unaffected. **The bypass is closed by refusing streaming, not by scanning it.**

What was measured is narrow: with `response_streaming: allow` the response leg does not run on a
streamed reply, and with `deny` the request is refused before any scan. UNVERIFIED: the policy
schema hints at a streaming block path that was not exercised here — the `rejection_mode`
description mentions that "In streaming mode, the final SSE chunk includes
`finish_reason='blocked_by_guard'`", and `allow_masking` states "Streaming will be disabled if
this is enabled".

### GAP 2 — tool-call arguments are invisible on the LLM path (MEASURED)

A buffered reply with `content: null` and the payload only inside
`tool_calls[].function.arguments` is allowed. Kong's text extraction does not include tool-call
arguments, so AIRS never receives them, under any value of `text_source`; tool definitions
(`tools[].function.description`) are likewise not message content. **This is not fixable in
configuration** — the Kong Gateway 3.x custom plugin can read `tool_calls` directly, this
config-only policy cannot.

### GAP 3 — the MCP response leg cannot be inspected (MEASURED)

`request-callout` declares exactly three Lua hooks — `callouts[].request.by_lua`,
`callouts[].response.by_lua` and `config.upstream.by_lua` — and all three run before the upstream
request is made. `callouts[].response.by_lua` sees the reply from AIRS, not the reply from the MCP
server. There is no response-phase hook, so:

| MCP message | Outcome |
| --- | --- |
| Payload in a tool RESULT | HTTP 200, delivered |
| `tools/list` | HTTP 200, bypassed unscanned on the request leg; the returned catalogue is not inspected either |
| `initialize` | HTTP 200, bypassed unscanned |

**Tool poisoning is not detected by this policy** — neither a malicious tool description in a
`tools/list` reply nor an injection inside a tool result. State it this way round: AIRS itself
detects both today. Sending a poisoned tool result or a poisoned catalogue to the AIRS scan
API returns `action: block`, `category: malicious`, with the tool named in the detection
record (MEASURED 2026-09-12). The gap is Kong's — the policy has no hook that can hand them
over. For MCP response-side enforcement today, use the PANW Lua plugin on a classic Kong
Gateway control plane.

`ai-custom-guardrail` cannot be used for MCP at all. The Konnect control plane refuses the
attachment with HTTP 400 (MEASURED 2026-09-12):

```text
policies: policy "<name>" of type "ai-custom-guardrail" is not supported for scope "mcp-servers"
```

That confirms from the API what Kong documents in the `ai-mcp-proxy` support table
("AI Guardrails ... Not supported").

### GAP 4 — an unclassifiable MCP body (CLOSED BY DEFAULT)

The callout classifies the request body before scanning it, and three shapes refuse
classification: a JSON-RPC batch (a top-level array), a body without `jsonrpc: "2.0"` and a
string `method`, and a body that does not decode to a JSON object at all. A batch is refused
deliberately — inspecting element one and waving the rest through is an evasion primitive.

A `tools/call` can be sitting inside any of the three, and none of them was inspected, so
**`upstream.by_lua` refuses them on the same path as a classification failure**: HTTP 403,
JSON-RPC `-32001`, the upstream never reached. A security control should not default open on an
unscanned tool call.

Deliberate bypasses are not caught by this. `ping`, `notifications/*`, `initialize` and
`tools/list` carry no caller content on the request leg, so there is nothing to refuse and they
still pass.

Pass-through is available as an opt-in, because Kong's behaviour on receiving a batch at an MCP
route is UNVERIFIED and a legitimate client may yet trip this:

```yaml
params:
  unclassified_action: "allow"   # default is "refuse"
```

The test is an exact match on `allow`, so an empty value, a typo or an unsubstituted placeholder
all refuse — the safe answer is both the default and the accident. Choosing `allow` is a
transport-compatibility decision, not a security one, and it reopens this gap. Covered by 21
assertions in `spec/mcp_callout_spec.lua`, including that a misspelled opt-out still refuses. See
[docs/DESIGN.md](docs/DESIGN.md) section 4.3.

### Other measured notes

- **The block-metrics defect from an earlier revision is fixed.** `metrics.block_reason` and
  `metrics.block_detail` wired to a *string* expression were dropped at runtime on every request
  — `[ai-custom-guardrail] metric input_block_detail has unexpected type string, expected table` —
  contradicting Kong's own policy reference, which types `block_detail` as a string. MEASURED
  (2026-09-14): the runtime wants a Lua **table**. `lua/guardrail/airs_verdict.lua`'s `detail` is
  now `{ reason, category, detections }` on every path, including allow (an empty table), and the
  warning is gone: a `file-log` policy on the same model shows
  `ai.proxy.custom-guardrail.input_block_detail` populated. The client-facing `block_message`
  contract is unchanged — the category and detector names go only into `detail` and the SCM scan
  log, never to the caller.
- SCM shows `model_name: None` and `user_id: None` on every LLM scan. A guardrail function
  can be handed only `source`, `content`, `conf` and `resp`; the calling consumer and the
  model name are unreachable from that phase. See [docs/DESIGN.md](docs/DESIGN.md).
- Delimiter-dense machine syntax in a prompt can itself trip the AIRS prompt-injection
  detector. `do it @@toolcall@@` returns 200 and `do it @@canned:p0@@` returns 200, but the two
  concatenated return 400. Steering tokens in test prompts can silently turn a response-leg
  test into a request-leg test; the lab fixtures use plain uppercase words for this reason.
- The MCP route requires `Accept: application/json, text/event-stream`. Without it the MCP
  proxy answers 406 Not Acceptable.

## Requirements

- A Kong **AI Gateway 2.x** control plane in Konnect. AI Gateways are a separate resource from
  classic control planes; they live at `/v1/ai-gateways` in the Konnect API.
- A **self-managed data plane**, the only type that ships today; "Serverless" and "Dedicated
  Cloud" both show "Coming soon". Runtime options are Docker, Linux binary and Kubernetes.
  Verified on `kong/kong-ai-gateway:2.0.3` (multi-arch, amd64 and arm64).
- **kongctl** (verified with 1.15.1) and a Konnect personal access token.
- A **Prisma AIRS API Intercept** application with a named security profile and an API key.
- For the offline tests only: **LuaJIT** (or `lua5.1`) with **`lua-cjson`** built against it —
  `luarocks --lua-version=5.1 install lua-cjson`. Nothing else here needs a local Lua toolchain.
- For `scripts/build-config.py` and `scripts/check-policy-schema.py`: **Python 3.9+** with
  **PyYAML**. The schema check also fetches Kong's published policy schema over the network;
  pass `--offline` to skip that.

## Quick start

The full version — data plane build, the two choices for where the API key rests, the console
route and the verification gates — is in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

```bash
export AI_GATEWAY_ID="YOUR_AI_GATEWAY_ID"             # your AI Gateway instance id
export KONNECT_PAT="YOUR_KONNECT_PAT"                 # Konnect personal access token
export PRISMA_AIRS_API_KEY="YOUR_AIRS_API_KEY"        # Prisma AIRS API key
export PRISMA_AIRS_PROFILE_NAME="YOUR_PROFILE_NAME"   # your AIRS security profile name
export AIRS_MCP_SERVER_NAME="YOUR_MCP_SERVER_NAME"    # name reported to AIRS for MCP scans

# 1. Build. Inlines lua/ into config/ and writes dist/. dist/ is not committed.
scripts/build-config.py
# 2. Store the key and create the vault that resolves {vault://airs/prisma-airs-api-key}.
kongctl apply -f dist/lab/airs-secret.yaml --pat "$KONNECT_PAT"
# 3. Apply the policies.
kongctl apply -f dist/llm/airs-guardrail.yaml --pat "$KONNECT_PAT"
kongctl apply -f dist/mcp/airs-mcp-request-scan.yaml --pat "$KONNECT_PAT"
```

Both values are secrets. Take them from wherever you already keep credentials — a password
manager, a secrets store, or a file only you can read — rather than pasting them into a shell
that records history.

Nothing is intercepted yet. A policy defaults to `global: false` and then covers nothing. Bind
it by naming the policy in the AI Model's or AI MCP Server's `policies:` list — and set
`response_streaming: deny` at the same time, or GAP 1 is open.

A complete AI Model definition — the union selector, the provider, `targets`, `formats` and the
`ai_gateway: !lookup { id: !env AI_GATEWAY_ID }` every applied file needs — is in
[config/lab/lab-model.yaml](config/lab/lab-model.yaml). It names the policy in `policies:` and
deliberately leaves `response_streaming: allow`, so that the streaming bypass can be reproduced;
set `deny` outside the lab. Apply it the same way as the policies:

```bash
export LAB_UPSTREAM_KEY="YOUR_UPSTREAM_API_KEY"   # the lab model's own upstream credential
kongctl apply -f dist/lab/lab-model.yaml --pat "$KONNECT_PAT"
```

`LAB_UPSTREAM_KEY` is the credential the lab AI Model presents to its own upstream. kongctl
refuses an inline credential, so it has to arrive as a deferred `!secret` from the environment.
Against `scripts/lab-echo-server.py`, which ignores authentication, any non-empty value does.

The configuration ships the US scan endpoint,
`https://service.api.aisecurity.paloaltonetworks.com/v1/scan/sync/request`. Other regions use a
different hostname — the repository's own [CONTRIBUTING.md](../../CONTRIBUTING.md) lists them
under Regional Endpoints, and `PRISMA_AIRS_URL` is the standard variable that carries one. Edit
the `url` in the policy to the endpoint your AIRS onboarding gives you; the path
`/v1/scan/sync/request` is the same in every region.

## Repository layout

| Path | Contents |
| --- | --- |
| `config/llm/`, `config/mcp/` | The two policies: `ai-custom-guardrail` for LLM traffic and `request-callout` for MCP traffic, both heavily commented. |
| `config/lab/` | Fixtures, not part of the integration: an AI Model over the echo upstream, an AI MCP Server over the lab MCP server, and the config store plus vault that hold the AIRS key. |
| `lua/guardrail/` | The four guardrail functions: `airs_profile`, `airs_metadata`, `airs_contents`, `airs_verdict`. |
| `lua/callout/` | The three `request-callout` hooks: `request_by_lua`, `response_by_lua`, `upstream_by_lua`. |
| `scripts/` | `build-config.py` (inline Lua into config, emit `dist/`), `check-policy-schema.py`, `kongctl_yaml.py`, `test-airs.sh` (live traffic through a gateway), the two lab servers, `run-lua-tests.sh`. |
| `spec/` | Offline Lua assertions — 52 in `verdict_spec.lua`, 66 in `mcp_callout_spec.lua`. |
| `dist/` | **Generated, and deliberately not committed.** The build inlines the Lua and, for the MCP callout, also the AIRS profile name and MCP server name, which are tenant-specific. Build before applying, then validate the result with `scripts/check-policy-schema.py`. |

## Checking it works

```bash
# Offline: needs no gateway, no Konnect and no AIRS credential.
bash scripts/run-lua-tests.sh          # 118 assertions over the verdict and callout logic

# The build bakes these two into the Lua, so it needs them set even offline.
# They are names, not secrets — any placeholder builds a config you can validate.
export PRISMA_AIRS_PROFILE_NAME=my-profile
export AIRS_MCP_SERVER_NAME=my-mcp
python3 scripts/build-config.py        # inline the Lua, emit dist/ (--check fails if stale)
python3 scripts/check-policy-schema.py # validate dist/ against the published 2.x POLICY schema

# Live, against a running gateway.
GATEWAY_URL=https://<data-plane-host> MODEL=my-model bash scripts/test-airs.sh
```

`test-airs.sh` sends six requests and reports what the policy did with each; its header comment
explains the two safeguards. A line reported as `GAP` is a
documented limitation reproducing, not a regression. Keep case 3 when you adapt the script: a
legitimate security question from an analyst, which must be allowed, catches an over-aggressive
profile.

Edit the `.lua` files, never the function bodies inside a built config: Lua inside a YAML
string is Lua nobody lints or tests.

## Credits

Findings this work relies on that were established elsewhere are attributed in
[docs/CREDITS.md](docs/CREDITS.md).
