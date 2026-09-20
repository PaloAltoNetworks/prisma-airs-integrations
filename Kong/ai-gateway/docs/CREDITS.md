# Credits

This integration is not the first attempt to put Prisma AIRS in front of Kong. A
substantial part of what this repository treats as known behaviour was
established by someone else, earlier, and is used here. This file says exactly
which parts, so that a reader can tell our measurements from theirs and can go
back to the original work.

## Prior art

**Project:** https://github.com/tbortolossi/prisma-airs-kong-ai-gateway
**Author:** Thomas Bortolossi
**Licence:** MIT

That project independently established a set of findings on **2026-09-08**,
before the work in this repository began, and a second set on **2026-09-14 and
2026-09-15** which arrived after it and corrected one of the first. Where this
repository states one of those findings as MEASURED, **the measurement is theirs
unless this repository says we repeated it**. The configuration, Lua and scripts here were written
against the AI Gateway 2.x policy schema and no file from that repository is
included in this one; the debt is factual, not textual, and it is a large one.

### Findings credited to that project

Findings 1 to 8 were established there first on **2026-09-08**. They are the
reason this repository could be written as configuration at all, rather than
discovered one HTTP 500 at a time. Findings 9 to 12 came later, on
**2026-09-14**, on Kong AI Gateway 2.0.3 / Kong Gateway 3.14.0.3 against a live
Prisma AIRS tenant; they are what the guardrail functions here were rewritten
around.

| # | Finding | Where it shows up here |
|---|---|---|
| 1 | `ai-custom-guardrail` function references are written **bare** — `$(airs_contents)` — and arguments are injected **by parameter name**. The explicit-argument call form, `$(airs_contents(source, content))`, returns HTTP 500 `failed to render by function: invalid expression syntax`, and no request reaches the model. | `config/llm/airs-guardrail.yaml`, the `request.body` block |
| 2 | Only four parameters can be injected into a guardrail function: `source`, `content`, `conf`, `resp`. Nothing else is accepted as an argument. | `lua/guardrail/airs_metadata.lua`, `lua/guardrail/airs_correlation.lua`. **The half of this finding about what a function can REACH has been superseded — see [below](#one-credited-finding-partly-superseded).** The half about argument injection stands and is still relied on |
| 3 | `$(resp)` is a **Lua table in both phases**, not a string on the response leg. | `lua/guardrail/airs_verdict.lua`, which keeps a string branch only as a defensive path |
| 4 | A block from this policy is **HTTP 400** with a body of the form `{"error":{"message":...}}`. | Documented as the client contract; clients must not expect 403 |
| 5 | Under `text_source: concatenate_all_content` the scanned text is the message contents joined by `"\n\n"` in **reverse chronological order**, system prompt included. | The `text_source` comment in the guardrail policy, and the false-positive and token-cost warnings that follow from it |
| 6 | A guardrail function that **raises fails the request closed at HTTP 500**. | The whole design of `lua/guardrail/airs_contents.lua` depends on this |
| 7 | **The streaming bypass.** See below. | `response_streaming: deny` on the AI Model |
| 8 | **The tool-call extraction gap**, established as a matrix. See below. | Stated as a coverage gap; narrowed, not closed, by `params.tool_scan` |
| 9 | **A guardrail function body reaches the Kong PDK**, and every call in one must be `pcall`-wrapped or it is a silent fail-open on streamed responses. This supersedes half of finding 2. See [below](#one-credited-finding-partly-superseded). | All four guardrail functions |
| 10 | **Unattributed conversation text is read as prompt injection.** `text_source` joins message content with no roles, and an ordinary multi-turn chat is blocked 3/3 as agent + injection. Prefixing `user:` and `assistant:` clears it without weakening detection; prefixing `system:` blocks it again, because that is the shape of a system-prompt spoof. | `lua/guardrail/airs_contents.lua` rebuilds and attributes the scanned text |
| 11 | **Prisma AIRS judges only the LAST element of `contents[]`.** Earlier elements are context and are not scanned, so a conversation split one-element-per-message stops scanning every turn but the newest. | `airs_contents` returns exactly one element, and `spec/verdict_spec.lua` fails if it ever returns more |
| 12 | **The AIRS correlation identifiers**, settled by nine probes against a live tenant because no published page settles it: `transaction_id` is the round, `session_id` is the conversation, and `tr_id` is the legacy name of `session_id` — not of `transaction_id`. A `request.body` field that is `nil` is omitted; one that is `""` is sent as JSON `false`. | `lua/guardrail/airs_correlation.lua`, and the `request.body` comment in the guardrail policy |

### One credited finding, partly superseded

Credited finding 2 has two halves, and only one of them survived.

**What stands.** Kong injects built-ins into a guardrail function *by parameter
name*, and the accepted names are exactly `source`, `content`, `conf` and
`resp`. Anything else is rejected outright with `argument '<name>' is not
allowed in guardrail functions`. That is true, it is still relied on throughout
this repository, and finding 1 depends on it.

**What does not.** The conclusion drawn from it — that the calling consumer's
identity and the model name are therefore unreachable — is wrong, and the error
is worth naming precisely because it is an easy one to make and neither project
caught it for four days. **The allowlist was enumerated by probing parameter
names and reading the rejection message. That measures what Kong hands the
function as an ARGUMENT. It says nothing about the sandbox the function BODY
runs in, which was never tested.** A negative established on one mechanism was
carried over to a different one.

MEASURED by the prior-art project on **2026-09-14**, against Kong AI Gateway
2.0.3 (Kong Gateway 3.14.0.3), later than the 2026-09-12 runtime the rest of
this file reports on. Inside a guardrail function body, `kong` and `ngx` are
tables and `require` is a function:

| Call | Result |
| --- | --- |
| `kong.request.get_header(name)` | the client's header, same value on both legs |
| `kong.request.get_body()` | the **structured `messages[]`**, in BOTH phases, chronological, roles intact. Also carries `tools[]` and `tool_calls`, which `$(content)` never exposes |
| `ngx.ctx.ai_model` | the AI Model entity — `id`, `name` |
| `kong.client.get_ip()` / `get_forwarded_ip()` | the caller's address |
| `kong.client.get_consumer()` / `get_credential()` | the authenticated consumer. Reachable; returned `nil` in a lab with no auth on the model, so the API is proved and a populated consumer is not |
| `ngx.var.request_id` | Kong's own request id |
| `kong.ctx.shared` | **persists from the INPUT leg to the OUTPUT leg of the same buffered request** |
| `kong.router.*` | `nil` — not reachable |
| `kong.log.serialize()` | refuses: "function cannot be called in access phase" |

**And one hard constraint that comes with it, measured the same day.** Every PDK
call in a guardrail function must be wrapped in `pcall`. On the OUTPUT leg of a
**streamed** response the function runs with no request context, and an
unguarded raise there does **not** fail the request the way a raise on a
buffered leg does (credited finding 6): it silently skips the guardrail call for
that segment. A/B on one streamed request, same policy: a function returning a
constant produced **7** segment scans; the same function calling
`kong.request.get_header` unguarded produced **0**, with HTTP 200 and the whole
stream delivered and nothing in the client's view to suggest the response was
never scanned; the same calls wrapped in `pcall` produced **7** again. *An
unguarded PDK call in a guardrail function is a silent fail-OPEN.* Every
function under `lua/guardrail/` is written to that rule and
`spec/verdict_spec.lua` asserts it: remove a `pcall` and the "no request
context" cases stop passing.

Two further facts from the same runs, both of which shape the code here.
`request.body` fields behave asymmetrically: a field that is `nil` is omitted
from the scan payload, while a field that is an **empty string is rendered as
JSON `false`**, so an identifier that cannot be built must be absent rather than
blank. And Prisma AIRS **judges only the LAST element of `contents[]`** — an
injection sent as the first of two, or the first of three, comes back
`allow`/`benign`, while the same injection sent last, or alone, blocks. Earlier
elements are context and are not scanned.

**The correction belongs to the prior art as much as the original finding did.**
It was their measurement, on their runtime, and they published the method error
against their own earlier conclusion. This repository inherited the conclusion
rather than discovering it, and it is corrected here on the same terms it was
credited on.

### Two findings where the method is the contribution

These two are singled out because knowing *that* they are true is worth less
than knowing *how* they were shown. Both methods are theirs.

**The streaming bypass.** The test was not to stare at chunk handling. It was to
point the OUTPUT policy at a guardrail service that **blocks everything**, send a
streamed request, and observe that the guardrail service **received no call at
all**. That converts an ambiguous negative — "the stream was not blocked" — into
an unambiguous one: the response phase never ran. There is no error, no warning
and no log line to notice; the absence of the call is the entire signal. The
practical consequence is that any caller can opt itself out of response scanning
by setting `stream: true` in its own request body, which is why this repository
sets `response_streaming: deny` on the AI Model rather than trusting the policy
alone.

MEASURED here (2026-09-12, AI Gateway 2.0.3): we reproduced the effect on our own
runtime — an identical payload is blocked with HTTP 400 when buffered and
delivered with HTTP 200 when streamed. The remedy was measured here: `response_streaming: deny` on the AI Model refuses a `stream: true` request with HTTP 400 before any scan runs (2026-09-12). The hole is theirs; the remedy is measured here.

**Correction, MEASURED (2026-09-14, AI Gateway 2.0.3).** "The guardrail service
received no call at all" does not generalise the way we generalised it. It was
true of the config we ran on 2026-09-08 and 2026-09-12, and that config is what
caused it: `response_buffer_size: 65536` in `config/llm/airs-guardrail.yaml`
kept the streamed answer below the threshold at which the OUTPUT phase ever
fires, so nothing was ever scanned and it looked identical to a total bypass.
Pointed at a guardrail service that counted every call it received, with the
buffer at other values: the OUTPUT phase runs on a stream, once per
`response_buffer_size` segment (schema default 100 bytes) — a 309-character
answer produced 3 calls of 101/104/103 characters; at 2048, zero calls, same
mechanism as our own 65536. So the prior art's method (point a blocking
guardrail at the stream, count calls) was exactly right and is still the right
method; the number this repository fed it as the buffer was the confound. See
GAP 1 in `README.md` for the corrected coverage claim: partial, per-segment,
best-effort, with a floor, a tail and a delay, not zero.

**The tool-call extraction gap.** The method was a **matrix: five message
positions by three `text_source` values**, each cell tested rather than reasoned
about. That is what makes the negative result trustworthy — it distinguishes "we
did not find it" from "it is not there", and it also produced the positive half
of the result, namely that a `role: "tool"` **result** *is* scanned under
`concatenate_all_content`. This repository selects `concatenate_all_content` for
that reason, and states the gap plainly instead of implying coverage: assistant
`tool_calls[].function.arguments` and `tools[].function.description` are not
message content and never enter `$(content)` under any value of the setting.

MEASURED here (2026-09-12, AI Gateway 2.0.3): a buffered reply with
`content: null` whose payload lives only in `tool_calls[].function.arguments` is
allowed. This is not fixable in configuration. The Kong 3.x custom plugin can
read `tool_calls` directly; a config-only policy cannot.

## What differs in this repository

These are differences and additions, not corrections. Some of them exist only
because the platform is different: several are impossible on the Kong Gateway 3.x
plugin contract that the prior art targets.

**Validated against the AI Gateway 2.x policy schema, not the Kong 3.x plugin
schema.** Kong publishes two different references for `ai-custom-guardrail` — one
under `developer.konghq.com/plugins/` and one under
`developer.konghq.com/ai-gateway/policies/` — and they are not the same contract.
DOCUMENTED: the policy schema carries four config keys the plugin schema does not
(`rejection_mode`, `continue_on_detection`, `log_blocked_content`,
`proxy_config`), and those four are what give a 2.x deployment a controlled block
contract and an observe-only rollout. `scripts/check-policy-schema.py` validates
built config against the policy schema: it fails on any config key the policy schema
does not carry, and it then reports, for information, the keys that exist in the
policy schema and not in the plugin schema, together with which of those this config
uses. That second list is how you tell config written against the 2.x policy
contract from config ported off the 3.x plugin without re-reading it.

**AIRS partial-scan failure is treated as a block.** The AIRS `ScanResponse`
carries `error` and `timeout` as first-class fields on a 200 body, plus an
`errors[]` array naming which detector degraded. A detector can fail or time out
while the overall verdict still returns `action: "allow"` — the scan did not say
the content is safe, it said it could not finish looking. `lua/guardrail/airs_verdict.lua`
fails closed on any of those, in addition to the classic `category` check:

```lua
local function is_set(v) return v ~= nil and v ~= false end

if is_set(resp.error) or is_set(resp.timeout) then
    return { block = true, block_message = msg,
             detail = { reason = "partial scan failure (fail-closed)",
                        category = resp.category } }
end
```

(`detail` is a table, `{ reason, category, detections }`, on every path this function returns — see
"Measurements made in this repository" below for why a string there is not an option.)

The same function deliberately does **not** block on `category` alone on the
allow path: an AIRS profile in alert-only mode returns `allow` together with a
`malicious` category, and that combination is the profile owner exercising a
choice.

**An empty extraction raises.** `lua/guardrail/airs_contents.lua` refuses to
build a scan payload when the extracted text is empty or is not a string. AIRS
returns `allow` on an empty string, so without this the gateway records a
successful inspection of nothing, which is how a content-extraction gap becomes a
silent pass. This depends directly on credited finding 6: raising fails the
request closed at HTTP 500.

**An MCP path.** `ai-custom-guardrail` cannot be attached to an MCP server.
MEASURED (2026-09-12, AI Gateway 2.0.3): the Konnect control plane refuses with
HTTP 400, `policy "<name>" of type "ai-custom-guardrail" is not supported for
scope "mcp-servers"` — the API itself confirming the gap Kong documents in the
`ai-mcp-proxy` support table. `request-callout` is accepted at that scope, and
`config/mcp/airs-mcp-request-scan.yaml` uses it to scan `tools/call` arguments
before the upstream is reached, returning an in-protocol JSON-RPC error rather
than a bare HTTP status. Be clear about its limit: all three of
`request-callout`'s Lua hooks run before the upstream request, so the **MCP
response leg cannot be inspected** — tool results and the tool catalogue are
outside this control. AIRS itself can detect poisoned tool results and poisoned
catalogues today; the limitation is Kong's, not the scanner's, and it should be
stated that way round.

## Measurements made in this repository

For symmetry, the findings below are ours, measured on 2026-09-12 against AI
Gateway 2.0.3 unless marked otherwise. They are not attributable to the prior
art.

- `guarding_mode: BOTH` genuinely runs both legs, visible in Strata Cloud Manager
  as two separate transactions, one Prompt and one Response.
- The `scan_id` in the client's error message matches the `scan_id` in SCM
  exactly, so an operator can go from a user complaint to the detection record.
- SCM recorded `model_name: None` and `user_id: None` on every scan. That was
  read as the direct consequence of credited finding 2; it was the consequence
  of `airs_metadata` reading static policy config, which it did because of the
  superseded half of that finding. Both fields now carry real values, and the
  prior-art project confirmed the rendering in the Strata Cloud Manager
  Transaction Metadata panel on 2026-09-15 — `model_name`, `user_id`, `user_ip`,
  `profile`, `environment` — which the scan results API cannot show, because it
  never echoes metadata back.
- **Fixed, MEASURED (2026-09-14, AI Gateway 2.0.3), was an unresolved defect.**
  `metrics.block_reason` and `metrics.block_detail` wired to a **string**
  expression produce, on every request — allowed or blocked —
  `[ai-custom-guardrail] metric input_block_detail has unexpected type string, expected table`,
  and the metric is dropped at runtime. Blocking itself is unaffected; the
  operator-facing reason did not reach Kong telemetry. Kong's policy reference
  documents these fields as `type: string`, which contradicts the runtime — the
  runtime wants a Lua **table**. With `airs_verdict`'s `detail` changed to
  `{ reason, category, detections }` on every path, including allow (an empty
  table), the warning disappears and the metric is exported: a `file-log`
  policy on the same model shows `ai.proxy.custom-guardrail.input_block_detail`
  populated with the table. `block_reason` was never affected — a string is
  correct there and stays a string. Strata Cloud Manager, correlated by
  `scan_id`, remains the fuller record (threats, the scanned text), but Kong
  telemetry now carries a reason code too.
- The AIRS scan API's tool-event contract: `tool_event` is a member of a
  `contents[]` element, not a top-level sibling of `contents`; `input` and
  `output` are strings containing JSON; `tool_invoked` is accepted and echoed
  back in the detection record.
- AIRS false positives on delimiter-dense machine syntax: neither `@@toolcall@@`
  nor `@@canned:p0@@` alone is blocked, while the two concatenated are. The lab
  fixtures use plain uppercase words for this reason.
- The fail-closed design holds in practice: with the callout to AIRS failing,
  every `tools/call` was refused with `-32003` and the upstream was never
  reached.

## Documentation as a source

Claims tagged DOCUMENTED in this repository come from vendor documentation, not
from our runtime. Two bodies of it carry most of the weight.

**Kong.** `developer.konghq.com` is the source for the `ai-custom-guardrail` and
`request-callout` policy references — field names, enums, defaults, scopes and
minimum versions — and for the entity model that AI Gateway 2.x replaced plugins
with. Three Kong statements are load-bearing here and are quoted in the configs
rather than paraphrased: that `ai-custom-guardrail` exists to "Integrate with any
3rd-party Guardrail service"; that in the `ai-mcp-proxy` scope-of-support table
AI Guardrails on MCP requests and responses are "Not supported"; and that AI
Policies which trigger in the response phase cannot be combined with streaming.
Kong's own changelog is the source for the framing used throughout — policies are
a control plane concept, implemented in the runtime as plugins.

Kong's documentation is also the source of the one place where documentation and
runtime disagree, recorded above: the policy reference types the `metrics` fields
as strings and the runtime rejects strings.

Kong's guardrail hub ships integrations for AWS, Azure, GCP, Lakera and NVIDIA
NeMo. There is no Palo Alto Networks entry, which is why this integration is
built on the generic hook.

**Palo Alto Networks.** PANW documentation and the Prisma AIRS API Intercept
reference are the source for the scan API contract — the `ai_profile`,
`metadata` and `contents` envelope, the sync scan endpoint, the regional service
hostnames, and the `ScanResponse` fields this integration enforces on. Strata
Cloud Manager is where the detection record lives and is the surface an operator
uses to resolve a block, correlated by `scan_id`.

Where vendor documentation and our runtime disagree, this repository records both
and marks which is which. Where neither settles a question, the claim is tagged
UNVERIFIED and left in `docs/DESIGN.md` rather than being asserted.
