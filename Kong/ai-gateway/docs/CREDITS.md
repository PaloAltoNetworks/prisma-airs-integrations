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
before the work in this repository began. Where this repository states one of
those findings as MEASURED, **the measurement is theirs unless this repository
says we repeated it**. The configuration, Lua and scripts here were written
against the AI Gateway 2.x policy schema and no file from that repository is
included in this one; the debt is factual, not textual, and it is a large one.

### Findings credited to that project

Each of the following was established there first, on 2026-09-08. They are the
reason this repository could be written as configuration at all, rather than
discovered one HTTP 500 at a time.

| # | Finding | Where it shows up here |
|---|---|---|
| 1 | `ai-custom-guardrail` function references are written **bare** — `$(airs_contents)` — and arguments are injected **by parameter name**. The explicit-argument call form, `$(airs_contents(source, content))`, returns HTTP 500 `failed to render by function: invalid expression syntax`, and no request reaches the model. | `config/llm/airs-guardrail.yaml`, the `request.body` block |
| 2 | Only four parameters can be injected into a guardrail function: `source`, `content`, `conf`, `resp`. Nothing else is reachable. The consequence is that the **calling consumer's identity and the model name are unavailable to the function**. | `lua/guardrail/airs_metadata.lua`; the `params` comment in the guardrail policy |
| 3 | `$(resp)` is a **Lua table in both phases**, not a string on the response leg. | `lua/guardrail/airs_verdict.lua`, which keeps a string branch only as a defensive path |
| 4 | A block from this policy is **HTTP 400** with a body of the form `{"error":{"message":...}}`. | Documented as the client contract; clients must not expect 403 |
| 5 | Under `text_source: concatenate_all_content` the scanned text is the message contents joined by `"\n\n"` in **reverse chronological order**, system prompt included. | The `text_source` comment in the guardrail policy, and the false-positive and token-cost warnings that follow from it |
| 6 | A guardrail function that **raises fails the request closed at HTTP 500**. | The whole design of `lua/guardrail/airs_contents.lua` depends on this |
| 7 | **The streaming bypass.** See below. | `response_streaming: deny` on the AI Model |
| 8 | **The tool-call extraction gap**, established as a matrix. See below. | Stated as a coverage gap rather than worked around |

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
             detail = "partial scan failure (fail-closed)" }
end
```

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
- SCM records `model_name: None` and `user_id: None` on every scan — the direct
  consequence of credited finding 2.
- **Defect, unresolved (MEASURED).** `metrics.block_reason` and
  `metrics.block_detail` wired to a string expression produce, on every block,
  `[ai-custom-guardrail] metric input_block_detail has unexpected type string, expected table`,
  and the metric is dropped at runtime. Blocking itself is unaffected; the
  operator-facing reason does not reach Kong telemetry. Kong's policy reference
  documents these fields as `type: string`, which contradicts the runtime, and the
  shape the runtime wants is not documented. Do not build a dashboard or an alert
  on these metrics: Strata Cloud Manager, correlated by `scan_id`, remains the
  complete record.
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
