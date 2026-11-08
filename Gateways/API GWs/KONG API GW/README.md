# Kong Integrations for Prisma AIRS

Integrate Kong Gateway with Palo Alto Networks Prisma AI Runtime Security (AIRS) to scan AI/LLM traffic for security threats.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

## Available Integrations

| Integration | Prompt Scan | Response Scan | Pre/Post Tool | Multi-Provider | Best For |
|-------------|:-----------:|:-------------:|:-------------:|:--------------:|----------|
| [Custom Plugin (v1)](custom-plugin/) | ✅ | ✅ | ❌ | ✅ (via AI Gateway) | LLM-only traffic, full ai-proxy compatibility |
| [Custom Plugin (v2 — MCP-aware)](custom-plugin-v2/) | ✅ | ✅ | ✅ | ⚠️ (OpenAI + Bedrock Converse native) | LLM + MCP `tools/call` inspection |
| [Request Callout](request-callout/) | ✅ | ❌ | ❌ | ❌ | Kong Konnect SaaS, OpenAI only |
| [Custom Plugin (v3)](custom-plugin-v3/) | ✅ | ✅ | ✅ | ✅ (native, 9 shapes) | Full MCP method coverage, buffered SSE, DLP, and a test suite |
| [AI Gateway 2.x Policies](ai-gateway/) | ✅ | ✅ (buffered) | ⚠️ (MCP `tools/call`, request leg) | ✅ (any AI Model) | Kong **AI Gateway 2.x**, configuration only — no plugin to install |

### Which Kong product each one targets

The first four rows are for **Kong Gateway 3.x** (including Konnect-managed 3.x control planes):
you create Services, Routes and Plugins. The last row is for **Kong AI Gateway 2.x**, which Kong
shipped in September 2026 as a separate runtime with its own control plane and its own entity
model — AI Models, AI MCP Servers and AI Policies, with no Services or Routes to attach a plugin
to. The two config formats are not interchangeable in either direction, so pick the row that
matches the product you run. Note that AI Gateway 2.x is a different thing from the *AI Gateway
capability* of Kong Gateway 3.x referred to under Multi-Provider Support below.

### Multi-Provider Support

The v1 custom plugin supports all LLM providers when used with [Kong AI Gateway](https://developer.konghq.com/ai-gateway/):

- OpenAI / Azure OpenAI
- Anthropic Claude
- Google Gemini / Vertex AI
- AWS Bedrock
- Mistral, Cohere, and more

Kong's AI Proxy plugin normalizes requests/responses to OpenAI format. See [custom-plugin README](custom-plugin/README.md#multi-provider-support-kong-ai-gateway) for setup.

> v2 runs at priority 1000 (above ai-proxy at 770) and parses OpenAI + Bedrock Converse request shapes directly. Use v1 if you need ai-proxy normalization to run first.

### MCP tool call inspection (v2 and v3)

v2 detects JSON-RPC 2.0 MCP requests and scans `tools/call` as AIRS `tool_event` payloads in both directions. MCP control messages (`initialize`, `tools/list`, etc.) are bypassed. See [custom-plugin-v2 README](custom-plugin-v2/README.md) for details.

v3 extends this to the rest of the MCP surface. Every method carrying caller-chosen or
server-supplied text is scanned on both legs — `resources/read`, `prompts/get`,
`completion/complete`, `sampling/createMessage`, `elicitation/create` and vendor extensions —
and denials are returned in-protocol as JSON-RPC errors carrying the caller's own request id,
so a client session survives a block. Tool *catalogues* are scanned on the way back, which is
the tool-poisoning surface: a malicious tool description in a `tools/list` reply, or poisoned
`instructions` in an `initialize` reply, is refused before it reaches the model. Only genuinely
content-free control messages (`ping`, `notifications/*`) are bypassed. See
[custom-plugin-v3 README](custom-plugin-v3/README.md#mcp-method-coverage) for the measured matrix.

On **AI Gateway 2.x** the reachable surface is narrower and the limit is the platform's, not
AIRS's: no Kong guardrail can be scoped to an AI MCP Server at all, so scanning is done with a
`request-callout` policy, and every hook that policy offers runs before the upstream call. MCP
requests are therefore scanned and MCP *responses* are not, which leaves tool-catalogue poisoning
out of reach there. See [ai-gateway README](ai-gateway/README.md#limitations) for the measured
evidence, including the control plane's own refusal to bind a guardrail at that scope.

## Quick Start

**Custom Plugin** - Full dual-phase scanning:
```bash
# Deploy plugin files to Kong, then enable
curl -X POST http://localhost:8001/services/{service}/plugins \
  --data "name=prisma-airs-intercept" \
  --data "config.api_key=YOUR_API_KEY" \
  --data "config.profile_name=YOUR_PROFILE_NAME"
```

**Request Callout** - Configuration-only approach:
```bash
# Apply request-callout plugin with AIRS configuration
# See request-callout/README.md for full config
```

## Prerequisites

- Kong Gateway 3.4+ or Kong Konnect account — or Kong AI Gateway 2.x for the `ai-gateway/` integration
- Prisma AIRS API key from Strata Cloud Manager
- Security Profile configured in Strata Cloud Manager

## Resources

- [Prisma AIRS Documentation](https://pan.dev/airs/)
- [Kong Gateway Documentation](https://docs.konghq.com/gateway/latest/)
- [Kong Plugin Hub - Prisma AIRS](https://developer.konghq.com/plugins/prisma-airs-intercept/)
