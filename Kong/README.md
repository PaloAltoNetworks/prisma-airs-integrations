# Kong Integrations for Prisma AIRS

Integrate Kong Gateway with Palo Alto Networks Prisma AI Runtime Security (AIRS) to scan AI/LLM traffic for security threats.

## Available Integrations

| Integration | Prompt Scan | Response Scan | Pre/Post Tool | Multi-Provider | Best For |
|-------------|:-----------:|:-------------:|:-------------:|:--------------:|----------|
| [Custom Plugin (v1)](custom-plugin/) | ✅ | ✅ | ❌ | ✅ (via AI Gateway) | LLM-only traffic, full ai-proxy compatibility |
| [Custom Plugin (v2 — MCP-aware)](custom-plugin-v2/) | ✅ | ✅ | ✅ | ⚠️ (OpenAI + Bedrock Converse native) | LLM + MCP `tools/call` inspection |
| [Request Callout](request-callout/) | ✅ | ❌ | ❌ | ❌ | Kong Konnect SaaS, OpenAI only |

### Multi-Provider Support

The v1 custom plugin supports all LLM providers when used with [Kong AI Gateway](https://developer.konghq.com/ai-gateway/):

- OpenAI / Azure OpenAI
- Anthropic Claude
- Google Gemini / Vertex AI
- AWS Bedrock
- Mistral, Cohere, and more

Kong's AI Proxy plugin normalizes requests/responses to OpenAI format. See [custom-plugin README](custom-plugin/README.md#multi-provider-support-kong-ai-gateway) for setup.

> v2 runs at priority 1000 (above ai-proxy at 770) and parses OpenAI + Bedrock Converse request shapes directly. Use v1 if you need ai-proxy normalization to run first.

### MCP tool call inspection (v2 only)

v2 detects JSON-RPC 2.0 MCP requests and scans `tools/call` as AIRS `tool_event` payloads in both directions. MCP control messages (`initialize`, `tools/list`, etc.) are bypassed. See [custom-plugin-v2 README](custom-plugin-v2/README.md) for details.

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

- Kong Gateway 3.4+ or Kong Konnect account
- Prisma AIRS API key from Strata Cloud Manager
- Security Profile configured in Strata Cloud Manager

## Resources

- [Prisma AIRS Documentation](https://pan.dev/airs/)
- [Kong Gateway Documentation](https://docs.konghq.com/gateway/latest/)
- [Kong Plugin Hub - Prisma AIRS](https://developer.konghq.com/plugins/prisma-airs-intercept/)
