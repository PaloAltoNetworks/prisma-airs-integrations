# Kong Integrations for Prisma AIRS

Integrate Kong Gateway with Palo Alto Networks Prisma AI Runtime Security (AIRS) to scan AI/LLM traffic for security threats.

## Available Integrations

| Integration | Prompt Scan | Response Scan | Multi-Provider | Best For |
|-------------|:-----------:|:-------------:|:--------------:|----------|
| [Custom Plugin](custom-plugin/) | ✅ | ✅ | ✅ (via AI Gateway) | Full coverage, any provider |
| [Request Callout](request-callout/) | ✅ | ❌ | ❌ | Kong Konnect SaaS, OpenAI only |

### Multi-Provider Support

The custom plugin supports all LLM providers when used with [Kong AI Gateway](https://developer.konghq.com/ai-gateway/):

- OpenAI / Azure OpenAI
- Anthropic Claude
- Google Gemini / Vertex AI
- AWS Bedrock
- Mistral, Cohere, and more

Kong's AI Proxy plugin normalizes requests/responses to OpenAI format. See [custom-plugin README](custom-plugin/README.md#multi-provider-support-kong-ai-gateway) for setup.

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
