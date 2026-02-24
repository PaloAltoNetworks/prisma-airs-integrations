# Prisma AIRS Integrations

Integration guides for Palo Alto Networks Prisma AIRS (AI Runtime Security) with third-party platforms.

## Overview

Prisma AIRS provides inline security for AI applications, scanning prompts, responses, and tool interactions in real-time. It detects threats like prompt injection, sensitive data exposure, malicious URLs, and toxic content before they impact your AI workflows.

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

This repository contains setup guides for embedding Prisma AIRS security into AI gateways, LLM proxies, coding assistants, and automation platforms.

## Integration Support Matrix

| Integration | Category | Prompt | Response | Streaming | Pre-tool | Post-tool | MCP |
|-------------|----------|:------:|:--------:|:---------:|:--------:|:---------:|:---:|
| [Anthropic (Hooks)](./Anthropic/claude-code-hooks/) | AI Coding Assistant | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| [Anthropic (MCP)](./Anthropic/claude-code-mcp/) | AI Coding Assistant | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Anthropic (Skill)](./Anthropic/claude-code-skill/) | AI Coding Assistant | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Microsoft (Azure APIM)](./Microsoft/azure-apim/) | API Gateway | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Google (Apigee)](./Google/apigee/) | API Gateway | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Kong (Custom Plugin)](./Kong/custom-plugin/) | API Gateway | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Kong (Request Callout)](./Kong/request-callout/) | API Gateway | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| [LiteLLM](./LiteLLM/) | AI Gateway | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| [n8n](./n8n/) | Workflow Automation | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [Portkey](./Portkey/) | AI Gateway | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| [TrueFoundry](./TrueFoundry/) | AI Gateway | ✅ | ✅ | ⚠️ | ❌ | ❌ | ❌ |

**Legend:** ✅ Full support | ⚠️ Partial support | ❌ Not supported

---

## Key Concepts

* **AI Runtime Security (AIRS):** Inline security that scans AI traffic in real-time, detecting prompt injection, data leakage, malicious code, and policy violations.
* **Strata Cloud Manager:** Management interface for configuring Prisma AIRS security profiles and generating API keys.
* **Security Profile:** Configuration that defines detection rules and actions (block, allow, alert) for scanned content.
* **Guardrail:** Security control in a partner platform that invokes Prisma AIRS to scan and validate AI requests/responses.

## Resources

* [Prisma AIRS Developer Documentation](https://pan.dev/airs)
* [Prisma AIRS Administrator Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
