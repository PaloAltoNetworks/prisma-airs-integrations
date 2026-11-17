# AI Gateways

Prisma AIRS integrations that run inside AI gateways.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Gateway | Folder | What it scans |
|---|---|---|
| Kong AI Gateway | [kong/](kong/) | AI/LLM traffic, through Kong AI Gateway 2.x policies or the Request-Callout plugin |
| LiteLLM Proxy (LLM Gateway) | [litellm/](litellm/) | Prompts and responses, with Prisma AIRS as a guardrail in the LiteLLM Proxy |
| MuleSoft AI Gateway (Omni Gateway) | [mulesoft/](mulesoft/) | Model Proxy traffic (prompts, replies streamed and not, and tool calls, in the OpenAI, Anthropic and Gemini formats) and MCP server traffic (tool calls, tool results and catalogues, and every other MCP message that carries text) |
| TrueFoundry AI Gateway | [truefoundry/](truefoundry/) | AI requests and responses, with Prisma AIRS as a guardrail in the TrueFoundry AI Gateway |

The top-level folders (`Kong/`, `LiteLLM/`, `TrueFoundry/`) remain the source of truth for now; `kong/`, `litellm/` and `truefoundry/` here are copies of them. `mulesoft/` lives only here.

Elsewhere in this repository, the main README lists this AI gateway integration: [Bifrost](../../Bifrost/).
