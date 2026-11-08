# AI Gateways

Prisma AIRS integrations that run inside AI gateways.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Gateway | Folder | What it scans |
|---|---|---|
| MuleSoft AI Gateway (Omni Gateway) | [Mulesoft/](Mulesoft/) | Model Proxy traffic (prompts, replies streamed and not, and tool calls, in the OpenAI, Anthropic and Gemini formats) and MCP server traffic (tool calls, tool results and catalogues, and every other MCP message that carries text) |

Elsewhere in this repository, the main README lists these AI gateway integrations: [LiteLLM](../../LiteLLM/), [Bifrost](../../Bifrost/) and [TrueFoundry](../../TrueFoundry/).
