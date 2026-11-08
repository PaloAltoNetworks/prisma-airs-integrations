# MuleSoft API Gateway

Prisma AIRS for plain API instances on MuleSoft Omni Gateway: ordinary HTTP API proxies, with no Model Proxy, in front of a model provider or an MCP server.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

This folder has no code of its own. Plain API instances run the same Prisma AIRS Guardrails custom policy as MuleSoft AI Gateway's Model Proxies and MCP server instances. Build and publish it from [Gateways/AI GWs/Mulesoft/custom-policy/](../../AI%20GWs/Mulesoft/custom-policy/).

| | |
|---|---|
| What it scans | Prompts and replies, streamed and not, in the OpenAI (Chat Completions and Responses), Anthropic Messages and Gemini formats, and MCP traffic (tool calls, tool results and tool catalogues), with MCP refusals sent as JSON-RPC errors. It fails closed by default. |
| Tested on | A MuleSoft-managed Omni Gateway 1.12.12, November 2026: plain API instances in front of Azure OpenAI, Google Gemini and DeepWiki's MCP server, with Client ID Enforcement first and the policy after it |
| Not covered | Amazon Bedrock's native APIs (InvokeModel, Converse): use a Model Proxy for Bedrock. A provider's other endpoints, such as embeddings, get 403 by default: route only the model endpoints through the instance. |

## Apply it to a plain API instance

1. Check the policy's [Prerequisites](../../AI%20GWs/Mulesoft/custom-policy/README.md#prerequisites), then build and publish it: Steps 1 and 2 of its [Configuration Steps](../../AI%20GWs/Mulesoft/custom-policy/README.md#configuration-steps). The definition must list `http` and `rest` under `metadata/capabilities/assetTypes`, as it does in this repository: a version published with `llm,mcp` only is not offered on a plain instance. If your Exchange already holds such a version, publish this one under a new version number (`version` in `Cargo.toml`).
2. If you have no API instance yet, create one on your Omni Gateway as an **HTTP API**, the type the test used, with the provider's base URL as its upstream (for Azure OpenAI, `https://YOUR_RESOURCE.openai.azure.com/`), so callers keep the provider's own paths. The definition also lists `rest` (an instance made from a REST API specification), which was not tested.
3. In API Manager, open **API Instances** › your instance › **Policies** › **Add policy**, and choose **Prisma AIRS Guardrails**.
4. Fill in the **Prisma AIRS API Key**, the **Prisma AIRS API Endpoint** if your tenant is not in the US, and the **AI Security Profile**. Click **Apply**.
5. Keep it last in the chain, after your authentication policy: in the test, **Client ID Enforcement** ran first and this policy second, with no other policies.

Callers use the provider's own paths, for example Azure OpenAI's `/openai/v1/chat/completions`. In the test the caller sent the provider's key; a header policy you add could set it instead (not tested). The Prisma AIRS policy adds none.

[On a plain API instance](../../AI%20GWs/Mulesoft/custom-policy/README.md#on-a-plain-api-instance), in the policy's README, explains what differs from a Model Proxy, and [the policy's verification record](../../AI%20GWs/Mulesoft/custom-policy/docs/VERIFICATION.md#plain-api-instances) lists what was tested.
