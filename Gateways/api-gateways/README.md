# API Gateways

Prisma AIRS integrations that run inside API gateways.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Gateway | Folder | What it scans |
|---|---|---|
| Azure API Management | [azure-apim/](azure-apim/) | AI traffic, through a policy fragment in an Azure API Management AI gateway policy |
| Google Apigee X | [apigee/](apigee/) | Prompts and responses, through an Apigee X proxy or a SharedFlow |
| Kong Gateway | [kong/](kong/) | AI/LLM traffic, through Kong custom plugins (v1, v2 and v3) |
| MuleSoft Omni Gateway | [mulesoft/](mulesoft/) | Prompts, replies and MCP traffic on plain API instances, with the same custom policy as MuleSoft AI Gateway |

The top-level folders (`Google/`, `Kong/`, `Microsoft/`) remain the source of truth for now; `apigee/`, `kong/` and `azure-apim/` here are copies of them. `mulesoft/` points to the policy in `ai-gateways/mulesoft/`.
