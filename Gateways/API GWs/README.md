# API Gateways

Prisma AIRS integrations that run inside API gateways.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Gateway | Folder | What it scans |
|---|---|---|
| Azure API Management | [Azure APIM/](Azure%20APIM/) | AI traffic, through a policy fragment in an Azure API Management AI gateway policy |
| Google Apigee X | [Google APIGEE API GW/](Google%20APIGEE%20API%20GW/) | Prompts and responses, through an Apigee X proxy or a SharedFlow |
| Kong Gateway | [KONG API GW/](KONG%20API%20GW/) | AI/LLM traffic, through Kong custom plugins (v1, v2 and v3) |
| MuleSoft Omni Gateway | [MuleSoft API GW/](MuleSoft%20API%20GW/) | Prompts, replies and MCP traffic on plain API instances, with the same custom policy as MuleSoft AI Gateway |
