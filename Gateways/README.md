# Gateways

Prisma AIRS integrations that run inside gateways.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Folder | What it holds |
|---|---|
| [ai-gateways/](ai-gateways/) | Integrations that run inside AI gateways: Databricks Unity AI Gateway, Kong, LiteLLM, MuleSoft AI Gateway and TrueFoundry |
| [api-gateways/](api-gateways/) | Integrations that run inside API gateways: Apigee, Azure API Management, Kong and MuleSoft Omni Gateway |

The top-level folders (`Google/`, `Kong/`, `LiteLLM/`, `Microsoft/`, `TrueFoundry/`) remain the source of truth for now, and most integrations here are copies of them. Databricks and MuleSoft live only here. Apigee is no longer a copy: `api-gateways/apigee/` adds the v3 SharedFlow and retires V1 and V2's experimental stream proxy, which `Google/apigee/` still holds.
