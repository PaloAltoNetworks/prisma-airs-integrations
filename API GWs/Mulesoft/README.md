# MuleSoft AI Gateway

Prisma AIRS for MuleSoft AI Gateway, which runs on Omni Gateway.

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

| Folder | What it is | Tested on |
|---|---|---|
| [custom-policy/](custom-policy/) | Prisma AIRS Guardrails: a PDK custom policy for Model Proxies and MCP server instances that scans prompts, replies, tool calls and tool results inline, refuses MCP calls inside the protocol, and fails closed by default | A MuleSoft-managed Omni Gateway 1.12.12, with Amazon Bedrock, Azure OpenAI and Google Gemini, and an MCP server instance in front of DeepWiki |
