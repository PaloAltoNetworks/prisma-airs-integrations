# OpenAI Integrations for Prisma AIRS

This directory contains integrations between OpenAI products and Palo Alto Networks Prisma AI Runtime Security (AIRS).

## IMPORTANT

The contents of this repository are community examples and reference implementations, supported as best effort by Palo Alto Networks. They are intended as starting points to illustrate integration patterns — review, adapt, and validate them for your own environment before any production use.

## Overview

| Integration | Method | Use Case |
|-------------|--------|----------|
| [codex-hooks](./codex-hooks/) | Hooks (automatic) | Runtime protection — scans prompts, bash commands, MCP tool calls, and post-stream final responses |

## Choosing an Integration

### Codex CLI Hooks 

**Best for**: Organizations running OpenAI Codex CLI that require always-on, transparent security scanning

- Automatically scans every user prompt, Bash command, MCP tool input/output, and final assistant response after streaming
- Fail-closed enforcement on prompts and tool calls (`exit 2` blocks before execution)
- Uses the Prisma AIRS `tool_event` payload for MCP tool calls — no additional MCP server required
- Drop-in `.codex/` directory; works at project or global scope

[View Codex CLI Hooks Integration](./codex-hooks/)

## Security Features

The Codex CLI hooks integration provides protection against:

- Prompt injection attacks
- Sensitive data exposure (PII, credentials, secrets)
- Malicious URL detection
- Toxic or harmful content
- Malicious code patterns
- AI manipulation attempts

## Getting Started

1. Choose the integration method that fits your needs
2. Follow the setup instructions in the respective directory
3. Obtain API credentials from [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)

## Resources

- [Prisma AIRS Documentation](https://pan.dev/airs/)
- [Prisma AIRS Admin Guide](https://docs.paloaltonetworks.com/ai-runtime-security/administration/prisma-airs-overview)
- [Codex CLI Hooks Reference](https://developers.openai.com/codex/hooks)
- [Codex CLI Repository](https://github.com/openai/codex)
