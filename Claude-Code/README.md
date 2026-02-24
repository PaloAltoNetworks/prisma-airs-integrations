# Claude Code Integrations for Prisma AIRS

This directory contains integrations between Claude Code and Palo Alto Networks Prisma AI Runtime Security (AIRS).

## Overview

Three integration methods are available, each serving different security needs:

| Integration | Method | Use Case |
|-------------|--------|----------|
| [claude-code-hooks](./claude-code-hooks/) | Hooks (automatic) | Runtime protection - scans all inputs/outputs transparently |
| [claude-code-mcp](./claude-code-mcp/) | MCP Server (native) | Native MCP tools for AI-driven security scanning |
| [claude-code-skill](./claude-code-skill/) | Skill (on-demand) | User-invoked scanning via slash command |

## Choosing an Integration

### Claude Code Hooks (Recommended for Enterprise)

**Best for**: Organizations requiring comprehensive, always-on protection

- Automatically scans every user input, tool call, and AI response
- Zero-trust architecture with 6 security checkpoints
- No user action required - protection is transparent
- Blocks threats before they reach Claude or the user

[View Hooks Integration](./claude-code-hooks/)

### Claude Code MCP Server

**Best for**: Native integration with Claude's tool ecosystem

- Connects via Model Context Protocol (MCP)
- Claude can invoke AIRS scanning tools autonomously
- Regional endpoint support (US, EU, India, Singapore)
- Simple JSON configuration

[View MCP Integration](./claude-code-mcp/)

### Claude Code Skill

**Best for**: Developers wanting explicit, user-controlled scanning

- User-invoked via `/prisma-airs-scan` command
- Scan specific prompts, code, or responses as needed
- Lightweight integration with minimal setup
- Ideal for spot-checking generated code or sensitive content

[View Skill Integration](./claude-code-skill/)

## Comparison

| Feature | Hooks | MCP Server | Skill |
|---------|-------|------------|-------|
| Automatic scanning | Yes | No (AI-driven) | No |
| User invocation | No | Via conversation | `/prisma-airs-scan` |
| Blocks threats | Yes | Informs user | Reports findings |
| Setup complexity | Medium | Low | Low |
| Best for | Enterprise security | AI-native workflows | Developer spot-checks |

## Security Features

All integrations provide protection against:

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
- [Prisma AIRS MCP Server Docs](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/prisma-airs-mcp-server-for-centralized-ai-agent-security)
- [Claude Code Hooks Reference](https://docs.anthropic.com/en/docs/claude-code/hooks)
