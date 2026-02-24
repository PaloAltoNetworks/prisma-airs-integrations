# Claude Code MCP Server Integration with Prisma AIRS

Connect Claude Code to Prisma AIRS via the Model Context Protocol (MCP) for on-demand security scanning through native MCP tools.

## Coverage

> For detection categories and use cases, see the [Prisma AIRS documentation](https://pan.dev/prisma-airs/api/airuntimesecurity/usecases/).

| Scanning Phase | Supported | Description |
|----------------|:---------:|-------------|
| Prompt | ✅ | Claude can invoke `pan_inline_scan` to scan user prompts on-demand |
| Response | ✅ | Claude can invoke `pan_inline_scan` to scan LLM outputs on-demand |
| Streaming | ❌ | MCP tools are blocking synchronous calls |
| Pre-tool call | ❌ | Not automatic - Claude must explicitly invoke scanning |
| Post-tool call | ❌ | Not automatic - Claude must explicitly invoke scanning |
| MCP | ❌ | Provides MCP tools but does not intercept MCP interactions |

## Overview

The Prisma AIRS MCP Server provides Claude Code with security scanning tools via the MCP protocol. Once configured, Claude can invoke AIRS scanning tools directly during conversations.

**Key Features:**
- Native MCP tool integration (`pan_inline_scan`, `pan_batch_scan`, `pan_get_scan_results`)
- Prompt injection detection
- Sensitive data (PII/credentials) detection
- Malicious URL identification
- Toxic content filtering

---

## Prerequisites

- Claude Code CLI installed
- Prisma AIRS API key from [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
- (Optional) Security profile name or ID

---

## Configuration

### Environment Variables

Add to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

```bash
export PRISMA_AIRS_API_KEY="your-prisma-airs-api-key"
export PRISMA_AIRS_PROFILE_NAME="your-security-profile-name"
```

### MCP Server Configuration

Claude Code supports MCP server configuration in multiple locations. Choose based on your needs:

| Location | Scope | Use Case |
|----------|-------|----------|
| `~/.claude.json` | User (all projects) | Personal setup, applies everywhere |
| `.claude/settings.json` | Project | Team-shared config, committed to repo |
| `.claude/settings.local.json` | Project (local) | Personal overrides, gitignored |
| `.mcp.json` | Project | Standalone MCP config file |

#### Option 1: User-Level Configuration (Recommended for Personal Use)

Edit `~/.claude.json` and add the `mcpServers` section:

```json
{
  "mcpServers": {
    "prisma-airs": {
      "type": "http",
      "url": "https://service.api.aisecurity.paloaltonetworks.com/mcp",
      "headers": {
        "x-pan-token": "${PRISMA_AIRS_API_KEY}",
        "x-pan-profile": "${PRISMA_AIRS_PROFILE_NAME}"
      }
    }
  }
}
```

#### Option 2: Project-Level Configuration (Recommended for Teams)

Create or edit `.claude/settings.json` in your project root:

```json
{
  "mcpServers": {
    "prisma-airs": {
      "type": "http",
      "url": "https://service.api.aisecurity.paloaltonetworks.com/mcp",
      "headers": {
        "x-pan-token": "${PRISMA_AIRS_API_KEY}",
        "x-pan-profile": "${PRISMA_AIRS_PROFILE_NAME}"
      }
    }
  }
}
```

> **Note:** Environment variables (`${PRISMA_AIRS_API_KEY}`) are resolved at runtime. Team members set their own credentials via environment variables.

---

## Regional Endpoints

Choose the endpoint closest to your location:

| Region | HTTP Endpoint |
|--------|--------------|
| **US** (default) | `https://service.api.aisecurity.paloaltonetworks.com/mcp` |
| **EU** | `https://service-de.api.aisecurity.paloaltonetworks.com/mcp` |
| **India** | `https://service-in.api.aisecurity.paloaltonetworks.com/mcp` |
| **Singapore** | `https://service-sg.api.aisecurity.paloaltonetworks.com/mcp` |

---

## Available MCP Tools

Once configured, Claude Code has access to these tools:

| Tool | Description |
|------|-------------|
| `mcp__prisma-airs__pan_inline_scan` | Synchronous scan of prompt/response/code |
| `mcp__prisma-airs__pan_batch_scan` | Asynchronous batch scanning (1-25 requests) |
| `mcp__prisma-airs__pan_get_scan_results` | Retrieve results from batch scans |

### Example Usage

In Claude Code, ask:

```
Scan this code for security issues using Prisma AIRS:
[paste code here]
```

Claude will invoke the MCP tool automatically.

---

## Verification

1. Start Claude Code in a project
2. Run `/mcp` to list connected servers
3. Verify `prisma-airs` appears in the list
4. Test with: "Use Prisma AIRS to scan: Hello world"

---

## Troubleshooting

### Server Not Appearing

- Verify environment variables are set: `echo $PRISMA_AIRS_API_KEY`
- Check JSON syntax in config file
- Restart Claude Code after config changes

### Authentication Errors

- Verify API key is valid in Strata Cloud Manager
- Check the key has API Intercept permissions
- Ensure profile name matches exactly (case-sensitive)

### Connection Timeouts

- Verify network access to the AIRS endpoint
- Try a different regional endpoint
- Check firewall/proxy settings

---

## Security Considerations

- **Never commit API keys** - Always use environment variables
- **Use project-level config** for team settings, user-level for credentials
- **Rotate API keys** regularly (recommended: 90 days)

---

## Resources

- [Prisma AIRS MCP Server Documentation](https://docs.paloaltonetworks.com/ai-runtime-security/activation-and-onboarding/prisma-airs-mcp-server-for-centralized-ai-agent-security)
- [Prisma AIRS API Reference](https://pan.dev/airs/)
- [Claude Code MCP Documentation](https://docs.anthropic.com/en/docs/claude-code/mcp)

---

## License

MIT
